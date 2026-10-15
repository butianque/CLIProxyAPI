package supply

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The pool is the host's record of every identity it has handed out and of the
// account each one registered. It is deliberately cross-kind: a phone number and
// an email address are both "an identity that registered an account", and the
// question a caller asks — which identity is behind this credential, and where
// did it come from — is the same for both. A single file also means the
// management surface can answer that question once, instead of once per kind.
//
// Only the core fields are fixed here. Anything a single kind needs (a phone
// channel, an email domain) goes in Meta, so adding a kind never changes this
// shape. That is the same rule the host.supply.grab wire contract follows.

// Record is one identity's history in the pool.
type Record struct {
	// Kind and Address identify the identity; together they are the key.
	Kind    Kind   `json:"kind"`
	Address string `json:"address"`

	// Source names who supplied the identity, e.g. "haozhuma" or "mail.tm".
	Source string `json:"source,omitempty"`
	// Target names the platform the identity registered, e.g. "loomy". It is
	// empty until an account is linked, which is the honest state for an
	// identity that was handed out but never registered anything.
	Target string `json:"target,omitempty"`

	// Account is the service account name the identity registered — the
	// credential's file name stem. AuthIndex is the host credential index
	// backing it, when it is known.
	//
	// Account is the durable key. AuthIndex is derived from the credential
	// (its provider, path and key material), so it cannot be known at the
	// moment the identity is linked — the credential does not exist yet. A
	// reader that needs the index resolves it from Account against the live
	// credential list; that is why Account is required and AuthIndex is not.
	Account   string `json:"account,omitempty"`
	AuthIndex string `json:"auth_index,omitempty"`

	// Price is the per-handout cost in CNY. Email sources are usually free.
	Price float64 `json:"price,omitempty"`
	// Outcome is the last thing that happened to the identity, e.g.
	// "registered", "released" or "timeout". State is its standing, e.g.
	// "held", "released" or "blacklisted".
	Outcome string `json:"outcome,omitempty"`
	State   string `json:"state,omitempty"`

	// Rents counts how many times the identity has been handed out, and Spend
	// is the total CNY spent on it.
	Rents int     `json:"rents,omitempty"`
	Spend float64 `json:"spend,omitempty"`
	// FirstSeen and LastUsed are unix seconds.
	FirstSeen int64 `json:"first_seen,omitempty"`
	LastUsed  int64 `json:"last_used,omitempty"`

	// Meta holds the kind-specific details: a phone's channel, carrier and
	// region; an email's domain. Values are plain JSON so a kind can add one
	// without changing this struct.
	Meta map[string]any `json:"meta,omitempty"`
}

// MetaString reads one string entry out of a record's Meta bag.
func (r Record) MetaString(key string) string {
	if r.Meta == nil {
		return ""
	}
	value, ok := r.Meta[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

// MetaBool reads one boolean entry out of a record's Meta bag.
func (r Record) MetaBool(key string) bool {
	if r.Meta == nil {
		return false
	}
	value, ok := r.Meta[key]
	if !ok {
		return false
	}
	flag, ok := value.(bool)
	return ok && flag
}

// Pool is the cross-kind identity pool.
type Pool struct {
	Version int      `json:"version"`
	Records []Record `json:"records,omitempty"`
	// SpendCNY is the running total spent through this pool.
	SpendCNY float64 `json:"spend_cny,omitempty"`
}

// poolVersion is the on-disk schema version.
const poolVersion = 1

// NewPool returns an empty pool.
func NewPool() *Pool { return &Pool{Version: poolVersion} }

// PoolPath is where the pool lives inside a supply state directory.
//
// The legacy filename is intentionally retained as the on-disk format boundary
// so upgrading does not strand existing supply history. It is one file for
// every kind: the pool's whole point is a single view, and a per-kind file
// would put the join back on the reader.
func PoolPath(dir string) string { return filepath.Join(dir, "ledger.json") }

// find returns the index of one identity's record, or -1.
func (l *Pool) find(kind Kind, address string) int {
	address = strings.TrimSpace(address)
	for i := range l.Records {
		if l.Records[i].Kind == kind && l.Records[i].Address == address {
			return i
		}
	}
	return -1
}

// Knows reports whether an identity has ever been handed out through this
// pool. A caller uses it to tell an identity it can re-occupy from one it has
// never seen.
func (l *Pool) Knows(kind Kind, address string) bool {
	_, ok := l.Get(kind, address)
	return ok
}

// Get returns the record for one identity.
func (l *Pool) Get(kind Kind, address string) (Record, bool) {
	if i := l.find(kind, address); i >= 0 {
		return l.Records[i], true
	}
	return Record{}, false
}

// All returns a copy of every record, for callers that need to scan them.
func (l *Pool) All() []Record {
	out := make([]Record, len(l.Records))
	copy(out, l.Records)
	return out
}

// Record notes one successful handout and folds it into the running spend.
//
// meta carries the kind-specific details; the core fields are set from the
// arguments. Re-recording an identity accumulates its rent count and spend
// rather than duplicating it.
func (l *Pool) Record(kind Kind, address, source string, price float64, meta map[string]any, now int64) Record {
	if l.Version == 0 {
		l.Version = poolVersion
	}
	address = strings.TrimSpace(address)
	i := l.find(kind, address)
	if i < 0 {
		l.Records = append(l.Records, Record{
			Kind:      kind,
			Address:   address,
			Source:    strings.TrimSpace(source),
			Price:     price,
			Rents:     1,
			Spend:     price,
			FirstSeen: now,
			LastUsed:  now,
			Meta:      meta,
		})
		l.SpendCNY += price
		return l.Records[len(l.Records)-1]
	}
	record := &l.Records[i]
	if source = strings.TrimSpace(source); source != "" {
		record.Source = source
	}
	if price > 0 {
		record.Price = price
	}
	record.Rents++
	record.LastUsed = now
	if price > 0 {
		record.Spend += price
		l.SpendCNY += price
	}
	for key, value := range meta {
		if record.Meta == nil {
			record.Meta = map[string]any{}
		}
		record.Meta[key] = value
	}
	return *record
}

// Link binds an identity to the account it registered, and to the platform it
// registered on. It is the step that makes a record traceable: before it, the
// pool knows an identity was handed out; after it, the pool knows which
// account and which platform it belongs to.
//
// It records the outcome and state of a successful registration, overwriting
// whatever a previous attempt left. Registration is the most recent fact and a
// definitive success, so a record that was marked timed-out or released by an
// earlier attempt must not keep saying so once an account is bound to it: the
// identity is held by that account now.
func (l *Pool) Link(kind Kind, address, target, account, authIndex string, now int64) {
	i := l.find(kind, address)
	if i < 0 {
		return
	}
	record := &l.Records[i]
	if target = strings.TrimSpace(target); target != "" {
		record.Target = target
	}
	if account = strings.TrimSpace(account); account != "" {
		record.Account = account
	}
	if authIndex = strings.TrimSpace(authIndex); authIndex != "" {
		record.AuthIndex = authIndex
	}
	record.Outcome = "registered"
	record.State = "held"
	record.LastUsed = now
}

// Mark records what last happened to an identity and where it now stands.
// Empty values leave the existing one in place, so a caller can update one
// without clearing the other.
func (l *Pool) Mark(kind Kind, address, outcome, state string, now int64) {
	i := l.find(kind, address)
	if i < 0 {
		return
	}
	record := &l.Records[i]
	if outcome = strings.TrimSpace(outcome); outcome != "" {
		record.Outcome = outcome
	}
	if state = strings.TrimSpace(state); state != "" {
		record.State = state
	}
	record.LastUsed = now
}

// Refund reverses one handout's recorded cost.
//
// A source returns an identity to its pool when it is released before anything
// was used, and credits the rental back, so counting that rental as spend would
// overstate the running total and trip the cumulative ceiling early. Only ever
// reverses what Record booked: the amount is capped at the record's own total
// so a refund can never drive the pool negative.
func (l *Pool) Refund(kind Kind, address string, amount float64, now int64) bool {
	if amount <= 0 {
		return false
	}
	i := l.find(kind, address)
	if i < 0 {
		return false
	}
	record := &l.Records[i]
	if record.Spend <= 0 {
		return false
	}
	if amount > record.Spend {
		amount = record.Spend
	}
	record.Spend -= amount
	l.SpendCNY -= amount
	if l.SpendCNY < 0 {
		l.SpendCNY = 0
	}
	record.LastUsed = now
	return true
}

// Spent returns the running total.
func (l *Pool) Spent() float64 { return l.SpendCNY }

// ForAccount returns the records linked to one account.
func (l *Pool) ForAccount(account string) []Record {
	account = strings.TrimSpace(account)
	out := make([]Record, 0, 1)
	for _, record := range l.Records {
		if record.Account == account {
			out = append(out, record)
		}
	}
	return out
}

// ForTarget returns the records linked to one platform.
func (l *Pool) ForTarget(target string) []Record {
	target = strings.TrimSpace(target)
	out := make([]Record, 0, 1)
	for _, record := range l.Records {
		if record.Target == target {
			out = append(out, record)
		}
	}
	return out
}

// LoadPool reads the pool; a missing file yields an empty one.
func LoadPool(path string) (*Pool, error) {
	pool := NewPool()
	if errLoad := loadJSON(path, pool); errLoad != nil {
		return NewPool(), errLoad
	}
	if pool.Version == 0 {
		pool.Version = poolVersion
	}
	return pool, nil
}

// Save writes the pool.
func (l *Pool) Save(path string) error {
	if l.Version == 0 {
		l.Version = poolVersion
	}
	return saveJSON(path, l)
}

// -- persistence helpers -----------------------------------------------------

// loadJSON reads one JSON document, treating a missing file as a zero value.
func loadJSON(path string, into any) error {
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		if errors.Is(errRead, os.ErrNotExist) {
			return nil
		}
		return errRead
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	return json.Unmarshal(raw, into)
}

// saveJSON writes one JSON document atomically, so a crash cannot truncate it.
func saveJSON(path string, value any) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if errMkdir := os.MkdirAll(dir, 0o755); errMkdir != nil {
			return errMkdir
		}
	}
	raw, errMarshal := json.MarshalIndent(value, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if errWrite := os.WriteFile(tmp, raw, 0o600); errWrite != nil {
		return errWrite
	}
	if errRename := os.Rename(tmp, path); errRename != nil {
		_ = os.Remove(tmp)
		return errRename
	}
	return nil
}
