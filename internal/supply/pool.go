package supply

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	// ChannelID names the configured supply channel that handed the identity
	// out, which is the join back to the source's settings. It is separate
	// from Source because a source is a platform and a channel is one account
	// on it: several channels can share one source.
	ChannelID string `json:"channel_id,omitempty"`
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

	// Registrations is every account this identity was used to register. Target
	// and Account above mirror the newest one, because that is what a credential
	// lookup asks for; the list is the history, because one identity can be
	// handed out again and register on a second platform.
	Registrations []Registration `json:"registrations,omitempty"`

	// Price is the per-handout cost in CNY. Email sources are usually free.
	Price float64 `json:"price,omitempty"`
	// Outcome is the last thing that happened to the identity, e.g.
	// "registered", "released" or "timeout". State is its standing, e.g.
	// "held", "released" or "blacklisted".
	Outcome string `json:"outcome,omitempty"`
	State   string `json:"state,omitempty"`

	// Rents counts how many times the identity has been used: each handout, and
	// each new account it registered. Spend is the total CNY spent on it.
	Rents int     `json:"rents,omitempty"`
	Spend float64 `json:"spend,omitempty"`
	// FirstSeen and LastUsed are unix seconds.
	FirstSeen int64 `json:"first_seen,omitempty"`
	LastUsed  int64 `json:"last_used,omitempty"`

	// Meta holds the kind-specific details: a phone's channel, carrier and
	// region; an email's domain. Values are plain JSON so a kind can add one
	// without changing this struct.
	Meta map[string]any `json:"meta,omitempty"`

	// Mailbox is how an individually-held email identity reads its own mail.
	//
	// It is what separates this kind of record from one a channel handed out: a
	// channel is one connection that mints addresses for a whole domain, while
	// an identity bought on its own owns exactly one address and carries its own
	// credential. Without this block such an identity could only be represented
	// as a channel of its own, which is the mistake this field undoes.
	Mailbox *Mailbox `json:"mailbox,omitempty"`
}

// clone returns a copy that shares no mutable state with the receiver, so a
// snapshot can be encoded while other writers keep working on the original.
//
// The metadata map is copied one level deep: mutators replace keys, they do not
// reach into a nested value, so a deeper copy would buy nothing.
func (r Record) clone() Record {
	copied := r
	if r.Meta != nil {
		copied.Meta = make(map[string]any, len(r.Meta))
		for key, value := range r.Meta {
			copied.Meta[key] = value
		}
	}
	if r.Mailbox != nil {
		box := *r.Mailbox
		copied.Mailbox = &box
	}
	if r.Registrations != nil {
		copied.Registrations = make([]Registration, len(r.Registrations))
		copy(copied.Registrations, r.Registrations)
	}
	return copied
}

// Mailbox is the per-identity way one email address reads its mail.
//
// It mirrors the connection details a channel carries, minus everything that
// only makes sense for a source of many addresses: there is no domain to receive
// for and no usage to derive, because this identity is exactly one address.
//
// Secret and Password are secret-store entry names, never values. The two are
// named apart because they hold different kinds of secret: the token (or
// authorization code) a transport authenticates with, and the mailbox password,
// which exists only for a person signing in by hand — Microsoft refuses it on
// both IMAP and Graph.
type Mailbox struct {
	// Nature is how the mailbox is read: imap, oauth2 or graph.
	Nature Nature `json:"nature,omitempty"`
	// Endpoint is the IMAP host. Empty for graph, which answers at one fixed
	// endpoint.
	Endpoint string `json:"endpoint,omitempty"`
	// ClientID is the application a refresh token was issued to.
	ClientID string `json:"client_id,omitempty"`
	// Secret names the entry holding the credential the transport uses.
	Secret string `json:"secret,omitempty"`
	// Password names the entry holding the mailbox password, when one was
	// supplied. It is used for a manual sign-in and by nothing else.
	Password string `json:"password_secret,omitempty"`
}

// Usable reports whether a mailbox block names enough to attempt a read: a
// transport, and a protocol host for the transports that need one.
func (m Mailbox) Usable() bool {
	if !m.Nature.IsMailbox() {
		return false
	}
	if m.Nature == NatureGraph {
		return true
	}
	return strings.TrimSpace(m.Endpoint) != ""
}

// Registration is one platform account an identity was used to register.
//
// A registration is keyed by (Target, Account): the same account registered
// again is the same fact restated, so it updates its entry rather than adding a
// second line for it. At is when that was last observed, which is what tells a
// reader whether the account is still the current one.
type Registration struct {
	Target    string `json:"target"`
	Account   string `json:"account,omitempty"`
	AuthIndex string `json:"auth_index,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
	At        int64  `json:"at,omitempty"`
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
//
// It is written from three places that do not share a caller: the phone service
// (under its own lock), the email provider (per call), and the management
// surface. One mutex here is what keeps those from corrupting the document — the
// alternative, a lock per caller, is a lock that one of them will forget.
type Pool struct {
	mu sync.Mutex

	// saveMu serializes writes to disk. It is separate from mu on purpose: mu
	// guards the document and is held only long enough to take a snapshot, while
	// a write is slow. Two writers racing on the same temporary file is what a
	// single writer at a time prevents.
	saveMu sync.Mutex

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
//
// Matching ignores case because an address is the same identity however it was
// spelled: a handout lowercases what it hands out, while a credential may carry
// the address as the provider displays it. Comparing byte-for-byte therefore
// missed records that differed only in case, which both dropped the annotation
// and let a second record be created for an identity already in the ledger.
// Every lookup goes through here, so this is the one place the rule has to hold.
func (l *Pool) find(kind Kind, address string) int {
	address = strings.TrimSpace(address)
	for i := range l.Records {
		if l.Records[i].Kind == kind && strings.EqualFold(l.Records[i].Address, address) {
			return i
		}
	}
	return -1
}

// Knows reports whether an identity has ever been handed out through this
// pool. A caller uses it to tell an identity it can re-occupy from one it has
// never seen.
func (l *Pool) Knows(kind Kind, address string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.find(kind, address) >= 0
}

// Get returns the record for one identity.
func (l *Pool) Get(kind Kind, address string) (Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i := l.find(kind, address); i >= 0 {
		return l.Records[i], true
	}
	return Record{}, false
}

// All returns a copy of every record, for callers that need to scan them.
func (l *Pool) All() []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Record, len(l.Records))
	copy(out, l.Records)
	return out
}

// CountByChannel counts how many identities each channel put into the pool, per
// kind. A channel that supplied nothing is absent from the result.
//
// It counts every record, including one that has since been released: the ledger
// still lists it, so this number has to agree with the rows an operator can count
// under that channel. Re-renting the same identity does not count twice, because
// the pool keys records by identity.
//
// An email record names the channel that minted the address. A phone record does
// not: a number is rented from the platform, so the record names the platform
// while the channel row holds that platform's credential. The phone join is
// therefore the connection's secret entry name, which is the same rule the panel
// applied by itself before this count existed.
func CountByChannel(channels []Channel, records []Record) map[string]map[Kind]int {
	channelOfSource := make(map[string]string, len(channels))
	for _, channel := range channels {
		if channel.Phone == nil {
			continue
		}
		for _, conn := range channel.Phone.Connections {
			secret := strings.TrimSpace(conn.Secret)
			if secret == "" {
				continue
			}
			// The first channel naming this credential owns it. One platform
			// account is one channel, so a second row naming the same credential
			// is a duplicate rather than a second source of numbers.
			if _, taken := channelOfSource[secret]; !taken {
				channelOfSource[secret] = channel.ID
			}
		}
	}
	counts := make(map[string]map[Kind]int, len(channels))
	for _, record := range records {
		channelID := strings.TrimSpace(record.ChannelID)
		if channelID == "" && record.Kind == KindPhone {
			channelID = channelOfSource[strings.TrimSpace(record.Source)]
		}
		if channelID == "" {
			continue
		}
		byKind := counts[channelID]
		if byKind == nil {
			byKind = make(map[Kind]int, 2)
			counts[channelID] = byKind
		}
		byKind[record.Kind]++
	}
	return counts
}

// Mailboxes returns every email identity that carries its own way of reading
// mail, in the order they were recorded.
//
// It is a copy because the caller scans it while other writers are appending:
// handing out the live slice would let a concurrent append move the records out
// from under a reader.
func (l *Pool) Mailboxes() []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Record, 0, len(l.Records))
	for _, record := range l.Records {
		if record.Kind != KindEmail || record.Mailbox == nil {
			continue
		}
		out = append(out, record)
	}
	return out
}

// AttachMailbox records how one individually-held identity reads its mail, and
// reports whether that created the record.
//
// It creates the record when the identity is new, because an imported mailbox has
// never been handed out: no other writer would ever mention it, and a pool that
// could only hold identities it produced itself could not hold a mailbox bought
// on its own.
//
// Re-attaching replaces the whole block, which is what makes a re-import with a
// different receiving method an in-place update rather than a second identity. It
// leaves the rent count and the last-used time alone: attaching a credential is
// not a use of the identity.
func (l *Pool) AttachMailbox(kind Kind, address string, box Mailbox, now int64) (Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Version == 0 {
		l.Version = poolVersion
	}
	address = strings.TrimSpace(address)
	box.Nature = Nature(strings.TrimSpace(string(box.Nature)))
	box.Endpoint = strings.TrimSpace(box.Endpoint)
	box.ClientID = strings.TrimSpace(box.ClientID)
	box.Secret = strings.TrimSpace(box.Secret)
	box.Password = strings.TrimSpace(box.Password)

	created := false
	i := l.find(kind, address)
	if i < 0 {
		l.Records = append(l.Records, Record{
			Kind:      kind,
			Address:   address,
			FirstSeen: now,
		})
		i = len(l.Records) - 1
		created = true
	}
	record := &l.Records[i]
	record.Mailbox = &box
	return *record, created
}

// Record notes one successful handout and folds it into the running spend.
//
// meta carries the kind-specific details; the core fields are set from the
// arguments. Re-recording an identity accumulates its rent count and spend
// rather than duplicating it.
func (l *Pool) Record(kind Kind, address, source string, price float64, meta map[string]any, now int64) Record {
	l.mu.Lock()
	defer l.mu.Unlock()
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
// It only ever annotates an identity the pool already knows. A link for an
// address that was never handed out is a no-op, because the pool is the host's
// record of what it supplied, not a place to learn about identities from
// outside; the caller that does know the identity reaches Register directly.
// The second result says whether anything was annotated, so a caller that
// persists the pool can skip the write when there was nothing to persist.
//
// It records the outcome and state of a successful registration, overwriting
// whatever a previous attempt left. Registration is the most recent fact and a
// definitive success, so a record that was marked timed-out or released by an
// earlier attempt must not keep saying so once an account is bound to it: the
// identity is held by that account now.
func (l *Pool) Link(kind Kind, address, target, account, authIndex string, now int64) (Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.find(kind, address) < 0 {
		return Record{}, false
	}
	record := l.registerLocked(kind, address, "", target, account, authIndex, "registered", now)
	record.State = "held"
	return *record, true
}

// Register notes that an identity was used to register an account, and on which
// platform.
//
// It is the write behind a registration, so it creates the record when the
// identity is new: a caller that knows which account an identity registered does
// not need a prior handout to have been booked first. That is the difference
// between Register and Link — Link annotates what the pool already knows, while
// Register states the fact and lets the record follow.
//
// An empty target appends no registration, because nothing was registered; the
// record is still updated, which is what makes a bare handout traceable to the
// channel that produced it. A registration for a pair the record already carries
// is that fact restated, so it updates the existing entry in place and leaves
// the rent count alone; a new pair is a new use of the identity, so it is
// appended and counted.
func (l *Pool) Register(kind Kind, address, channelID, target, account, authIndex, outcome string, now int64) *Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.registerLocked(kind, address, channelID, target, account, authIndex, outcome, now)
}

// registerLocked is Register under the caller's lock, so a method that already
// holds it can annotate a record without deadlocking on itself.
func (l *Pool) registerLocked(kind Kind, address, channelID, target, account, authIndex, outcome string, now int64) *Record {
	if l.Version == 0 {
		l.Version = poolVersion
	}
	address = strings.TrimSpace(address)
	channelID = strings.TrimSpace(channelID)
	target = strings.TrimSpace(target)
	account = strings.TrimSpace(account)
	authIndex = strings.TrimSpace(authIndex)
	outcome = strings.TrimSpace(outcome)

	i := l.find(kind, address)
	if i < 0 {
		l.Records = append(l.Records, Record{
			Kind:      kind,
			Address:   address,
			Source:    channelID,
			ChannelID: channelID,
			FirstSeen: now,
			LastUsed:  now,
		})
		i = len(l.Records) - 1
	}
	record := &l.Records[i]
	// The channel is written once. An identity keeps the channel that first
	// produced it, so a later report cannot quietly reassign its history.
	if channelID != "" && record.ChannelID == "" {
		record.ChannelID = channelID
	}
	// Empty arguments leave the existing value in place: a registration report
	// carries what its caller knows, not a full record.
	if target != "" {
		record.Target = target
	}
	if account != "" {
		record.Account = account
	}
	if authIndex != "" {
		record.AuthIndex = authIndex
	}
	if outcome != "" {
		record.Outcome = outcome
	}
	record.LastUsed = now
	if target == "" {
		return record
	}

	registration := Registration{
		Target:    target,
		Account:   account,
		AuthIndex: authIndex,
		Outcome:   outcome,
		At:        now,
	}
	for j := range record.Registrations {
		if record.Registrations[j].Target == target && record.Registrations[j].Account == account {
			record.Registrations[j] = registration
			return record
		}
	}
	record.Registrations = append(record.Registrations, registration)
	record.Rents++
	return record
}

// Mark records what last happened to an identity and where it now stands.
// Empty values leave the existing one in place, so a caller can update one
// without clearing the other.
func (l *Pool) Mark(kind Kind, address, outcome, state string, now int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
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

// Remove deletes one identity's record and reports what was removed.
//
// Only the ledger entry goes. A record names the credential an identity produced
// — Account, and a mailbox's Secret — it does not own it: those entries live in
// the credential store, and removing a row is an operator tidying up the supply
// history, not a request to revoke an account. Destroying the credential is a
// separate, deliberate action.
//
// The caller saves; like every other write here this only edits the document in
// memory, under the lock, so a save can be batched or skipped.
func (l *Pool) Remove(kind Kind, address string) (Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	i := l.find(kind, address)
	if i < 0 {
		return Record{}, false
	}
	// The removed record is returned by value: it is out of the document now, so
	// the caller is the only one left holding it.
	removed := l.Records[i]
	l.Records = slices.Delete(l.Records, i, i+1)
	return removed, true
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
	l.mu.Lock()
	defer l.mu.Unlock()
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
func (l *Pool) Spent() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.SpendCNY
}

// ForAccount returns the records linked to one account.
func (l *Pool) ForAccount(account string) []Record {
	account = strings.TrimSpace(account)
	l.mu.Lock()
	defer l.mu.Unlock()
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
	l.mu.Lock()
	defer l.mu.Unlock()
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
//
// The snapshot is taken under the lock and marshalled outside it: a write can be
// slow on a large document, and holding the mutex for the whole encode would
// stall every reader behind a disk write.
func (l *Pool) Save(path string) error {
	// The write lock is taken before the snapshot, not after it. A snapshot taken
	// outside the write lock could be older than one a competing writer already
	// persisted, and the older one would then overwrite the newer: every record
	// the other writer added would be gone. Ordering the snapshot with the write
	// is what makes the last save the newest state.
	l.saveMu.Lock()
	defer l.saveMu.Unlock()

	l.mu.Lock()
	if l.Version == 0 {
		l.Version = poolVersion
	}
	snapshot := Pool{
		Version:  l.Version,
		Records:  make([]Record, len(l.Records)),
		SpendCNY: l.SpendCNY,
	}
	for i, record := range l.Records {
		// The record is copied deeply enough that encoding it outside the lock
		// reads nothing another writer can still change: a shallow copy would
		// leave the metadata map shared, and a concurrent grab would be writing
		// it while json walks it.
		snapshot.Records[i] = record.clone()
	}
	l.mu.Unlock()

	return saveJSON(path, &snapshot)
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
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if errMkdir := os.MkdirAll(dir, 0o755); errMkdir != nil {
			return errMkdir
		}
	}
	raw, errMarshal := json.MarshalIndent(value, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	raw = append(raw, '\n')
	// A unique temporary name, so a writer that is somehow not the only one
	// cannot interleave its bytes with another's into one file.
	file, errTemp := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if errTemp != nil {
		return errTemp
	}
	tmp := file.Name()
	// The document carries identities and, in a mailbox block, credential entry
	// names; the permissions are tightened before anything is written into it.
	if errChmod := file.Chmod(0o600); errChmod != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return errChmod
	}
	if _, errWrite := file.Write(raw); errWrite != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return errWrite
	}
	if errSync := file.Sync(); errSync != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return errSync
	}
	if errClose := file.Close(); errClose != nil {
		_ = os.Remove(tmp)
		return errClose
	}
	if errRename := os.Rename(tmp, path); errRename != nil {
		_ = os.Remove(tmp)
		return errRename
	}
	return nil
}
