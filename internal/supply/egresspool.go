package supply

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// This file is the egress pool: the exits this installation owns, identified by
// a small integer.
//
// Why an id rather than a URL everywhere: an exit is a bought address that gets
// replaced. An account's exit is part of its identity, so when an exit is
// retired every account on it has to move together. Storing the URL on each
// account would mean editing N places and no way to answer "who is on #1".
//
// The pool is the authority for two questions:
//
//   - which exit is #n, and is it working (LastProbe)
//   - which identities are bound to #n (counted by the management surface, not
//     stored here: the bindings live on the accounts, channels and keys
//     themselves, and a copy here would drift)
//
// It deliberately does not store bindings. A binding is a fact about an account,
// and duplicating it in the pool would create a second source of truth that goes
// stale the moment an account is deleted by any other path.

// egressPoolVersion is the on-disk schema version.
const egressPoolVersion = 1

// EgressPoolPath is where the proxy list lives inside a supply state directory.
func EgressPoolPath(dir string) string { return filepath.Join(dir, "egress-pool.json") }

// EgressProbe is what an echo service said about an exit the last time it was
// asked.
//
// It is a snapshot, not a live state: "last time we asked" is a fact, "it works
// right now" is not something this file can claim.
type EgressProbe struct {
	OK          bool   `json:"ok"`
	IP          string `json:"ip,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	City        string `json:"city,omitempty"`
	ASN         string `json:"asn,omitempty"`
	Org         string `json:"org,omitempty"`
	Error       string `json:"error,omitempty"`
	LatencyMS   int64  `json:"latency_ms,omitempty"`
	// At is when the probe ran, in Unix seconds. Zero means never probed.
	At int64 `json:"at,omitempty"`
}

// EgressEntry is one exit.
type EgressEntry struct {
	// ID is what accounts and channels point at. It is never reused: a retired
	// #2 stays retired so an old reference cannot silently mean a new address.
	ID      int    `json:"id"`
	URL     string `json:"url"`
	Label   string `json:"label,omitempty"`
	Note    string `json:"note,omitempty"`
	Enabled bool   `json:"enabled"`
	Created int64  `json:"created,omitempty"`
	// LastProbe is the most recent answer from an echo service. Absent means
	// never probed, which is shown as "not tested" rather than as a failure.
	LastProbe *EgressProbe `json:"last_probe,omitempty"`
}

// Display is what the panel shows in a list: the label, or the address when the
// operator did not name it.
func (e EgressEntry) Display() string {
	if label := strings.TrimSpace(e.Label); label != "" {
		return label
	}
	return proxyutil.Redact(e.URL)
}

// EgressPoolDocument is the on-disk proxy list.
type EgressPoolDocument struct {
	Version int           `json:"version"`
	NextID  int           `json:"next_id"`
	Entries []EgressEntry `json:"entries,omitempty"`
}

// EgressPool is the proxy list, persisted as one JSON document.
type EgressPool struct {
	mu   sync.RWMutex
	path string
	doc  EgressPoolDocument
}

// NewEgressPool returns an empty pool that persists to path.
func NewEgressPool(path string) *EgressPool {
	return &EgressPool{path: path, doc: EgressPoolDocument{Version: egressPoolVersion, NextID: 1}}
}

// LoadEgressPool reads the pool; a missing file yields an empty one.
func LoadEgressPool(path string) (*EgressPool, error) {
	// Decode into a zero document rather than a pre-seeded one: "next_id is
	// absent" has to stay observable, or a hand-written file would be read as
	// next_id=1 and the next Add would collide with a stored id.
	pool := &EgressPool{path: path}
	if errLoad := loadJSON(path, &pool.doc); errLoad != nil {
		return NewEgressPool(path), errLoad
	}
	if pool.doc.Version == 0 {
		pool.doc.Version = egressPoolVersion
	}
	// A document written before ids were allocated, or one edited by hand, may
	// carry entries without a NextID, or a NextID that is behind the ids already
	// in use. Either way an id that is already taken must never be handed out
	// again: bindings are held by id, so a duplicate would make two exits answer
	// to one number and resolve to whichever came first.
	highest := 0
	for _, entry := range pool.doc.Entries {
		if entry.ID > highest {
			highest = entry.ID
		}
	}
	if pool.doc.NextID <= highest {
		pool.doc.NextID = highest + 1
	}
	return pool, nil
}

// Path is where this pool persists.
func (p *EgressPool) Path() string { return p.path }

// List returns every entry, in id order.
func (p *EgressPool) List() []EgressEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]EgressEntry, len(p.doc.Entries))
	copy(out, p.doc.Entries)
	return out
}

// Get returns one entry by id.
func (p *EgressPool) Get(id int) (EgressEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.getLocked(id)
}

func (p *EgressPool) getLocked(id int) (EgressEntry, bool) {
	for _, entry := range p.doc.Entries {
		if entry.ID == id {
			return entry, true
		}
	}
	return EgressEntry{}, false
}

// Resolve returns the address behind an id.
//
// The second result distinguishes "no such entry" from "entry exists but is
// disabled": a caller that is about to send traffic has to tell those apart,
// because a dangling id is a configuration error while a disabled entry is an
// operator's decision.
func (p *EgressPool) Resolve(id int) (url string, found bool, enabled bool) {
	entry, ok := p.Get(id)
	if !ok {
		return "", false, false
	}
	return entry.URL, true, entry.Enabled
}

// NormalizeEgressURL trims and validates an exit address.
//
// "direct" and "none" are rejected here on purpose: those spellings mean "no
// proxy", and an entry in the pool that means "no proxy" would let an account
// silently leave from the host's own address while looking bound.
func NormalizeEgressURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("supply: an exit needs an address")
	}
	if !proxyutil.ValidRequestProxy(trimmed) {
		return "", fmt.Errorf("supply: %q is not a usable proxy address (expected http, https, socks5 or socks5h with a host)", trimmed)
	}
	return trimmed, nil
}

// Add appends one exit and returns it with its assigned id.
func (p *EgressPool) Add(url, label, note string) (EgressEntry, error) {
	normalized, errURL := NormalizeEgressURL(url)
	if errURL != nil {
		return EgressEntry{}, errURL
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := EgressEntry{
		ID:      p.doc.NextID,
		URL:     normalized,
		Label:   strings.TrimSpace(label),
		Note:    strings.TrimSpace(note),
		Enabled: true,
		Created: time.Now().Unix(),
	}
	p.doc.NextID = entry.ID + 1
	p.doc.Entries = append(p.doc.Entries, entry)
	if errSave := p.saveLocked(); errSave != nil {
		return EgressEntry{}, errSave
	}
	return entry, nil
}

// EgressEdit carries the fields an update may change.
//
// Each field is a pointer so that "leave it alone" and "set it to empty" stay
// distinguishable: a label can be cleared, and an address that is omitted must
// keep the stored one rather than being wiped by a panel that only reads it back
// redacted.
type EgressEdit struct {
	URL     *string
	Label   *string
	Note    *string
	Enabled *bool
}

// Update applies an edit and returns the stored entry.
func (p *EgressPool) Update(id int, edit EgressEdit) (EgressEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	index := -1
	for i, entry := range p.doc.Entries {
		if entry.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return EgressEntry{}, fmt.Errorf("supply: no exit #%d", id)
	}
	updated := p.doc.Entries[index]
	if edit.URL != nil {
		normalized, errURL := NormalizeEgressURL(*edit.URL)
		if errURL != nil {
			return EgressEntry{}, errURL
		}
		if normalized != updated.URL {
			// The address changed, so the old probe no longer describes this
			// entry. Dropping it is the honest move: keeping it would show a
			// green address that belongs to the previous exit.
			updated.LastProbe = nil
		}
		updated.URL = normalized
	}
	if edit.Label != nil {
		updated.Label = strings.TrimSpace(*edit.Label)
	}
	if edit.Note != nil {
		updated.Note = strings.TrimSpace(*edit.Note)
	}
	if edit.Enabled != nil {
		updated.Enabled = *edit.Enabled
	}
	p.doc.Entries[index] = updated
	if errSave := p.saveLocked(); errSave != nil {
		return EgressEntry{}, errSave
	}
	return updated, nil
}

// Delete removes one entry. A missing id is not an error.
//
// Deleting does not touch any binding: the accounts keep whatever address they
// were given. The management surface refuses a delete while bindings exist so
// this stays a deliberate second step rather than an accident.
func (p *EgressPool) Delete(id int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.doc.Entries[:0]
	for _, entry := range p.doc.Entries {
		if entry.ID != id {
			kept = append(kept, entry)
		}
	}
	if len(kept) == len(p.doc.Entries) {
		return nil
	}
	p.doc.Entries = kept
	return p.saveLocked()
}

// RecordProbe stores the result of asking an echo service about one exit.
func (p *EgressPool) RecordProbe(id int, probe EgressProbe) (EgressEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	index := -1
	for i, entry := range p.doc.Entries {
		if entry.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return EgressEntry{}, fmt.Errorf("supply: no exit #%d", id)
	}
	if probe.At == 0 {
		probe.At = time.Now().Unix()
	}
	p.doc.Entries[index].LastProbe = &probe
	updated := p.doc.Entries[index]
	if errSave := p.saveLocked(); errSave != nil {
		return EgressEntry{}, errSave
	}
	return updated, nil
}

// UnresolvedEgress is what a caller passes on when a pool id cannot be resolved.
//
// It is deliberately not a valid proxy address: the transport builder rejects
// it, so a dangling reference fails loudly instead of quietly leaving from the
// host's own address. A silent direct connection is the one outcome this design
// must never produce, because it puts an identity on an address nobody chose.
const UnresolvedEgress = "unresolved:egress-id"

// EgressRef is a stored reference to an exit.
//
// It has two spellings on purpose. ID is the managed form: it survives the
// address being replaced, which is the whole reason the pool exists. URL is the
// hand-typed form an older installation already has, and it still describes a
// real exit, so it keeps working.
type EgressRef struct {
	// ID names a pool entry. Zero means this reference is a bare address.
	ID int
	// URL is the address, either the managed one resolved from ID or the typed
	// one when ID is zero.
	URL string
}

// IsSet reports whether the reference names an exit at all.
func (r EgressRef) IsSet() bool {
	return r.ID > 0 || strings.TrimSpace(r.URL) != ""
}

// Resolve returns the address a reference names.
//
// An ID always wins over a URL stored beside it: the URL is a cache that goes
// stale the moment the exit is replaced, and honouring it would mean a replaced
// exit keeps sending traffic from the old address.
//
// A dangling ID is an error rather than a silent fallback to the URL or to a
// direct connection. Quietly leaving from the host's own address is the one
// failure this design must not allow: it would put a whole account on an
// address the operator never chose.
//
// A disabled entry still resolves. Disabling means "do not assign new
// identities here"; it is not a switch that cuts off what is already bound,
// because an operator disabling an exit during a replacement would otherwise
// take every account on it offline at once.
func (p *EgressPool) ResolveRef(ref EgressRef) (string, error) {
	if ref.ID <= 0 {
		return strings.TrimSpace(ref.URL), nil
	}
	url, found, _ := p.Resolve(ref.ID)
	if !found {
		return "", fmt.Errorf("supply: exit #%d is referenced but no longer exists", ref.ID)
	}
	return url, nil
}

// Next returns the exit a new identity should be bound to.
//
// The rule is deliberately boring: among enabled entries, the one with the
// fewest bindings, ties broken by the lowest id. Randomness would make "why is
// this account on #3" unanswerable, and a rotation would put one account's
// traffic on several exits over its life, which is exactly the pattern a burnt
// exit is inferred from.
//
// An exit whose last probe failed is passed over while any other candidate
// exists. That is what "make sure this exit is usable" means at assignment
// time: a failed probe does not prove the exit is dead (every echo service can
// be down at once), so it is not a ban, but handing out an exit we already know
// did not answer would be a choice nobody made.
//
// counts is how many identities each id already holds. An id missing from the
// map counts as zero.
func (p *EgressPool) Next(counts map[int]int) (EgressEntry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	best, ok := p.leastLoadedLocked(counts, true)
	if ok {
		return best, true
	}
	// Every enabled exit has a failed probe on record. Something has to be
	// handed out, and a stale failure is weaker evidence than an empty list.
	return p.leastLoadedLocked(counts, false)
}

// leastLoadedLocked picks the enabled entry with the fewest bindings.
//
// When skipFailedProbes is set, entries whose last probe failed are ignored.
func (p *EgressPool) leastLoadedLocked(counts map[int]int, skipFailedProbes bool) (EgressEntry, bool) {
	var best EgressEntry
	found := false
	for _, entry := range p.doc.Entries {
		if !entry.Enabled {
			continue
		}
		if skipFailedProbes && entry.LastProbe != nil && !entry.LastProbe.OK {
			continue
		}
		if !found {
			best, found = entry, true
			continue
		}
		current, bestCount := counts[entry.ID], counts[best.ID]
		if current < bestCount || (current == bestCount && entry.ID < best.ID) {
			best = entry
		}
	}
	return best, found
}

func (p *EgressPool) saveLocked() error {
	if p.doc.Version == 0 {
		p.doc.Version = egressPoolVersion
	}
	if errSave := saveJSON(p.path, p.doc); errSave != nil {
		return errSave
	}
	return nil
}
