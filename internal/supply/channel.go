package supply

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// StateDir resolves the directory that holds the supply state documents.
//
// An explicit configured directory wins; otherwise state lives beside the
// configuration file. Startup and the management surface resolve it through
// here so both always name the same directory.
func StateDir(configDir, configured string) string {
	if dir := strings.TrimSpace(configured); dir != "" {
		return dir
	}
	return filepath.Join(configDir, "supply")
}

// Nature is how the host reaches a channel: the transport it speaks. It is what
// decides the connection form and the shape of the pool the channel feeds.
//
// It is deliberately *not* "where the identity comes from". The same
// self-hosted domain can be read through a forwarding worker's API or through
// IMAP on the mailbox itself, so the origin is a value, not a form.
type Nature string

const (
	// NatureAPI reaches an HTTP service: a code platform, a temporary mailbox
	// service, or a forwarding worker.
	NatureAPI Nature = "api"
	// NatureIMAP reads a mailbox over IMAP. One mailbox can serve many
	// recipient addresses, which is what lets several self-hosted domains
	// forward into a single channel.
	NatureIMAP Nature = "imap"
	// NatureWeb drives a website's own endpoints with a session cookie. Phone
	// only: it is how a code platform's channel list is managed.
	NatureWeb Nature = "web"
)

// natures lists every supported nature, in the order the panel offers them.
var natures = []Nature{NatureAPI, NatureIMAP, NatureWeb}

// Natures returns the supported natures.
func Natures() []Nature {
	out := make([]Nature, len(natures))
	copy(out, natures)
	return out
}

// Valid reports whether n is a known nature.
func (n Nature) Valid() bool {
	for _, candidate := range natures {
		if candidate == n {
			return true
		}
	}
	return false
}

// SupportsKind reports whether a channel of this nature can serve kind.
//
// A phone identity comes from a platform (over its API) or from that platform's
// website session; mail is read over an API or over IMAP. A nature that cannot
// serve a kind is rejected when the channel is saved, rather than failing later
// at the first call.
func (n Nature) SupportsKind(kind Kind) bool {
	switch kind {
	case KindPhone:
		return n == NatureAPI || n == NatureWeb
	case KindEmail:
		return n == NatureAPI || n == NatureIMAP
	}
	return false
}

// Channel is one configured source of identities.
//
// Label is what a person reads and picks from; Nature is what the host switches
// on. Keeping them separate is what lets a channel be renamed without changing
// how it is reached — the id, not the label, is the durable key.
type Channel struct {
	// ID is stable for the channel's lifetime; renaming a label never changes
	// it, because the ledger attributes identities by id.
	ID string `json:"id"`
	// Kind is the identity kind this channel hands out.
	Kind Kind `json:"kind"`
	// Label is the free-text name a person sees and selects by.
	Label string `json:"label"`
	// Nature is the transport, which selects the implementation and the
	// connection form.
	Nature Nature `json:"nature"`
	// Endpoint is the service address for a network nature, when the operator
	// needs one. It never holds a credential.
	Endpoint string `json:"endpoint,omitempty"`
	// Account is the non-secret sign-in name, when the nature has one. A
	// password, token or authorization code is never held here.
	Account string `json:"account,omitempty"`
	// Secret names the credential in the host secret store. It is a name, not a
	// value: the value is only ever read through the store at call time.
	Secret string `json:"secret,omitempty"`
	// Enabled turns the channel off without deleting it.
	Enabled bool `json:"enabled"`
	// Created and Updated are unix seconds.
	Created int64 `json:"created,omitempty"`
	Updated int64 `json:"updated,omitempty"`
}

// Normalize trims a channel's text fields and validates it.
func (c Channel) Normalize() (Channel, error) {
	c.ID = strings.TrimSpace(c.ID)
	c.Label = strings.TrimSpace(c.Label)
	c.Endpoint = strings.TrimSpace(c.Endpoint)
	c.Account = strings.TrimSpace(c.Account)
	c.Secret = strings.TrimSpace(c.Secret)
	if !c.Kind.Valid() {
		return Channel{}, fmt.Errorf("supply: channel has unknown kind %q", c.Kind)
	}
	if c.Label == "" {
		return Channel{}, errors.New("supply: channel needs a label")
	}
	if !c.Nature.Valid() {
		return Channel{}, fmt.Errorf("supply: channel has unknown nature %q", c.Nature)
	}
	if !c.Nature.SupportsKind(c.Kind) {
		return Channel{}, fmt.Errorf("supply: nature %q cannot serve the %s kind", c.Nature, c.Kind)
	}
	return c, nil
}

// ChannelDocument is the on-disk channel list.
type ChannelDocument struct {
	Version  int       `json:"version"`
	Channels []Channel `json:"channels,omitempty"`
}

// channelVersion is the on-disk schema version.
const channelVersion = 1

// ChannelPath is where the channel list lives inside a supply state directory.
func ChannelPath(dir string) string { return filepath.Join(dir, "channels.json") }

// ChannelStore is the configured-channel list.
//
// It is one document for every kind, for the same reason the ledger is: "which
// sources exist" is one question, and a per-kind file would put the join back
// on the reader.
type ChannelStore struct {
	mu   sync.RWMutex
	path string
	doc  ChannelDocument
}

// NewChannelStore returns an empty store that persists to path.
func NewChannelStore(path string) *ChannelStore {
	return &ChannelStore{path: path, doc: ChannelDocument{Version: channelVersion}}
}

// LoadChannels reads the channel list; a missing file yields an empty store.
func LoadChannels(path string) (*ChannelStore, error) {
	store := NewChannelStore(path)
	if errLoad := loadJSON(path, &store.doc); errLoad != nil {
		return NewChannelStore(path), errLoad
	}
	if store.doc.Version == 0 {
		store.doc.Version = channelVersion
	}
	return store, nil
}

// Path is where this store persists.
func (s *ChannelStore) Path() string { return s.path }

// List returns every channel of one kind. An unknown kind is not a filter, so
// it returns every channel — the same "no filter" reading the identity ledger
// gives an unknown kind, so the two surfaces agree.
func (s *ChannelStore) List(kind Kind) []Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Channel, 0, len(s.doc.Channels))
	for _, channel := range s.doc.Channels {
		if kind.Valid() && channel.Kind != kind {
			continue
		}
		out = append(out, channel)
	}
	return out
}

// All returns every channel, across kinds.
func (s *ChannelStore) All() []Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Channel, len(s.doc.Channels))
	copy(out, s.doc.Channels)
	return out
}

// Get returns one channel by id.
func (s *ChannelStore) Get(id string) (Channel, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(strings.TrimSpace(id))
}

func (s *ChannelStore) getLocked(id string) (Channel, bool) {
	for _, channel := range s.doc.Channels {
		if channel.ID == id {
			return channel, true
		}
	}
	return Channel{}, false
}

// Upsert creates or replaces a channel.
//
// An empty id creates one, deriving a stable id from the label; a known id
// updates in place and keeps its creation time; an unknown id creates a channel
// under that id, so a caller can pick its own key. A label that collides with
// another channel is allowed — the id is the key, and two channels may share a
// name — but the derived id is de-duplicated so a new channel never silently
// takes over an existing one.
//
// Kind is immutable: a channel's identities were handed out under it, so
// changing it would silently re-attribute them.
func (s *ChannelStore) Upsert(channel Channel, now int64) (Channel, error) {
	normalized, errNormalize := channel.Normalize()
	if errNormalize != nil {
		return Channel{}, errNormalize
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if normalized.ID == "" {
		normalized.ID = s.nextIDLocked(normalized.Kind, normalized.Label)
		normalized.Created = now
	} else if existing, ok := s.getLocked(normalized.ID); ok {
		normalized.Created = existing.Created
		if normalized.Kind != existing.Kind {
			return Channel{}, errors.New("supply: a channel cannot change its kind")
		}
	} else {
		normalized.Created = now
	}
	normalized.Updated = now

	replaced := false
	for i := range s.doc.Channels {
		if s.doc.Channels[i].ID == normalized.ID {
			s.doc.Channels[i] = normalized
			replaced = true
			break
		}
	}
	if !replaced {
		s.doc.Channels = append(s.doc.Channels, normalized)
	}
	if errSave := s.saveLocked(); errSave != nil {
		return Channel{}, errSave
	}
	return normalized, nil
}

// Delete removes one channel. A missing id is not an error: the caller wanted
// it gone, and it is.
func (s *ChannelStore) Delete(id string) error {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.doc.Channels[:0]
	for _, channel := range s.doc.Channels {
		if channel.ID != id {
			kept = append(kept, channel)
		}
	}
	if len(kept) == len(s.doc.Channels) {
		return nil
	}
	s.doc.Channels = kept
	return s.saveLocked()
}

// nextIDLocked derives an unused id for a new channel. Callers hold the lock.
func (s *ChannelStore) nextIDLocked(kind Kind, label string) string {
	base := string(kind) + "-" + slug(label)
	if strings.HasSuffix(base, "-") {
		base += "channel"
	}
	id := base
	for n := 2; ; n++ {
		if _, taken := s.getLocked(id); !taken {
			return id
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
}

// saveLocked persists the document. Callers hold the lock.
func (s *ChannelStore) saveLocked() error {
	if s.doc.Version == 0 {
		s.doc.Version = channelVersion
	}
	return saveJSON(s.path, s.doc)
}

// slug reduces a label to an id-safe token. Labels are free text and may be
// entirely non-Latin, in which case there is no token to derive and the caller
// falls back to a generic name.
func slug(label string) string {
	var b strings.Builder
	trailingDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			trailingDash = false
			continue
		}
		if b.Len() > 0 && !trailingDash {
			b.WriteByte('-')
			trailingDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
