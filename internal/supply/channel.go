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
func (n Nature) SupportsKind(kind Kind) bool {
	switch kind {
	case KindPhone:
		return n == NatureAPI || n == NatureWeb
	case KindEmail:
		return n == NatureAPI || n == NatureIMAP
	}
	return false
}

// Connection holds the per-nature details for reaching a channel.
type Connection struct {
	Endpoint string `json:"endpoint,omitempty"`
	Account  string `json:"account,omitempty"`
	Secret   string `json:"secret,omitempty"`
	// IMAP-only fields.
	Usage  string `json:"usage,omitempty"`
	Domain string `json:"domain,omitempty"`
}

// KindConfig is the per-kind block inside a channel: which natures it speaks
// and the connection details for each.
type KindConfig struct {
	Enabled     bool                  `json:"enabled"`
	Natures     []Nature              `json:"natures"`
	Connections map[Nature]Connection `json:"connections"`
}

// Channel is one configured source of identities.
//
// A channel can serve phone, email, or both. Each kind has its own set of
// natures (connection methods) and per-nature connection details. The label is
// what a person reads and picks from; the id is the durable key.
type Channel struct {
	ID       string      `json:"id"`
	Label    string      `json:"label"`
	Category string      `json:"category,omitempty"`
	Phone    *KindConfig `json:"phone,omitempty"`
	Email    *KindConfig `json:"email,omitempty"`
	Created  int64       `json:"created,omitempty"`
	Updated  int64       `json:"updated,omitempty"`
}

// Kinds returns the identity kinds this channel serves.
func (c Channel) Kinds() []Kind {
	var out []Kind
	if c.Phone != nil {
		out = append(out, KindPhone)
	}
	if c.Email != nil {
		out = append(out, KindEmail)
	}
	return out
}

// KindConfigFor returns the config block for a kind, or nil.
func (c Channel) KindConfigFor(kind Kind) *KindConfig {
	switch kind {
	case KindPhone:
		return c.Phone
	case KindEmail:
		return c.Email
	}
	return nil
}

// normalizeConnection trims text fields and validates IMAP-specific rules.
func normalizeConnection(nature Nature, conn Connection) (Connection, error) {
	conn.Endpoint = strings.TrimSpace(conn.Endpoint)
	conn.Account = strings.TrimSpace(conn.Account)
	conn.Secret = strings.TrimSpace(conn.Secret)
	conn.Usage = strings.TrimSpace(conn.Usage)
	conn.Domain = strings.TrimSpace(conn.Domain)
	if nature != NatureIMAP {
		conn.Usage = ""
		conn.Domain = ""
	} else {
		if conn.Usage == "" {
			conn.Usage = "personal"
		}
		switch conn.Usage {
		case "self-domain":
			if conn.Domain == "" {
				return Connection{}, errors.New("supply: self-domain usage requires a domain")
			}
		case "personal":
			conn.Domain = ""
		default:
			return Connection{}, fmt.Errorf("supply: unknown imap usage %q", conn.Usage)
		}
	}
	return conn, nil
}

// normalizeKindConfig validates one kind block.
func normalizeKindConfig(kind Kind, kc *KindConfig) error {
	if len(kc.Natures) == 0 {
		return fmt.Errorf("supply: %s config has no natures", kind)
	}
	if kc.Connections == nil {
		kc.Connections = make(map[Nature]Connection)
	}
	seen := make(map[Nature]bool, len(kc.Natures))
	for i, nature := range kc.Natures {
		if !nature.Valid() {
			return fmt.Errorf("supply: unknown nature %q in %s config", nature, kind)
		}
		if !nature.SupportsKind(kind) {
			return fmt.Errorf("supply: nature %q cannot serve the %s kind", nature, kind)
		}
		if seen[nature] {
			return fmt.Errorf("supply: duplicate nature %q in %s config", nature, kind)
		}
		seen[nature] = true
		conn, errConn := normalizeConnection(nature, kc.Connections[nature])
		if errConn != nil {
			return errConn
		}
		kc.Connections[nature] = conn
		_ = i
	}
	// Remove stale connection entries not in the nature list.
	for key := range kc.Connections {
		if !seen[key] {
			delete(kc.Connections, key)
		}
	}
	return nil
}

// Normalize trims text fields and validates the channel.
func (c Channel) Normalize() (Channel, error) {
	c.ID = strings.TrimSpace(c.ID)
	c.Label = strings.TrimSpace(c.Label)
	c.Category = strings.TrimSpace(c.Category)
	if c.Label == "" {
		return Channel{}, errors.New("supply: channel needs a label")
	}
	// Category defaults to third-party.
	if c.Category == "" {
		c.Category = "third-party"
	}
	switch c.Category {
	case "third-party", "self-owned", "self-built":
		// ok
	default:
		return Channel{}, fmt.Errorf("supply: unknown category %q", c.Category)
	}
	// At least one kind must be configured.
	if c.Phone == nil && c.Email == nil {
		return Channel{}, errors.New("supply: channel must serve at least one kind")
	}
	if c.Phone != nil {
		if err := normalizeKindConfig(KindPhone, c.Phone); err != nil {
			return Channel{}, err
		}
	}
	if c.Email != nil {
		if err := normalizeKindConfig(KindEmail, c.Email); err != nil {
			return Channel{}, err
		}
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

// List returns every channel that serves kind. An unknown kind returns all.
func (s *ChannelStore) List(kind Kind) []Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Channel, 0, len(s.doc.Channels))
	for _, channel := range s.doc.Channels {
		if kind.Valid() && channel.KindConfigFor(kind) == nil {
			continue
		}
		out = append(out, channel)
	}
	return out
}

// All returns every channel.
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
func (s *ChannelStore) Upsert(channel Channel, now int64) (Channel, error) {
	normalized, errNormalize := channel.Normalize()
	if errNormalize != nil {
		return Channel{}, errNormalize
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if normalized.ID == "" {
		normalized.ID = s.nextIDLocked(normalized.Label)
		normalized.Created = now
	} else if existing, ok := s.getLocked(normalized.ID); ok {
		normalized.Created = existing.Created
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

// Delete removes one channel. A missing id is not an error.
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

// nextIDLocked derives an unused id for a new channel.
func (s *ChannelStore) nextIDLocked(label string) string {
	base := slug(label)
	if base == "" {
		base = "channel"
	}
	id := base
	for n := 2; ; n++ {
		if _, taken := s.getLocked(id); !taken {
			return id
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
}

func (s *ChannelStore) saveLocked() error {
	return saveJSON(s.path, s.doc)
}

// slug reduces a label to a URL-safe ASCII identifier.
func slug(label string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(label) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 && r == ' ' || r == '-' || r == '_' {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// contains reports whether the slice includes the value.
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
