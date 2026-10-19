package supply

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
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
	// NatureOAuth2 reads a mailbox over IMAP too, but authenticates with an
	// OAuth2 bearer token minted from a refresh token instead of with a
	// password. Microsoft mailboxes accept nothing else: their IMAP server
	// answers LOGINDISABLED and advertises AUTH=XOAUTH2 alone.
	//
	// It is a separate nature rather than a flag on NatureIMAP because the
	// operator's answer differs — a different credential, a different form,
	// a different failure ("the refresh token expired" is not "the password is
	// wrong").
	//
	// It is not a channel nature: a mailbox that carries its own credential is
	// one identity, so it lives in the pool. See ChannelNatures.
	NatureOAuth2 Nature = "oauth2"
	// NatureGraph reads the same mailbox through Microsoft Graph's REST API.
	//
	// It exists because a refresh token's grant decides what the token can be
	// spent on: one minted for Graph scopes is refused by the IMAP server and
	// cannot be exchanged for an IMAP token, so a channel that only speaks IMAP
	// cannot use that mailbox at all.
	//
	// Like NatureOAuth2 it is a pool identity's transport, not a channel nature.
	NatureGraph Nature = "graph"
	// NatureWeb drives a website's own endpoints with a session cookie. Phone
	// only: it is how a code platform's channel list is managed.
	NatureWeb Nature = "web"
)

// natures lists every supported nature, in the order the panel offers them.
var natures = []Nature{NatureAPI, NatureIMAP, NatureOAuth2, NatureGraph, NatureWeb}

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
		return n == NatureAPI || n == NatureIMAP || n == NatureOAuth2 || n == NatureGraph
	}
	return false
}

// ChannelNatures lists the natures a channel of kind may declare, in the order
// the panel offers them.
//
// It is narrower than SupportsKind on purpose. A channel is one connection that
// covers many addresses — a code platform, a catch-all domain, a forwarding
// service. A mailbox that owns its own address and its own credential is the
// other kind of thing: it is one identity, it lives in the pool, and giving it a
// channel of its own would turn the channel table into an address book.
//
// Email therefore keeps only IMAP here. OAuth2 and Graph are how a single
// mailbox authenticates, which is a pool identity's business, not a channel's.
func ChannelNatures(kind Kind) []Nature {
	switch kind {
	case KindPhone:
		return []Nature{NatureAPI, NatureWeb}
	case KindEmail:
		return []Nature{NatureIMAP}
	}
	return nil
}

// ReadsMailbox reports whether this nature opens a mailbox over IMAP.
//
// Both IMAP and OAuth2 speak the same protocol, so they share the address
// rules, the derived credential name shape, and the catch-all domain question.
// They differ only in what proves the session's identity, which is why the
// stored credential cannot be shared between them. Graph reads the same mailbox
// but not over IMAP, so it is a mailbox without being one of these — see
// IsMailbox.
func (n Nature) ReadsMailbox() bool {
	return n == NatureIMAP || n == NatureOAuth2
}

// IsMailbox reports whether this nature reads a mailbox at all, over either
// protocol. Everything that holds for a mailbox regardless of transport — the
// catch-all domain, the derived credential entry, the one-credential-per-mailbox
// rule — hangs off this rather than off the IMAP pair.
func (n Nature) IsMailbox() bool {
	return n.ReadsMailbox() || n == NatureGraph
}

// UsesRefreshToken reports whether the stored credential is an OAuth2 refresh
// token rather than a password or an authorization code.
//
// The token is the same for both token-based transports; only the resource it is
// spent on differs.
func (n Nature) UsesRefreshToken() bool {
	return n == NatureOAuth2 || n == NatureGraph
}

// Connection holds the per-nature details for reaching a channel.
type Connection struct {
	Endpoint string `json:"endpoint,omitempty"`
	Account  string `json:"account,omitempty"`
	Secret   string `json:"secret,omitempty"`
	// Mailbox-only fields.
	//
	// Usage is derived, not typed: it follows the channel's category (see
	// Channel.CatchAll), so it can never disagree with it. Domain is the one fact
	// only the operator knows, and it is required exactly when the mailbox is a
	// domain's catch-all.
	Usage  string `json:"usage,omitempty"`
	Domain string `json:"domain,omitempty"`
	// ClientID is the OAuth2 application the refresh token was issued to.
	//
	// It lives on the channel rather than in the secret store because it is not
	// a secret — the refresh token is — and an operator editing the channel
	// should see which application it belongs to without retyping it.
	ClientID string `json:"client_id,omitempty"`
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

// CatchAllCategory reports whether category means "a domain I built that catches
// every address" rather than "one mailbox I can read".
//
// The two categories answer different questions and neither is a synonym for the
// other:
//
//   - third-party: someone else's service. One address at a time.
//   - self-built:  a domain of mine with a catch-all, so a fresh address can be
//     minted for every signup and all of them land in one mailbox.
//
// A personal mailbox of one's own used to be a third category. It is not one any
// more: a channel exists to cover many addresses from one connection, while a
// personal mailbox is exactly one address with its own credential — an identity
// of the pool, not a source of identities. Keeping it here made the channel table
// grow one row per bought mailbox.
func CatchAllCategory(category string) bool {
	return strings.TrimSpace(category) == "self-built"
}

// CatchAll reports whether this channel's mailbox receives every address of a
// domain the operator built.
//
// This is the switch that decides what the channel *is*, and it lives in the
// category on purpose: "a domain of mine with a catch-all" is a fact about what
// the channel can do, not about how we connect (the same domain can be read over
// IMAP or through a forwarding worker's API). Keeping it here means the panel
// asks it once, and the connection cannot contradict it.
func (c Channel) CatchAll() bool {
	return CatchAllCategory(c.Category)
}

// normalizeEndpoint trims a connection address and gives it an explicit scheme
// when it was written without one, so "api.haozhuma.com" is stored as
// "https://api.haozhuma.com" instead of failing at request time as a
// scheme-less URL. An explicit http:// is kept: the choice is the operator's.
//
// An empty address is left empty, so a nature that needs none is unaffected. A
// non-empty address must be an http(s) URL with a host; anything else is
// rejected here, which is what makes the write answer 400 rather than the
// request path failing later.
func normalizeEndpoint(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	parsed, errParse := url.Parse(trimmed)
	if errParse != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("supply: endpoint %q is not an http(s) address", strings.TrimSpace(value))
	}
	return strings.TrimRight(trimmed, "/"), nil
}

// normalizeIMAPEndpoint validates a mailbox connection address, which is a host
// with an optional port ("imap.qq.com:993") rather than a URL.
//
// IMAP is not HTTP, so the rule normalizeEndpoint applies would be actively
// harmful here: it prefixes "https://" onto a bare host, and the client would
// then try to dial a URL it cannot use. A scheme in an IMAP address is rejected
// instead of silently rewritten, because the operator meant something the host
// will not do.
//
// An omitted port is left off: the default belongs to the client, not to the
// stored document.
func normalizeIMAPEndpoint(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if strings.Contains(trimmed, "://") {
		return "", fmt.Errorf("supply: imap endpoint %q must be host:port, not a URL", trimmed)
	}
	host, port, errSplit := net.SplitHostPort(trimmed)
	if errSplit != nil {
		host, port = trimmed, ""
	}
	if host == "" || strings.ContainsAny(host, " \t/") {
		return "", fmt.Errorf("supply: imap endpoint %q has no usable host", trimmed)
	}
	if port == "" {
		return host, nil
	}
	number, errAtoi := strconv.Atoi(port)
	if errAtoi != nil || number < 1 || number > 65535 {
		return "", fmt.Errorf("supply: imap endpoint %q has an invalid port", trimmed)
	}
	return host + ":" + port, nil
}

// normalizeConnection trims text fields and validates mailbox-specific rules.
//
// catchAll is the channel's category answer: a mailbox that receives for a
// domain the operator owns needs that domain, and a plain mailbox must not carry
// one. Deriving the usage from it — instead of reading a usage the caller sent —
// is what keeps the two from disagreeing.
//
// Only the natures a channel may declare reach here (see ChannelNatures), so the
// token-based mailbox transports are not handled: they carry their own
// credentials, which makes them pool identities rather than channels.
func normalizeConnection(nature Nature, conn Connection, catchAll bool) (Connection, error) {
	conn.Endpoint = strings.TrimSpace(conn.Endpoint)
	conn.Account = strings.TrimSpace(conn.Account)
	conn.Secret = strings.TrimSpace(conn.Secret)
	conn.Usage = strings.TrimSpace(conn.Usage)
	conn.Domain = strings.TrimSpace(conn.Domain)
	conn.ClientID = strings.TrimSpace(conn.ClientID)
	if nature.ReadsMailbox() {
		endpoint, errEndpoint := normalizeIMAPEndpoint(conn.Endpoint)
		if errEndpoint != nil {
			return Connection{}, errEndpoint
		}
		conn.Endpoint = endpoint
	} else {
		endpoint, errEndpoint := normalizeEndpoint(conn.Endpoint)
		if errEndpoint != nil {
			return Connection{}, errEndpoint
		}
		conn.Endpoint = endpoint
	}
	if !nature.IsMailbox() {
		conn.Usage = ""
		conn.Domain = ""
		conn.ClientID = ""
		return conn, nil
	}
	conn.ClientID = ""
	// A mailbox credential belongs to the mailbox, so its entry name is derived
	// from the login instead of being configured. A name already on the
	// connection is kept: it may name an entry that exists under an older rule,
	// and renaming the pointer would orphan the credential.
	if conn.Secret == "" {
		conn.Secret = EmailCredentialName(conn.Account)
	}
	// A domain typed as "@example.com" (or "box@example.com") names the same
	// domain, but stored as typed it can never match: matching appends "@" to it,
	// and minting builds "local@" + it. That is the failure nobody can see — the
	// channel looks configured and simply never finds a code — so it is fixed
	// here rather than reported.
	if conn.Domain != "" {
		conn.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(conn.Domain, "@")), ".")
		if strings.ContainsAny(conn.Domain, "@ \t/") {
			return Connection{}, fmt.Errorf("supply: mailbox %q names %q, which is not a bare domain", conn.Account, conn.Domain)
		}
	}
	if catchAll {
		if conn.Domain == "" {
			return Connection{}, errors.New("supply: a catch-all domain mailbox needs the domain it receives for")
		}
		conn.Usage = "self-domain"
		return conn, nil
	}
	// A domain outside the self-built category is a contradiction, not something
	// to drop quietly: the operator typed it, and dropping it would leave a
	// channel that looks configured but can only ever receive one address.
	if conn.Domain != "" {
		return Connection{}, fmt.Errorf("supply: mailbox %q names domain %q, but its category is not a self-built domain", conn.Account, conn.Domain)
	}
	conn.Usage = "personal"
	return conn, nil
}

// normalizeKindConfig validates one kind block.
func normalizeKindConfig(kind Kind, kc *KindConfig, catchAll bool) error {
	if len(kc.Natures) == 0 {
		return fmt.Errorf("supply: %s config has no natures", kind)
	}
	if kc.Connections == nil {
		kc.Connections = make(map[Nature]Connection)
	}
	seen := make(map[Nature]bool, len(kc.Natures))
	for _, nature := range kc.Natures {
		if !nature.Valid() {
			return fmt.Errorf("supply: unknown nature %q in %s config", nature, kind)
		}
		if !nature.SupportsKind(kind) {
			return fmt.Errorf("supply: nature %q cannot serve the %s kind", nature, kind)
		}
		if !containsNature(ChannelNatures(kind), nature) {
			return fmt.Errorf("supply: a %s channel does not speak %q; a mailbox with its own credential belongs to the pool", kind, nature)
		}
		if seen[nature] {
			return fmt.Errorf("supply: duplicate nature %q in %s config", nature, kind)
		}
		seen[nature] = true
		conn, errConn := normalizeConnection(nature, kc.Connections[nature], catchAll)
		if errConn != nil {
			return errConn
		}
		kc.Connections[nature] = conn
	}
	// Remove stale connection entries not in the nature list.
	for key := range kc.Connections {
		if !seen[key] {
			delete(kc.Connections, key)
		}
	}
	// A mailbox is read one way, and a channel only declares IMAP; the other
	// ways belong to a pool identity, which is checked above.
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
	case "third-party", "self-built":
		// ok
	default:
		return Channel{}, fmt.Errorf("supply: unknown category %q", c.Category)
	}
	// At least one kind must be configured.
	if c.Phone == nil && c.Email == nil {
		return Channel{}, errors.New("supply: channel must serve at least one kind")
	}
	if c.Phone != nil {
		if err := normalizeKindConfig(KindPhone, c.Phone, c.CatchAll()); err != nil {
			return Channel{}, err
		}
	}
	if c.Email != nil {
		if err := normalizeKindConfig(KindEmail, c.Email, c.CatchAll()); err != nil {
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

// EmailCredentialName is the secret-store entry holding one mailbox's password.
//
// The entry belongs to the mailbox, not to the channel: the password is the
// login's, so naming it after the channel would ask the operator for a label
// that means nothing and would break when the channel is renamed. Deriving it
// from the login also means the panel never has to send a name.
func EmailCredentialName(account string) string {
	return emailCredentialName("email-imap-", account)
}

// EmailOAuth2CredentialName is the secret-store entry holding one mailbox's
// OAuth2 refresh token.
//
// It is named apart from the password entry on purpose. The two hold different
// kinds of value, and reusing one name across a switch from one method to the
// other would hand a refresh token to an IMAP LOGIN command — a failure that
// reads as "wrong password" while the real cause is the wrong kind of secret.
func EmailOAuth2CredentialName(account string) string {
	return emailCredentialName("email-oauth2-", account)
}

// EmailPasswordCredentialName is the secret-store entry holding one mailbox's
// password.
//
// It is kept apart from the authorization code entry because it answers a
// different question: a Microsoft mailbox refuses a password on every transport,
// so this value exists only for a person signing in to the mailbox's own web
// page. Nothing in the read path ever spends it.
func EmailPasswordCredentialName(account string) string {
	return emailCredentialName("email-password-", account)
}

// emailCredentialName derives a mailbox's entry name under a method prefix.
func emailCredentialName(prefix, account string) string {
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(prefix)
	for _, r := range account {
		// Keep the login readable: a name an operator can recognise in the
		// secret store is worth more than one that is merely ASCII-safe.
		if r == '@' || r == '.' || r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return b.String()
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

// containsNature reports whether the slice includes the nature.
func containsNature(slice []Nature, value Nature) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}
