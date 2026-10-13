// Package sms is the plugin-side SMS-provider layer: it rents a number from a
// code-receiving platform, reads the verification message, and keeps a record of
// which number each account registered with so a later re-authentication can get
// back onto the same number.
//
// It is deliberately narrow. The plugin host invokes plugin callbacks
// synchronously, so anything long-running here blocks the caller; the loop that
// waits for a message therefore lives with the caller. The actions exposed here
// are the cheap ones: pick a number, read once, release, blacklist.
//
// Credentials never live in the plugin configuration. They come from the host
// secret store, so this package is constructed from an already-decrypted secret.
package phone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// Project identifies the upstream service a number is rented for.
type Project struct {
	// SID is the platform's project id (an integer rendered as a string). For
	// Loomy this is iFlytek's relay project, 21614.
	SID string
	// Name is the project's display name, used only when the platform has to be
	// searched for the project. Empty is fine: the name is also readable from a
	// channel the account has already joined.
	Name string
	// Code pins the rental to one channel (the platform's 对接码). Empty means
	// "pick automatically from the joined channels", which is the normal case.
	Code string
}

// Quote is one purchasable channel inside a project.
type Quote struct {
	// UID is the channel id (对接码), used to address the channel and to record
	// where a number came from.
	UID string `json:"uid"`
	// Price is this account's per-number cost in CNY.
	Price float64 `json:"price"`
	// Stock is how many numbers the supplier currently reports available.
	Stock int `json:"stock"`
	// Carriers lists the operators the channel draws from.
	Carriers string `json:"carriers,omitempty"`
	// Paragraphs lists the number prefixes the channel draws from.
	Paragraphs string `json:"paragraphs,omitempty"`
	// Contact is the supplier's contact handle.
	Contact string `json:"contact,omitempty"`
	// Name is the project name the channel belongs to, for display.
	Name string `json:"name,omitempty"`
	// Paused reports that the account has switched this channel off. The
	// platform rents only from channels that are both joined and enabled, so a
	// paused channel is excluded from selection even though it stays in the
	// account's joined set. Default false keeps a bare Quote usable.
	Paused bool `json:"paused,omitempty"`
}

// Number is one rented number.
type Number struct {
	// Phone is the number in national format, no country code.
	Phone string `json:"phone"`
	// SID is the project the number was rented for.
	SID string `json:"sid"`
	// Code is the channel the number came from, when the platform reports it.
	Code string `json:"code,omitempty"`
	// Carrier is the operator, e.g. 移动.
	Carrier string `json:"carrier,omitempty"`
	// Region is the number's attributed region.
	Region string `json:"region,omitempty"`
}

// Message is one read of a rented number's inbox.
type Message struct {
	// Ready reports whether a message has arrived.
	Ready bool `json:"ready"`
	// Code is the numeric verification code extracted by the platform.
	Code string `json:"code,omitempty"`
	// Text is the full message body.
	Text string `json:"text,omitempty"`
}

// ErrNoStock reports that no joined channel has an affordable number.
var ErrNoStock = errors.New("sms: no number available")

// ErrNotReady reports that a number has no message yet. It is the ordinary
// outcome of polling, not a failure.
var ErrNotReady = errors.New("sms: no message yet")

// ErrBudget reports that the next rental would exceed the configured ceiling.
var ErrBudget = errors.New("sms: spend ceiling reached")

// ErrCredential reports that the platform credential is missing or unusable.
var ErrCredential = errors.New("sms: provider credential unavailable")

// Logf receives provider-level notices. It is optional; a nil value discards
// them. The plugin installs its host logger here so the package stays free of
// any dependency on the plugin host.
var Logf func(level, message string)

// nowUnix returns the current time in unix seconds.
func nowUnix() int64 { return time.Now().Unix() }

// hostLogSafe reports a notice through Logf when one is installed.
func hostLogSafe(message string) {
	if Logf != nil {
		Logf("info", message)
	}
}

// IsFatal reports whether an acquisition error means every channel would fail,
// so the caller should stop instead of trying the next channel.
func IsFatal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoStock) || errors.Is(err, ErrBudget) || errors.Is(err, ErrCredential) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, needle := range []string{"token", "登录", "余额", "权限", "禁用", "unauthorized"} {
		if strings.Contains(message, needle) {
			return true
		}
	}
	return false
}

// Provider rents numbers and reads their inboxes for one platform.
//
// Implementations must be safe for concurrent use: several accounts can be
// re-authenticating at once.
type Provider interface {
	// ID names the provider, e.g. "haozhuma".
	ID() string
	// Balance reports the remaining account balance in CNY.
	Balance(ctx context.Context) (float64, error)
	// Rent rents one number. A non-empty uid addresses that channel; an empty
	// one lets the platform choose.
	Rent(ctx context.Context, project Project, uid string) (Number, error)
	// AcquirePhone re-occupies one exact number, which is how a later
	// re-authentication gets back onto a registered number.
	AcquirePhone(ctx context.Context, project Project, phone string) (Number, error)
	// Read reads a number's inbox once.
	Read(ctx context.Context, project Project, phone string) (Message, error)
	// Release returns a number to the platform's pool.
	Release(ctx context.Context, project Project, phone string) error
	// Blacklist permanently stops the platform handing this number back.
	Blacklist(ctx context.Context, project Project, phone string) error
}

// -- channel cache -----------------------------------------------------------

// ChannelCache is the local list of channels this account has joined, with the
// price the platform charges this account for each.
//
// It is a long-lived cache: prices are set by suppliers and rarely move, while
// the joined set changes only when somebody joins a channel. haozhuma exposes it
// only through its web surface, which needs a browser session, so it is
// snapshotted here and refreshed opportunistically.
type ChannelCache struct {
	Version   int    `json:"version"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
	SID       string `json:"sid,omitempty"`
	// ProjectHash is the web surface's handle for SID, resolved from its name.
	// It is cached because resolving it costs a name search.
	ProjectHash string  `json:"project_hash,omitempty"`
	Channels    []Quote `json:"channels,omitempty"`
}

// channelCacheVersion is the on-disk schema version.
const channelCacheVersion = 1

// NewChannelCache returns an empty cache.
func NewChannelCache() *ChannelCache { return &ChannelCache{Version: channelCacheVersion} }

// Replace swaps the cache for a freshly read channel list.
func (c *ChannelCache) Replace(sid string, channels []Quote, now int64) {
	sorted := append([]Quote(nil), channels...)
	SortQuotes(sorted)
	c.Version = channelCacheVersion
	c.SID = strings.TrimSpace(sid)
	c.Channels = sorted
	c.UpdatedAt = now
}

// SetProjectHash records the web handle for the cached project.
func (c *ChannelCache) SetProjectHash(hash string) {
	c.ProjectHash = strings.TrimSpace(hash)
}

// Cheapest returns the usable channels ordered cheapest first, dropping
// anything above maxPrice (0 means no limit), with no stock, or switched off.
//
// A listed price of zero is kept: the platform does report free channels, and
// dropping them would hide the cheapest possible rental. Only the sentinel that
// means "unpriced" — a channel with no price and no name, as produced by the
// unpinned fallback — is excluded.
func (c *ChannelCache) Cheapest(maxPrice float64) []Quote {
	out := make([]Quote, 0, len(c.Channels))
	for _, quote := range c.Channels {
		if quote.Price == 0 && quote.Name == "" {
			continue
		}
		if quote.Paused {
			continue
		}
		if maxPrice > 0 && quote.Price > maxPrice {
			continue
		}
		if quote.Stock <= 0 {
			continue
		}
		out = append(out, quote)
	}
	SortQuotes(out)
	return out
}

// MarkOutOfStock drops a channel's stock after the platform refused a number.
//
// The unpinned fallback carries no channel id, so there is nothing to mark; its
// refusal is reported to the caller instead.
func (c *ChannelCache) MarkOutOfStock(uid string) {
	if strings.TrimSpace(uid) == "" {
		return
	}
	for i := range c.Channels {
		if c.Channels[i].UID == uid {
			c.Channels[i].Stock = 0
		}
	}
}

// CheapestPrice returns the lowest known per-number price, or 0.
func (c *ChannelCache) CheapestPrice() float64 {
	for _, quote := range c.Channels {
		if quote.Stock > 0 {
			return quote.Price
		}
	}
	return 0
}

// SortQuotes orders channels cheapest first, then by the deepest stock, so a
// caller's first choice is always the cheapest usable channel.
func SortQuotes(quotes []Quote) {
	sort.SliceStable(quotes, func(i, j int) bool {
		if quotes[i].Price != quotes[j].Price {
			return quotes[i].Price < quotes[j].Price
		}
		return quotes[i].Stock > quotes[j].Stock
	})
}

// -- budget ------------------------------------------------------------------

// Budget is the spend ceiling. Both limits are checked before a number is
// rented, so the plugin can never spend past the operator's stated tolerance.
type Budget struct {
	// MaxTotalCNY caps the ledger's lifetime spend. 0 disables the cap.
	MaxTotalCNY float64
	// MaxPerNumberCNY skips channels priced above this. 0 disables the cap.
	MaxPerNumberCNY float64
}

// roundCNY rounds a CNY amount to the platform's three-decimal precision, so a
// balance difference (which carries float noise) becomes a clean ledger price.
func roundCNY(value float64) float64 {
	if value <= 0 {
		return 0
	}
	return math.Round(value*1000) / 1000
}

// Allows reports whether one more rental at price would stay inside the cap.
func (b Budget) Allows(price, spent float64) error {
	if b.MaxPerNumberCNY > 0 && price > b.MaxPerNumberCNY {
		return fmt.Errorf("%w: number costs %.3f, cap is %.3f", ErrBudget, price, b.MaxPerNumberCNY)
	}
	if b.MaxTotalCNY > 0 && spent+price > b.MaxTotalCNY {
		return fmt.Errorf("%w: %.3f spent of %.3f", ErrBudget, spent, b.MaxTotalCNY)
	}
	return nil
}

// -- persistence -------------------------------------------------------------

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

// LoadChannelCache reads the channel cache; a missing file yields an empty one.
func LoadChannelCache(path string) (*ChannelCache, error) {
	cache := NewChannelCache()
	if errLoad := loadJSON(path, cache); errLoad != nil {
		return NewChannelCache(), errLoad
	}
	if cache.Version == 0 {
		cache.Version = channelCacheVersion
	}
	return cache, nil
}

// Save writes the channel cache.
func (c *ChannelCache) Save(path string) error {
	if c.Version == 0 {
		c.Version = channelCacheVersion
	}
	return saveJSON(path, c)
}

// -- location ----------------------------------------------------------------

// Store owns the phone kind's on-disk state: the channel cache. The identity
// ledger is deliberately not here — it is cross-kind and owned by
// internal/supply, so a phone number and an email address land in the same file
// and the management surface can read them as one list.
//
// The cache lives beside the auth directory rather than inside it: the host
// watches that directory for credential files and treats every new *.json in it
// as one, so plugin state written there is misparsed.
type Store struct {
	Dir string
}

// NewStore resolves the state directory from an auth file path.
func NewStore(authPath, override string) Store {
	if dir := strings.TrimSpace(override); dir != "" {
		return Store{Dir: dir}
	}
	authDir := filepath.Dir(strings.TrimSpace(authPath))
	if parent := filepath.Dir(authDir); parent != "" && parent != "." && parent != authDir {
		return Store{Dir: filepath.Join(parent, ".cpa-plugin-loomy")}
	}
	if home, errHome := os.UserHomeDir(); errHome == nil {
		return Store{Dir: filepath.Join(home, ".cpa-plugin-loomy")}
	}
	return Store{Dir: ".cpa-plugin-loomy"}
}

// ChannelsPath is where the channel cache lives.
func (s Store) ChannelsPath() string { return filepath.Join(s.Dir, "loomy-sms-channels.json") }

// LedgerPath is where the cross-kind identity ledger lives.
func (s Store) LedgerPath() string { return supply.LedgerPath(s.Dir) }

// Load reads the channel cache, falling back to an empty one on a decode error.
func (s Store) Load() *ChannelCache {
	cache, errCache := LoadChannelCache(s.ChannelsPath())
	if errCache != nil {
		cache = NewChannelCache()
	}
	return cache
}

// Save writes the channel cache.
func (s Store) Save(cache *ChannelCache) error {
	if cache == nil {
		return nil
	}
	return cache.Save(s.ChannelsPath())
}

// SaveHealth writes the channel health store.
func (s Store) SaveHealth(health *ChannelHealth) error {
	if health == nil {
		return nil
	}
	return health.Save(s.HealthPath())
}

// -- service -----------------------------------------------------------------

// ChannelLister is implemented by providers that can enumerate this account's
// joined channels directly, so the cache can refresh itself rather than waiting
// for a human to paste a snapshot.
//
// It is separate from Provider because listing needs a browser session cookie
// that only some providers have, and a provider without one is still perfectly
// usable from its cached list.
type ChannelLister interface {
	Channels(ctx context.Context) ([]Quote, error)
}

// Joiner is implemented by providers whose channel catalogue is larger than the
// set this account has joined, and where joining is free.
//
// That is the shape of a rate-limited supplier marketplace: an account must join
// a channel before it can rent from it, joining costs nothing, and stock is
// spread thin across many cheap channels. A provider without a Joiner simply
// rents from whatever is already joined.
type Joiner interface {
	// FindProject resolves the handle the channel list needs. The project is
	// identified by its numeric id but looked up by name, because the platform
	// only searches by name.
	FindProject(ctx context.Context, projectID, keyword string) (ProjectRef, error)
	// AllChannels lists every channel of a project, joined or not, with the
	// supplier's list price.
	AllChannels(ctx context.Context, projectHash string) ([]Quote, error)
	// JoinChannels joins the given channels and returns the ones accepted.
	JoinChannels(ctx context.Context, uids []string) ([]string, error)
}

// ChannelStateSetter is implemented by providers whose joined set carries an
// on/off switch per channel.
//
// The platform rents from random channels among the joined *and enabled* set, so
// switching expensive channels off upstream is the only way to steer an
// automatic rental toward cheap ones. A provider without this interface still
// works: it simply cannot prune its joined set.
type ChannelStateSetter interface {
	// SetChannelOpen switches channels on or off. action is one of "pause",
	// "recover" or "del". It returns the uids the platform accepted.
	SetChannelOpen(ctx context.Context, action string, uids []string) ([]string, error)
}

// Service couples a platform to its channel cache and the ledger, and enforces
// the rent order: cheapest usable channel first.
type Service struct {
	Provider Provider
	Store    Store
	Budget   Budget
	// Strategy tunes how price and reliability combine into the rent order. A
	// zero value uses the documented defaults.
	Strategy Strategy
	// CoolDownSeconds is how long a just-failed channel is held out of the
	// preferred order. Zero disables the cool-down.
	CoolDownSeconds int64

	mu       sync.Mutex
	cache    *ChannelCache
	ledger   *supply.Ledger
	health   *ChannelHealth
	cooldown *CoolDown
	loaded   bool
	// shared is the cross-kind ledger owned by the supply registry. When set,
	// stateAll uses it instead of loading its own copy, so every kind reads and
	// writes one document.
	shared *supply.Ledger
}

// NewService builds a service over one provider.
func NewService(provider Provider, store Store, budget Budget) *Service {
	return &Service{
		Provider: provider,
		Store:    store,
		Budget:   budget,
		cooldown: NewCoolDown(),
	}
}

// state lazily loads the on-disk documents once.
func (s *Service) state() (*ChannelCache, *supply.Ledger) {
	cache, ledger, _ := s.stateAll()
	return cache, ledger
}

// stateAll lazily loads every on-disk document once, health included.
func (s *Service) stateAll() (*ChannelCache, *supply.Ledger, *ChannelHealth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		s.cache = s.Store.Load()
		if s.shared != nil {
			s.ledger = s.shared
		} else {
			ledger, errLedger := supply.LoadLedger(s.Store.LedgerPath())
			if errLedger != nil {
				ledger = supply.NewLedger()
			}
			s.ledger = ledger
		}
		health, errHealth := LoadChannelHealth(s.Store.HealthPath())
		if errHealth != nil {
			health = NewChannelHealth()
		}
		s.health = health
		if s.cooldown == nil {
			s.cooldown = NewCoolDown()
		}
		s.loaded = true
	}
	return s.cache, s.ledger, s.health
}

// Health returns the channel health store.
func (s *Service) Health() *ChannelHealth {
	_, _, health := s.stateAll()
	return health
}

// Channels returns the cached channel list.
func (s *Service) Channels() *ChannelCache {
	cache, _ := s.state()
	return cache
}

// Ledger returns the cross-kind identity ledger.
func (s *Service) Ledger() *supply.Ledger {
	_, ledger := s.state()
	return ledger
}

// -- phone ledger views ------------------------------------------------------
//
// The ledger itself is cross-kind (internal/supply). These helpers read and
// write the phone kind's records, keeping the phone-specific details (channel,
// carrier, region) in the record's Meta bag so the shared shape never grows a
// field for one kind.

// ledgerRecordMeta builds the Meta bag for one phone record.
func ledgerRecordMeta(number Number) map[string]any {
	meta := map[string]any{}
	if number.Code != "" {
		meta["channel"] = number.Code
	}
	if number.SID != "" {
		meta["sid"] = number.SID
	}
	if number.Carrier != "" {
		meta["carrier"] = number.Carrier
	}
	if number.Region != "" {
		meta["region"] = number.Region
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// ledgerPhone returns one number's ledger record.
func ledgerPhone(ledger *supply.Ledger, phone string) (supply.Record, bool) {
	return ledger.Get(supply.KindPhone, phone)
}

// ledgerChannel returns the channel a number was rented from, as recorded.
func ledgerChannel(ledger *supply.Ledger, phone string) string {
	record, ok := ledgerPhone(ledger, phone)
	if !ok {
		return ""
	}
	return record.MetaString("channel")
}

// ledgerMarkBlacklisted records a number we asked the platform to stop returning.
func ledgerMarkBlacklisted(ledger *supply.Ledger, phone string, now int64) {
	ledger.Mark(supply.KindPhone, phone, "blacklisted", "blacklisted", now)
}

// ReplaceChannels installs a freshly read channel list and persists it.
func (s *Service) ReplaceChannels(sid string, channels []Quote, now int64) error {
	cache, _ := s.state()
	s.mu.Lock()
	cache.Replace(sid, channels, now)
	errSave := s.Store.Save(cache)
	s.mu.Unlock()
	return errSave
}

// RefreshChannels re-reads this account's joined channels from the platform.
//
// The platform's web surface reports every project the account has joined, so
// the list is narrowed to the requested project by its id prefix. A provider
// without a channel lister, or one whose session cookie has expired, reports an
// error and the caller keeps its cached list.
func (s *Service) RefreshChannels(ctx context.Context, sid string) (int, error) {
	lister, ok := s.Provider.(ChannelLister)
	if !ok {
		return 0, fmt.Errorf("sms: provider %s cannot list channels", s.Provider.ID())
	}
	all, errList := lister.Channels(ctx)
	if errList != nil {
		return 0, errList
	}
	prefix := strings.TrimSpace(sid) + "-"
	owned := make([]Quote, 0, len(all))
	for _, quote := range all {
		if strings.TrimSpace(sid) == "" || strings.HasPrefix(quote.UID, prefix) {
			owned = append(owned, quote)
		}
	}
	if errSave := s.ReplaceChannels(sid, owned, nowUnix()); errSave != nil {
		return len(owned), errSave
	}
	return len(owned), nil
}

// EnsureChannelsAndRefresh rebuilds the cache the way a caller asked for it:
// join-first when asked, otherwise a plain re-read of the joined set.
func (s *Service) EnsureChannelsAndRefresh(ctx context.Context, project Project, join bool) (int, error) {
	if join {
		return s.EnsureChannels(ctx, project.SID, project.Name)
	}
	return s.RefreshChannels(ctx, project.SID)
}

// ChannelsUpdatedAt reports when the cached channel list was last refreshed.
func (s *Service) ChannelsUpdatedAt() int64 {
	return s.Channels().UpdatedAt
}

// projectKeyword reads the project name off a cached channel label, which is the
// only place it can be found without the operator naming the project: the
// platform searches projects by name, and a joined channel's label carries it
// ("[21614]讯飞").
func projectKeyword(cache *ChannelCache) string {
	if cache == nil {
		return ""
	}
	for _, quote := range cache.Channels {
		if name := ProjectKeyword(quote.Name); name != "" {
			return name
		}
	}
	return ""
}

// Acquire rents the cheapest affordable number for a project.
//
// When the channel cache is populated it walks the channels in price order and
// stops at the first one that answers with a number; a refused channel is marked
// out of stock so the next call skips it, and an error that would fail every
// channel (bad token, empty balance, budget ceiling) aborts immediately.
//
// The channel list is only an optimisation. The documented rent call takes just
// the project id — the channel is optional — and the platform then picks from
// the channels this account already holds. So when nothing is cached, renting
// falls back to that unpinned call rather than refusing: 取号 must work with the
// API credential alone, without the web session that only lists channels.
//
// A cold cache still tries one auto-join first, but only because joining is free
// and narrows the platform's choice to channels at or below the ceiling; a
// missing web session is not an error.
func (s *Service) Acquire(ctx context.Context, project Project) (Number, supply.Record, error) {
	cache, ledger, health := s.stateAll()

	s.mu.Lock()
	candidates := cache.Cheapest(s.Budget.MaxPerNumberCNY)
	spent := ledger.Spent()
	cooling := s.cooldown.Active(nowUnix())
	s.mu.Unlock()

	if project.Code == "" && len(candidates) == 0 {
		if _, errJoin := s.EnsureChannels(ctx, project.SID, project.Name); errJoin != nil {
			hostLogSafe("loomy sms: auto-join skipped: " + errJoin.Error())
		}
		s.mu.Lock()
		candidates = cache.Cheapest(s.Budget.MaxPerNumberCNY)
		cooling = s.cooldown.Active(nowUnix())
		s.mu.Unlock()
	}
	if project.Code != "" {
		candidates = []Quote{{UID: project.Code, Price: 0, Stock: 1}}
	}
	if len(candidates) == 0 {
		// No priced channels to choose from: let the platform pick a channel for
		// the project. The price is then whatever it charges, so the budget is
		// enforced by the cumulative ceiling instead of the per-number cap.
		hostLogSafe("loomy sms: no cached channel prices; renting unpinned, per-number cap cannot be pre-checked")
		candidates = []Quote{{UID: "", Price: 0, Stock: 1}}
	}

	// Order by price combined with each channel's track record, so a cheap
	// channel that keeps timing out yields to one that actually delivers. A
	// just-failed channel is held back until the rest have been considered.
	candidates = s.Strategy.Rank(candidates, health, cooling)

	var lastErr error
	for _, quote := range candidates {
		if errBudget := s.Budget.Allows(quote.Price, spent); errBudget != nil {
			return Number{}, supply.Record{}, errBudget
		}
		// An unpinned rental has no list price, so the platform's own charge is
		// unknown until it happens. Read the balance first and price the rental
		// by the difference, so the ledger and the cumulative ceiling stay
		// truthful on the fallback path too.
		var before float64
		var errBefore error
		if quote.Price <= 0 {
			before, errBefore = s.Provider.Balance(ctx)
		}
		number, errRent := s.Provider.Rent(ctx, project, quote.UID)
		if errRent == nil {
			price := quote.Price
			if price <= 0 && errBefore == nil {
				if after, errAfter := s.Provider.Balance(ctx); errAfter == nil {
					price = roundCNY(before - after)
				}
			}
			if price <= 0 {
				hostLogSafe(fmt.Sprintf("loomy sms: rented %s but its price is unknown; not counted against the spend ceiling", number.Phone))
			} else if s.Budget.MaxPerNumberCNY > 0 && price > s.Budget.MaxPerNumberCNY {
				// The number is already rented; the ceiling cannot refuse it
				// after the fact. Record it and make the overrun visible.
				hostLogSafe(fmt.Sprintf("loomy sms: unpinned rental %s cost %.3f, above the %.3f per-number ceiling", number.Phone, price, s.Budget.MaxPerNumberCNY))
			}
			// Remember which channel this rental came from, both on the number
			// and in the health store, so the wait for a message can be scored
			// against the channel that actually produced it.
			if number.Code == "" {
				number.Code = quote.UID
			}
			s.recordAttempt(number.Code, price)
			return s.commitRental(number, price, project)
		}
		lastErr = errRent
		if IsFatal(errRent) {
			return Number{}, supply.Record{}, errRent
		}
		// The channel refused: remember it so the next call does not retry it.
		s.mu.Lock()
		cache.MarkOutOfStock(quote.UID)
		s.mu.Unlock()
	}
	if lastErr == nil {
		lastErr = ErrNoStock
	}
	return Number{}, supply.Record{}, lastErr
}

// recordAttempt marks that a number was rented from a channel, so the later
// delivery or timeout can be counted against the right one.
func (s *Service) recordAttempt(uid string, price float64) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return
	}
	_, _, health := s.stateAll()
	s.mu.Lock()
	stat := health.get(uid)
	stat.Attempts++
	if price > 0 {
		stat.Price = price
	}
	errSave := s.Store.SaveHealth(health)
	s.mu.Unlock()
	if errSave != nil {
		hostLogSafe("loomy sms: channel health write failed: " + errSave.Error())
	}
}

// EnsureChannels makes sure the cache holds every affordable channel of a
// project, joining any that the account does not yet have, and rebuilds the
// cache from the account's joined list so each channel's on/off state is known.
//
// The platform only searches projects by name, so the keyword is needed to find
// the project's channel list. It is taken from the configured value when set,
// and otherwise read off a channel already in the cache, whose label carries the
// project name ("[21614]讯飞").
//
// It joins only channels at or below the per-number ceiling, so a marketplace
// with thousands of channels cannot quietly enrol an account into expensive
// ones. It is best-effort: a caller with a usable cache keeps working even when
// the web session is gone.
func (s *Service) EnsureChannels(ctx context.Context, sid, keyword string) (int, error) {
	joiner, ok := s.Provider.(Joiner)
	if !ok {
		return 0, fmt.Errorf("sms: provider %s cannot join channels", s.Provider.ID())
	}

	cache, _ := s.state()
	hash := strings.TrimSpace(cache.ProjectHash)
	if strings.TrimSpace(keyword) == "" {
		keyword = projectKeyword(cache)
	}
	if hash == "" || (strings.TrimSpace(keyword) == "" && len(cache.Channels) == 0) {
		// On a cold cache the project name is not known yet, and the platform
		// only searches by name. Read what is already joined first: its labels
		// carry the project name.
		if strings.TrimSpace(keyword) == "" {
			if _, errRefresh := s.RefreshChannels(ctx, sid); errRefresh == nil {
				keyword = projectKeyword(cache)
				if hash == "" {
					hash = strings.TrimSpace(cache.ProjectHash)
				}
			}
		}
		if hash == "" {
			ref, errFind := joiner.FindProject(ctx, sid, keyword)
			if errFind != nil {
				// Fall back to a plain re-read of what is already joined, so a
				// project that cannot be resolved still refreshes.
				if count, errRefresh := s.RefreshChannels(ctx, sid); errRefresh == nil {
					return count, nil
				}
				return 0, errFind
			}
			hash = ref.Hash
		}
	}

	all, errList := joiner.AllChannels(ctx, hash)
	if errList != nil {
		return 0, errList
	}

	joined, errJoined := s.joinedUIDs(ctx)
	if errJoined != nil {
		joined = map[string]bool{}
	}

	prefix := strings.TrimSpace(sid) + "-"
	var toJoin []string
	for _, quote := range all {
		if !strings.HasPrefix(quote.UID, prefix) {
			continue
		}
		if quote.Price <= 0 || (s.Budget.MaxPerNumberCNY > 0 && quote.Price > s.Budget.MaxPerNumberCNY) {
			continue
		}
		if !joined[quote.UID] {
			toJoin = append(toJoin, quote.UID)
		}
	}

	if len(toJoin) > 0 {
		if _, errJoin := joiner.JoinChannels(ctx, toJoin); errJoin != nil {
			return 0, errJoin
		}
		hostLogSafe(fmt.Sprintf("loomy sms: auto-joined %d channels at or below %.3f CNY", len(toJoin), s.Budget.MaxPerNumberCNY))
	}

	// Rebuild the cache from the account's authoritative joined list, not from
	// the marketplace catalogue. The joined list (type=3) carries each channel's
	// price, stock and on/off state; the marketplace list (type=8) has no state,
	// so building from it would lose which channels are paused and make the
	// guardrail blind on the next pass.
	kept, errJoinedList := s.joinedQuotesFor(ctx, sid)
	if errJoinedList != nil {
		return 0, errJoinedList
	}
	s.mu.Lock()
	cache.Replace(sid, kept, nowUnix())
	cache.SetProjectHash(hash)
	errSave := s.Store.Save(cache)
	s.mu.Unlock()
	return len(kept), errSave
}

// joinedQuotesFor reads the account's joined channels and narrows them to one
// project. It is the stateful counterpart of the marketplace list: the same
// channels but with each one's price, stock and on/off state as the platform
// reports them.
func (s *Service) joinedQuotesFor(ctx context.Context, sid string) ([]Quote, error) {
	lister, ok := s.Provider.(ChannelLister)
	if !ok {
		return nil, fmt.Errorf("sms: provider %s cannot list channels", s.Provider.ID())
	}
	all, errList := lister.Channels(ctx)
	if errList != nil {
		return nil, errList
	}
	prefix := strings.TrimSpace(sid) + "-"
	kept := make([]Quote, 0, len(all))
	for _, quote := range all {
		if strings.TrimSpace(sid) == "" || strings.HasPrefix(quote.UID, prefix) {
			kept = append(kept, quote)
		}
	}
	SortQuotes(kept)
	return kept, nil
}

// SetChannelOpen pauses or recovers the named channels on the platform.
//
// It is the per-channel form of GuardChannels: the operator narrows the
// platform's picker by hand. The calls are free and reversible.
func (s *Service) SetChannelOpen(ctx context.Context, action string, uids []string) ([]string, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	setter, ok := s.Provider.(ChannelStateSetter)
	if !ok {
		return nil, fmt.Errorf("sms: provider %s cannot switch channels", s.Provider.ID())
	}
	return setter.SetChannelOpen(ctx, action, uids)
}

// LedgerChannels returns the set of channels that hold a number this account has
// used. It is the guard for pausing a channel: the platform refuses to re-issue
// a number whose channel is paused, so pausing one of these would strand a
// re-authentication (design 23 §3.4).
func (s *Service) LedgerChannels() map[string]bool {
	_, ledger := s.state()
	out := map[string]bool{}
	if ledger == nil {
		return out
	}
	for _, record := range ledger.All() {
		if record.Kind != supply.KindPhone {
			continue
		}
		if channel := record.MetaString("channel"); channel != "" {
			out[channel] = true
		}
	}
	return out
}

// PauseThreshold is the run of consecutive failures after which a channel is
// taken out of the platform's picker.
func (s *Service) PauseThreshold() int {
	return s.Strategy.withDefaults().PauseAfterConsecutiveFails
}

// ShouldSuspend reports whether a channel has failed enough times in a row to be
// taken out of the platform's picker.
func (s *Service) ShouldSuspend(uid string) bool {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return false
	}
	_, _, health := s.stateAll()
	s.mu.Lock()
	defer s.mu.Unlock()
	stat, ok := health.Stat(uid)
	return ok && stat.ConsecutiveFails >= s.PauseThreshold()
}

// RecordDelivery notes that a channel produced a message. It clears the
// channel's failure run, which is what keeps a channel that had a bad spell from
// being punished forever.
func (s *Service) RecordDelivery(uid string, price float64) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return
	}
	_, _, health := s.stateAll()
	s.mu.Lock()
	health.Record(uid, OutcomeDelivered, price, nowUnix())
	errSave := s.Store.SaveHealth(health)
	s.mu.Unlock()
	if errSave != nil {
		hostLogSafe("loomy sms: channel health write failed: " + errSave.Error())
	}
}

// SuspendUnreliable pauses a channel that has failed too often, unless doing so
// would strand a number already in the ledger.
//
// It returns whether the channel was paused. A channel holding a ledger number
// is protected: the pause is skipped and the channel is left to the score, which
// already demotes it. That is the R-PROTECT rule from design 23 §3.4 — the
// protection is deliberate and one-sided, because a stranded number costs a full
// re-registration while a demoted channel only costs a slightly worse pick.
func (s *Service) SuspendUnreliable(ctx context.Context, uid string) (bool, error) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return false, nil
	}
	if s.LedgerChannels()[uid] {
		hostLogSafe(fmt.Sprintf("loomy sms: %s is unreliable but holds a ledger number; demoting only, not pausing", uid))
		return false, nil
	}
	if _, errPause := s.SetChannelOpen(ctx, "pause", []string{uid}); errPause != nil {
		return false, errPause
	}
	_, _, health := s.stateAll()
	s.mu.Lock()
	health.get(uid).PausedByUs = true
	_ = s.Store.SaveHealth(health)
	s.mu.Unlock()
	hostLogSafe(fmt.Sprintf("loomy sms: paused unreliable channel %s", uid))
	return true, nil
}

// GuardChannels narrows the platform's enabled channels to the cheap, in-stock
// ones, so a blind rental can no longer land on an expensive one.
//
// This cannot be done locally: the platform's own picker decides which channel a
// blind rental lands on, so tuning the local cache only narrows what this plugin
// knows, not what the platform picks. Narrowing the enabled set upstream does:
// after a pass, even an unpinned getPhone can only land on an affordable channel
// with stock.
//
// One channel is never switched off: the cheapest in-stock channel at or below
// the ceiling stays enabled, so a pass can never leave the account with nothing
// to rent from. The calls are free and reversible. Without a ChannelStateSetter
// this is a no-op.
//
// A channel this plugin paused for unreliability is left paused even when it is
// affordable and in stock: recovering it here would silently undo that decision
// on the next pass. Such a channel is only recovered once its record clears the
// failure run (or an operator does it by hand), so the two policies cannot fight
// over the same channel.
func (s *Service) GuardChannels(ctx context.Context, sid string) (int, error) {
	setter, ok := s.Provider.(ChannelStateSetter)
	if !ok {
		return 0, fmt.Errorf("sms: provider %s cannot switch channels", s.Provider.ID())
	}
	// Load the on-disk documents up front: a guardrail pass can be the first
	// call on a fresh service (the panel route builds one and calls this
	// directly), and the cache must not be nil when it is rewritten below.
	_, _, health := s.stateAll()
	joined, errList := s.joinedQuotesFor(ctx, sid)
	if errList != nil {
		return 0, errList
	}
	ceiling := s.Budget.MaxPerNumberCNY
	reliabilityPause := map[string]bool{}
	s.mu.Lock()
	for uid, stat := range health.Stats {
		if stat == nil || !stat.PausedByUs {
			continue
		}
		// A channel we paused for unreliability is released back to the normal
		// rules once its failure run has cleared — a delivery since the pause
		// proves it works again. Until then it stays out of the platform's
		// picker, so the two policies never fight over it.
		if stat.ConsecutiveFails == 0 {
			stat.PausedByUs = false
			continue
		}
		reliabilityPause[uid] = true
	}
	s.mu.Unlock()

	// Choose one channel to keep enabled no matter what, so a pass can never
	// leave the account with nothing to rent from. Prefer the cheapest in-stock
	// channel at or below the ceiling; if every channel is over the ceiling,
	// keep the cheapest in-stock one anyway, so the account still works and the
	// overrun is visible in the ledger rather than silently making it unusable.
	// A channel we paused for unreliability is preferred for this slot as a last
	// resort, so its pause never leaves the account with nothing.
	keep := ""
	best := 0.0
	for _, quote := range joined {
		if reliabilityPause[quote.UID] {
			continue
		}
		if quote.Price <= 0 || (ceiling > 0 && quote.Price > ceiling) || quote.Stock <= 0 {
			continue
		}
		if keep == "" || quote.Price < best {
			keep, best = quote.UID, quote.Price
		}
	}
	if keep == "" {
		for _, quote := range joined {
			if quote.Stock <= 0 {
				continue
			}
			if keep == "" || quote.Price < best {
				keep, best = quote.UID, quote.Price
			}
		}
	}

	var toPause, toRecover []string
	for _, quote := range joined {
		affordable := quote.Price > 0 && (ceiling <= 0 || quote.Price <= ceiling)
		usable := affordable && quote.Stock > 0
		switch {
		case quote.UID == keep:
			if quote.Paused {
				toRecover = append(toRecover, quote.UID)
			}
		case reliabilityPause[quote.UID]:
			// Left to the reliability policy: keep it paused, and never recover
			// it here. If the platform already shows it enabled, pause it so the
			// decision actually holds.
			if !quote.Paused {
				toPause = append(toPause, quote.UID)
			}
		case usable && quote.Paused:
			toRecover = append(toRecover, quote.UID)
		case !usable && !quote.Paused:
			toPause = append(toPause, quote.UID)
		}
	}

	if len(toPause) > 0 {
		if _, errPause := setter.SetChannelOpen(ctx, "pause", toPause); errPause != nil {
			return 0, errPause
		}
		hostLogSafe(fmt.Sprintf("loomy sms: paused %d channels above %.3f CNY or out of stock", len(toPause), ceiling))
	}
	if len(toRecover) > 0 {
		if _, errRecover := setter.SetChannelOpen(ctx, "recover", toRecover); errRecover != nil {
			return 0, errRecover
		}
		hostLogSafe(fmt.Sprintf("loomy sms: recovered %d affordable in-stock channels", len(toRecover)))
	}

	// Rebuild the cache from the joined list with the new states applied, so a
	// rental in this same pass already sees the narrowed set — and so the cache
	// is authoritative even when it started empty.
	updated := make([]Quote, 0, len(joined))
	pausedSet := map[string]bool{}
	for _, uid := range toPause {
		pausedSet[uid] = true
	}
	recoveredSet := map[string]bool{}
	for _, uid := range toRecover {
		recoveredSet[uid] = true
	}
	for _, quote := range joined {
		switch {
		case pausedSet[quote.UID]:
			quote.Paused = true
		case recoveredSet[quote.UID]:
			quote.Paused = false
		}
		updated = append(updated, quote)
	}
	s.mu.Lock()
	s.cache.Replace(sid, updated, nowUnix())
	errSave := s.Store.Save(s.cache)
	if errHealth := s.Store.SaveHealth(health); errHealth != nil && errSave == nil {
		errSave = errHealth
	}
	s.mu.Unlock()
	return len(toPause) + len(toRecover), errSave
}

// joinedUIDs reads the set of channels this account has joined.
func (s *Service) joinedUIDs(ctx context.Context) (map[string]bool, error) {
	lister, ok := s.Provider.(ChannelLister)
	if !ok {
		return nil, fmt.Errorf("sms: provider %s cannot list channels", s.Provider.ID())
	}
	current, errList := lister.Channels(ctx)
	if errList != nil {
		return nil, errList
	}
	out := make(map[string]bool, len(current))
	for _, quote := range current {
		out[quote.UID] = true
	}
	return out, nil
}

// Reacquire re-occupies one exact number, which is how a re-authentication gets
// back onto the number an account registered with.
func (s *Service) Reacquire(ctx context.Context, project Project, phone string) (Number, supply.Record, error) {
	_, ledger := s.state()

	price := 0.0
	if record, ok := ledgerPhone(ledger, phone); ok && record.Price > 0 {
		price = record.Price
	}
	if errBudget := s.Budget.Allows(price, ledger.Spent()); errBudget != nil {
		return Number{}, supply.Record{}, errBudget
	}
	number, errRent := s.Provider.AcquirePhone(ctx, project, phone)
	if errRent != nil {
		return Number{}, supply.Record{}, errRent
	}
	return s.commitRental(number, price, project)
}

// commitRental folds one successful rental into the ledger and persists it.
func (s *Service) commitRental(number Number, price float64, project Project) (Number, supply.Record, error) {
	if number.SID == "" {
		number.SID = project.SID
	}
	now := time.Now().Unix()
	_, ledger := s.state()
	s.mu.Lock()
	record := ledger.Record(supply.KindPhone, number.Phone, s.Provider.ID(), price, ledgerRecordMeta(number), now)
	errSave := ledger.Save(s.Store.LedgerPath())
	s.mu.Unlock()
	if errSave != nil {
		// The number is already rented; a failed write must not lose it for the
		// caller, so the error is reported alongside the record.
		return number, record, fmt.Errorf("sms: rented %s but ledger write failed: %w", number.Phone, errSave)
	}
	return number, record, nil
}

// Read reads a number's inbox once.
func (s *Service) Read(ctx context.Context, project Project, phone string) (Message, error) {
	return s.Provider.Read(ctx, project, phone)
}

// Release returns a number to the platform's pool.
func (s *Service) Release(ctx context.Context, project Project, phone string) error {
	return s.Provider.Release(ctx, project, phone)
}

// ReleaseUnused returns a number to the platform's pool and reverses the spend
// recorded for it.
//
// The caller reaches this only when the rental produced nothing usable — the
// message was never sent, or none arrived before the deadline — and the platform
// credits such a rental back. Keeping its price in the ledger would overstate
// the running total, so the refund is folded in here, next to the release that
// caused it.
//
// The outcome says which of the two it was, because they mean opposite things to
// the channel: OutcomeTimeout is the channel's own failure and is counted against
// it, while OutcomeReleased means no verdict was reached and must not be. The
// channel is taken from the ledger record for the number.
func (s *Service) ReleaseUnused(ctx context.Context, project Project, phone string, price float64, outcome ChannelOutcome) error {
	errRelease := s.Provider.Release(ctx, project, phone)
	if errRelease != nil {
		// The number was not returned, so the platform keeps the charge; nothing
		// to credit back. The channel also cannot be blamed, since the rental
		// was never concluded.
		return errRelease
	}
	_, ledger, health := s.stateAll()
	s.mu.Lock()
	channel := ledgerChannel(ledger, phone)
	refunded := ledger.Refund(supply.KindPhone, phone, price, nowUnix())
	ledger.Mark(supply.KindPhone, phone, outcome.String(), "released", nowUnix())
	if channel != "" {
		health.Record(channel, outcome, price, nowUnix())
		if outcome == OutcomeTimeout {
			s.cooldown.Mark(channel, nowUnix(), s.CoolDownSeconds)
		}
	}
	errSave := ledger.Save(s.Store.LedgerPath())
	if channel != "" {
		if errHealth := s.Store.SaveHealth(health); errHealth != nil && errSave == nil {
			errSave = errHealth
		}
	}
	s.mu.Unlock()
	if refunded {
		hostLogSafe(fmt.Sprintf("loomy sms: released unused %s and credited %.3f CNY back", phone, price))
	}
	return errSave
}

// Blacklist stops the platform from handing this number back.
func (s *Service) Blacklist(ctx context.Context, project Project, phone string) error {
	_, ledger := s.state()
	errBlacklist := s.Provider.Blacklist(ctx, project, phone)
	if errBlacklist != nil {
		return errBlacklist
	}
	s.mu.Lock()
	ledgerMarkBlacklisted(ledger, phone, time.Now().Unix())
	errSave := ledger.Save(s.Store.LedgerPath())
	s.mu.Unlock()
	return errSave
}

// LinkAccount records which service account a number registered, and on which
// platform. The platform is the phone kind's target: the account it registered
// was a Loomy account.
func (s *Service) LinkAccount(phone, target, account, authIndex string) error {
	_, ledger := s.state()
	s.mu.Lock()
	ledger.Link(supply.KindPhone, phone, target, account, authIndex, time.Now().Unix())
	errSave := ledger.Save(s.Store.LedgerPath())
	s.mu.Unlock()
	return errSave
}

// Balance reports the platform's remaining balance.
func (s *Service) Balance(ctx context.Context) (float64, error) {
	return s.Provider.Balance(ctx)
}
