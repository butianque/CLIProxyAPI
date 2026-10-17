package email

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// Defaults for the email kind. They are deliberately generous about the search
// window and stingy about how much is read: a verification mail is minutes old,
// and the expensive part is fetching bodies.
const (
	DefaultPollWindow  = 72 * time.Hour
	DefaultMaxMessages = 20
)

// Config assembles the email provider.
type Config struct {
	// ChannelsPath is the channel document the mailboxes are read from. The
	// document is re-read per call, so an operator's edit takes effect without a
	// restart.
	ChannelsPath string

	// Pool records which mailbox handed out which address. It is optional: an
	// IMAP source rents nothing, so a nil pool only means the ledger stays empty.
	Pool *supply.Pool

	// PoolPath is where the shared ledger is persisted. It is required whenever
	// Pool is set, because the pool is one document shared by every kind and a
	// provider that did not persist its own writes would lose them.
	PoolPath string

	// PollWindow bounds how far back a read looks.
	PollWindow time.Duration

	// MaxMessages caps how many messages one folder contributes to a read.
	MaxMessages int

	// Dial opens a mailbox session. Tests replace it; nil means real IMAP.
	Dial func(ctx context.Context, target Target) (Session, error)

	// Credential resolves a secret-store entry name to its value. Tests replace
	// it; nil means the host secret store.
	Credential func(name string) (string, error)
}

// ProviderImpl is the email supply provider.
type ProviderImpl struct {
	cfg        Config
	dial       func(ctx context.Context, target Target) (Session, error)
	credential func(name string) (string, error)
}

// New builds the email provider.
func New(cfg Config) (*ProviderImpl, error) {
	if strings.TrimSpace(cfg.ChannelsPath) == "" {
		return nil, errors.New("email: no channel document to read mailboxes from")
	}
	if cfg.PollWindow <= 0 {
		cfg.PollWindow = DefaultPollWindow
	}
	if cfg.MaxMessages <= 0 {
		cfg.MaxMessages = DefaultMaxMessages
	}
	provider := &ProviderImpl{cfg: cfg, dial: cfg.Dial, credential: cfg.Credential}
	if provider.dial == nil {
		provider.dial = dialSession
	}
	if provider.credential == nil {
		provider.credential = readCredential
	}
	return provider, nil
}

// Kind reports the kind this provider serves.
func (p *ProviderImpl) Kind() supply.Kind { return supply.KindEmail }

// Status reports whether any mailbox is configured.
//
// It stays local: a status call happens on every panel load and at startup, and
// reaching a mail server to answer "is this configured" would make both depend
// on the network. Locked reports the host secret store, because a locked store
// means the passwords cannot be read — that is "unknown", not "absent".
func (p *ProviderImpl) Status(ctx context.Context) (supply.Status, error) {
	targets, errTargets := p.targets()
	if errTargets != nil {
		return supply.Status{}, errTargets
	}
	store := secretstore.Default()
	locked := store == nil || !store.Unlocked()
	return supply.Status{
		Enabled: len(targets) > 0,
		Kinds:   []supply.Kind{supply.KindEmail},
		Locked:  locked,
	}, nil
}

// Grab hands out an address that this mailbox can receive for.
//
// For a catch-all domain that is a fresh local part, so the address space is
// infinite; for a personal mailbox it is the mailbox itself, because that is
// the only address it owns.
func (p *ProviderImpl) Grab(ctx context.Context, opts supply.GrabOptions) (supply.Identity, error) {
	targets, errTargets := p.targets()
	if errTargets != nil {
		return supply.Identity{}, errTargets
	}
	if len(targets) == 0 {
		return supply.Identity{}, supply.ErrUnavailable
	}
	if wanted := strings.ToLower(strings.TrimSpace(opts.Address)); wanted != "" {
		for _, target := range targets {
			if target.Covers(wanted) {
				p.recordGrab(target, wanted)
				return supply.Identity{
					Kind:    supply.KindEmail,
					Address: wanted,
					Region:  target.Domain,
					Code:    target.ChannelID,
				}, nil
			}
		}
		// An address no configured mailbox receives is not one this service
		// handed out, and the caller's right answer is a manual path.
		return supply.Identity{}, supply.ErrUnknownIdentity
	}
	target, ok := pickTarget(targets, strings.TrimSpace(opts.UID))
	if !ok {
		return supply.Identity{}, supply.ErrUnavailable
	}
	if target.Usage == "self-domain" && target.Domain != "" {
		local, errRandom := randomLocalPart()
		if errRandom != nil {
			return supply.Identity{}, errRandom
		}
		address := local + "@" + strings.ToLower(target.Domain)
		p.recordGrab(target, address)
		return supply.Identity{
			Kind:    supply.KindEmail,
			Address: address,
			Region:  target.Domain,
			Code:    target.ChannelID,
		}, nil
	}
	address := strings.ToLower(strings.TrimSpace(target.Account))
	p.recordGrab(target, address)
	return supply.Identity{
		Kind:    supply.KindEmail,
		Address: address,
		Region:  target.Domain,
		Code:    target.ChannelID,
	}, nil
}

// recordGrab notes a handed-out address in the pool, so the ledger knows the
// identity exists before anything is registered with it.
//
// The address is noted without a target first, which is what gives a new record
// the channel that produced it, and then booked as a handout, which is what
// counts the use and keeps the domain. A nil pool is the not-configured state
// and is skipped.
//
// A failed write is deliberately not returned: the address has already been
// handed out and costs nothing, so a ledger that cannot be written must not turn
// a usable identity into an error. The next successful write rewrites the whole
// document.
func (p *ProviderImpl) recordGrab(target Target, address string) {
	if p.cfg.Pool == nil {
		return
	}
	now := time.Now().Unix()
	channelID := strings.TrimSpace(target.ChannelID)
	p.cfg.Pool.Register(supply.KindEmail, address, channelID, "", "", "", "", now)
	meta := map[string]any{}
	if domain := strings.TrimSpace(target.Domain); domain != "" {
		meta["domain"] = domain
	}
	p.cfg.Pool.Record(supply.KindEmail, address, channelID, 0, meta, now)
	_ = p.savePool()
}

// Read looks for the newest mail addressed to address.
//
// "No mail yet" is the ordinary answer while a verification mail is in flight,
// so it is reported as Ready=false rather than as an error.
func (p *ProviderImpl) Read(ctx context.Context, purpose, address string) (supply.Message, error) {
	wanted := strings.ToLower(strings.TrimSpace(address))
	if wanted == "" {
		return supply.Message{}, errors.New("email: a read needs an address to look for")
	}
	targets, errTargets := p.targets()
	if errTargets != nil {
		return supply.Message{}, errTargets
	}
	if len(targets) == 0 {
		return supply.Message{}, supply.ErrUnavailable
	}
	var firstErr error
	scanned := false
	for _, target := range orderTargets(targets, wanted) {
		mails, errScan := p.scan(ctx, target, wanted, 1)
		if errScan != nil {
			if firstErr == nil {
				firstErr = errScan
			}
			continue
		}
		scanned = true
		if len(mails) == 0 {
			continue
		}
		newest := mails[0]
		return supply.Message{
			Ready:   true,
			Code:    newest.Code,
			Text:    newest.Text,
			Subject: newest.Subject,
			From:    newest.From,
		}, nil
	}
	if !scanned && firstErr != nil {
		return supply.Message{}, firstErr
	}
	return supply.Message{Ready: false}, nil
}

// Link records which account an address registered, so the ledger can answer
// "which address is behind this credential" later.
//
// The channel is left out on purpose: the record already carries the one that
// handed the address out, and a registration must not reassign it.
func (p *ProviderImpl) Link(ctx context.Context, address, target, account, authIndex string) error {
	if p.cfg.Pool == nil {
		return nil
	}
	p.cfg.Pool.Register(supply.KindEmail, address, "", target, account, authIndex, "registered", time.Now().Unix())
	return p.savePool()
}

// Release is a no-op for email: a catch-all address is not rented, so there is
// nothing to give back.
func (p *ProviderImpl) Release(ctx context.Context, address, outcome string) error {
	return nil
}

// InboxReading is one inbox read: the messages, and what each mailbox
// contributed to it.
//
// The per-mailbox part exists because a channel row has to say "three messages,
// newest at 12:04" or "this mailbox could not be read, and here is why".
// Counting the messages instead would be wrong: the list is trimmed to a global
// limit, so a busy mailbox crowds out a quiet one and the quiet one would read
// as empty.
type InboxReading struct {
	Mails     []Mail
	Mailboxes []InboxMailbox
	// Window is how far back the read looked, so a caller can say "in the last
	// three days" instead of implying "everything ever received".
	Window time.Duration
}

// InboxMailbox is one configured mailbox's contribution to a read.
type InboxMailbox struct {
	ChannelID string
	Label     string
	Account   string
	Domain    string
	// Count is how many messages in the window were addressed to the requested
	// address (every message when no address was given).
	Count int
	// Latest is the newest of them, or nil when there were none.
	Latest *Mail
	// Err is why this mailbox could not be read; empty when it could.
	Err string
}

// Inbox returns recent mail across the configured mailboxes, newest first.
//
// This is the management surface's read: the operator wants to see what
// actually arrived, including mail that states no code. An empty address means
// "everything", which is what an inbox view shows before a search.
func (p *ProviderImpl) Inbox(ctx context.Context, address string, limit int) (InboxReading, error) {
	wanted := strings.ToLower(strings.TrimSpace(address))
	if limit <= 0 {
		limit = p.cfg.MaxMessages
	}
	targets, errTargets := p.targets()
	if errTargets != nil {
		return InboxReading{}, errTargets
	}
	if len(targets) == 0 {
		return InboxReading{}, supply.ErrUnavailable
	}
	reading := InboxReading{
		Window:    p.cfg.PollWindow,
		Mailboxes: make([]InboxMailbox, 0, len(targets)),
	}
	collected := make([]Mail, 0, limit)
	var firstErr error
	scanned := false
	for _, target := range orderTargets(targets, wanted) {
		summary := InboxMailbox{
			ChannelID: target.ChannelID,
			Label:     target.Label,
			Account:   target.Account,
			Domain:    target.Domain,
		}
		mails, errScan := p.scan(ctx, target, wanted, limit)
		if errScan != nil {
			// One mailbox failing is not the whole read failing: another may
			// answer. But the failure is reported per mailbox, because a channel
			// row that says "no mail" while its mailbox was never opened is the
			// kind of answer that sends the operator looking in the wrong place.
			summary.Err = errScan.Error()
			if firstErr == nil {
				firstErr = errScan
			}
			reading.Mailboxes = append(reading.Mailboxes, summary)
			continue
		}
		scanned = true
		summary.Count = len(mails)
		if len(mails) > 0 {
			latest := mails[0]
			summary.Latest = &latest
		}
		reading.Mailboxes = append(reading.Mailboxes, summary)
		collected = append(collected, mails...)
	}
	if !scanned && firstErr != nil {
		return InboxReading{}, firstErr
	}
	sortNewestFirst(collected)
	if len(collected) > limit {
		collected = collected[:limit]
	}
	reading.Mails = collected
	return reading, nil
}

// TargetViews reports the configured mailboxes without any credential value.
func (p *ProviderImpl) TargetViews() ([]TargetView, error) {
	targets, errTargets := p.targets()
	if errTargets != nil {
		return nil, errTargets
	}
	views := make([]TargetView, 0, len(targets))
	for _, target := range targets {
		views = append(views, TargetView{
			ChannelID:     target.ChannelID,
			Label:         target.Label,
			Mailbox:       target.Account,
			Host:          target.Host,
			Domain:        target.Domain,
			Usage:         target.Usage,
			SecretName:    target.SecretName,
			HasCredential: p.hasCredential(target.SecretName),
		})
	}
	return views, nil
}

// TargetView is one configured mailbox as the management surface reports it.
type TargetView struct {
	ChannelID     string `json:"channel_id"`
	Label         string `json:"label"`
	Mailbox       string `json:"mailbox"`
	Host          string `json:"host"`
	Domain        string `json:"domain,omitempty"`
	Usage         string `json:"usage,omitempty"`
	SecretName    string `json:"secret_name,omitempty"`
	HasCredential bool   `json:"has_credential"`
}

// scan reads one mailbox and returns the messages that were addressed to
// address (or all of them when address is empty).
func (p *ProviderImpl) scan(ctx context.Context, target Target, address string, limit int) ([]Mail, error) {
	resolved, errCredential := p.withCredential(target)
	if errCredential != nil {
		return nil, errCredential
	}
	session, errDial := p.dial(ctx, resolved)
	if errDial != nil {
		return nil, errDial
	}
	defer func() { _ = session.Close() }()

	folders, errFolders := session.Mailboxes(ctx)
	if errFolders != nil {
		// A folder list that cannot be read is not fatal: INBOX is always there,
		// and a code in INBOX is the common case.
		folders = nil
	}
	since := time.Now().Add(-p.cfg.PollWindow)
	collected := make([]Mail, 0, limit)
	scanned := false
	var firstErr error
	for _, mailbox := range junkMailboxes(folders) {
		mails, errRecent := session.Recent(ctx, mailbox, since, p.cfg.MaxMessages)
		if errRecent != nil {
			// One unreadable folder is not fatal while another still answers, but
			// a mailbox where every folder failed is not an empty inbox: saying
			// "no mail" would hide the failure behind a convincing answer.
			if firstErr == nil {
				firstErr = errRecent
			}
			continue
		}
		scanned = true
		for _, mail := range mails {
			if !mail.Mentions(address) {
				continue
			}
			mail.ChannelID = target.ChannelID
			collected = append(collected, mail)
		}
	}
	if !scanned && firstErr != nil {
		return nil, firstErr
	}
	// Newest first, then trim: the caller asked for the newest match, and a
	// folder returns its messages in arrival order, not by date.
	sortNewestFirst(collected)
	if len(collected) > limit {
		collected = collected[:limit]
	}
	return collected, nil
}

// withCredential fills in the mailbox password from the secret store.
func (p *ProviderImpl) withCredential(target Target) (Target, error) {
	if target.Password != "" {
		return target, nil
	}
	if strings.TrimSpace(target.SecretName) == "" {
		return Target{}, fmt.Errorf("%w: %s names no credential", ErrCredential, target.Label)
	}
	value, errRead := p.credential(target.SecretName)
	if errRead != nil {
		return Target{}, fmt.Errorf("%w: %v", ErrCredential, errRead)
	}
	target.Password = value
	return target, nil
}

// hasCredential reports whether the named secret exists, without reading it out
// of the store.
func (p *ProviderImpl) hasCredential(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	store := secretstore.Default()
	if store == nil || !store.Unlocked() {
		return false
	}
	_, errGet := store.Get(name)
	return errGet == nil
}

// targets reads the channel document and keeps the enabled mailboxes.
func (p *ProviderImpl) targets() ([]Target, error) {
	store, errLoad := supply.LoadChannels(p.cfg.ChannelsPath)
	if errLoad != nil {
		return nil, errLoad
	}
	channels := store.List(supply.KindEmail)
	targets := make([]Target, 0, len(channels))
	for _, channel := range channels {
		config := channel.KindConfigFor(supply.KindEmail)
		if config == nil || !config.Enabled {
			continue
		}
		// One mailbox is read one way. OAuth2 is checked first because a
		// hand-edited document can declare both, and a Microsoft mailbox only
		// answers the token method.
		connection, ok := config.Connections[supply.NatureOAuth2]
		auth := AuthOAuth2
		if !ok {
			connection, ok = config.Connections[supply.NatureIMAP]
			auth = AuthPassword
		}
		if !ok {
			continue
		}
		if strings.TrimSpace(connection.Account) == "" || strings.TrimSpace(connection.Endpoint) == "" {
			continue
		}
		// The category decides whether this mailbox stands in for a whole domain
		// or for one address. Reading it here as well as on write keeps a
		// hand-edited document from claiming both.
		usage := "personal"
		domain := ""
		if channel.CatchAll() {
			usage = "self-domain"
			domain = connection.Domain
		}
		// The entry name belongs to the mailbox: the channel carries the one
		// chosen when it was saved (a stored name may predate the derivation
		// rule), and a hand-written document without one still resolves.
		secret := strings.TrimSpace(connection.Secret)
		if secret == "" {
			secret = supply.EmailCredentialName(connection.Account)
			if auth == AuthOAuth2 {
				secret = supply.EmailOAuth2CredentialName(connection.Account)
			}
		}
		targets = append(targets, Target{
			ChannelID:  channel.ID,
			Label:      channel.Label,
			Host:       connection.Endpoint,
			Account:    connection.Account,
			Auth:       auth,
			ClientID:   connection.ClientID,
			Domain:     domain,
			Usage:      usage,
			SecretName: secret,
		})
	}
	return targets, nil
}

// savePool persists the ledger. The pool is shared by every kind, so a write is
// followed by a save here rather than by the registry.
func (p *ProviderImpl) savePool() error {
	if p.cfg.Pool == nil || strings.TrimSpace(p.cfg.PoolPath) == "" {
		return nil
	}
	return p.cfg.Pool.Save(p.cfg.PoolPath)
}

// readCredential reads one entry from the host secret store.
func readCredential(name string) (string, error) {
	store := secretstore.Default()
	if store == nil {
		return "", errors.New("the secret store is disabled")
	}
	if !store.Unlocked() {
		return "", errors.New("the secret store is locked")
	}
	value, errGet := store.Get(name)
	if errGet != nil {
		if errors.Is(errGet, secretstore.ErrNotFound) {
			return "", errors.New("the named credential is not in the store")
		}
		return "", errors.New("the named credential cannot be read")
	}
	return value, nil
}

// orderTargets puts the mailboxes that could actually receive address first, so
// a read does not open a connection to a mailbox that cannot hold the mail.
func orderTargets(targets []Target, address string) []Target {
	if address == "" {
		return targets
	}
	covering := make([]Target, 0, len(targets))
	others := make([]Target, 0, len(targets))
	for _, target := range targets {
		if target.Covers(address) {
			covering = append(covering, target)
			continue
		}
		others = append(others, target)
	}
	return append(covering, others...)
}

// pickTarget chooses the mailbox a grab reads from: the named channel when one
// is given, otherwise the first configured mailbox.
func pickTarget(targets []Target, channelID string) (Target, bool) {
	if len(targets) == 0 {
		return Target{}, false
	}
	if channelID == "" {
		return targets[0], true
	}
	for _, target := range targets {
		if target.ChannelID == channelID {
			return target, true
		}
	}
	return Target{}, false
}

// randomLocalPart builds the local part of a fresh catch-all address.
func randomLocalPart() (string, error) {
	buffer := make([]byte, 6)
	if _, errRead := rand.Read(buffer); errRead != nil {
		return "", errRead
	}
	return hex.EncodeToString(buffer), nil
}

// ProbeIMAP checks that a mailbox can be opened with an authorization code.
func ProbeIMAP(ctx context.Context, host, account, password string) (string, error) {
	return probeMailbox(ctx, Target{Host: host, Account: account, Password: password})
}

// ProbeOAuth2 checks that a mailbox can be opened with an OAuth2 refresh token.
//
// The token exchange runs here too, so an expired or revoked refresh token is
// reported as a credential problem — which is what it is — instead of as an
// unreachable mailbox.
func ProbeOAuth2(ctx context.Context, host, account, clientID, refreshToken string) (string, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("%w: no OAuth2 application id", ErrProbeUnready)
	}
	return probeMailbox(ctx, Target{
		Host:     host,
		Account:  account,
		Auth:     AuthOAuth2,
		ClientID: clientID,
		Password: refreshToken,
	})
}

// probeMailbox opens a session, lists its folders, and closes again.
//
// It is read-only: nothing is sent anywhere, so it needs no passphrase — and it
// never repeats the credential in a detail or an error.
func probeMailbox(ctx context.Context, target Target) (string, error) {
	if strings.TrimSpace(target.Host) == "" {
		return "", fmt.Errorf("%w: no mailbox host", ErrProbeUnready)
	}
	if strings.TrimSpace(target.Account) == "" {
		return "", fmt.Errorf("%w: no mailbox account", ErrProbeUnready)
	}
	if strings.TrimSpace(target.Password) == "" {
		return "", fmt.Errorf("%w: no mailbox credential", ErrProbeUnready)
	}
	session, errDial := dialSession(ctx, target)
	if errDial != nil {
		if errors.Is(errDial, ErrLoginRejected) {
			return "", fmt.Errorf("%w: %v", ErrProbeUnready, errDial)
		}
		return "", errDial
	}
	defer func() { _ = session.Close() }()
	folders, errFolders := session.Mailboxes(ctx)
	if errFolders != nil {
		return "", errFolders
	}
	return fmt.Sprintf("connected, %d mailboxes", len(folders)), nil
}

var _ supply.Provider = (*ProviderImpl)(nil)
