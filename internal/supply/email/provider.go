package email

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
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

	// Egress is the supply-wide exit every mailbox uses unless its channel names
	// one. Empty inherits the process environment.
	Egress string

	// ResolveEgress turns a proxy-pool id into the address it names.
	//
	// It is injected rather than loaded here because the pool is one document
	// shared by every kind and by the host: a provider reading its own copy
	// would drift from the others. Nil means no pool is available, in which case
	// an id cannot be honoured and the connection fails closed.
	ResolveEgress func(id int) (string, error)

	// MaxOpen bounds how many mailboxes are open at once across the process.
	// Zero uses DefaultMaxOpen; a negative value means no bound.
	MaxOpen int

	// MaxPerHost bounds how many mailboxes are open at once against one server.
	// Zero uses DefaultMaxPerHost; a negative value means no bound.
	MaxPerHost int
}

// ProviderImpl is the email supply provider.
type ProviderImpl struct {
	cfg        Config
	dial       func(ctx context.Context, target Target) (Session, error)
	credential func(name string) (string, error)
	gate       *dialGate
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
	if cfg.MaxOpen == 0 {
		cfg.MaxOpen = DefaultMaxOpen
	}
	if cfg.MaxPerHost == 0 {
		cfg.MaxPerHost = DefaultMaxPerHost
	}
	provider := &ProviderImpl{
		cfg:        cfg,
		dial:       cfg.Dial,
		credential: cfg.Credential,
		gate:       newDialGate(cfg.MaxOpen, cfg.MaxPerHost),
	}
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
	// A caller may ask for one kind of source: a bought mailbox that exists on
	// its own, or an alias of a domain this service operates. Narrowing here
	// rather than at each caller keeps the choice out of the wire contract.
	if usage := strings.TrimSpace(opts.Usage); usage != "" {
		narrowed := make([]Target, 0, len(targets))
		for _, target := range targets {
			if strings.EqualFold(strings.TrimSpace(target.Usage), usage) {
				narrowed = append(narrowed, target)
			}
		}
		if len(narrowed) == 0 {
			return supply.Identity{}, supply.ErrUnavailable
		}
		targets = narrowed
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
	// Only a mailbox that can receive the address can hold its mail, so the
	// others are not opened: walking every configured mailbox would make one
	// read cost as many connections as the service has mailboxes.
	covering := make([]Target, 0, 1)
	for _, target := range orderTargets(targets, wanted) {
		if target.Covers(wanted) {
			covering = append(covering, target)
		}
	}
	if len(covering) == 0 {
		return supply.Message{}, supply.ErrUnknownIdentity
	}
	targets = covering
	var firstErr error
	scanned := false
	for _, target := range targets {
		mails, _, errScan := p.scan(ctx, target, wanted, Cursor{}, 1)
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
			Links:   newest.Links,
		}, nil
	}
	if !scanned && firstErr != nil {
		return supply.Message{}, firstErr
	}
	return supply.Message{Ready: false}, nil
}

// ReadResult is one answer to "what arrived for this address after the position
// I hold".
//
// It carries the messages, not only a code, because a verification mail is not
// the only thing that arrives: a welcome mail with no code can sit on top of it,
// and an answer that reported only the newest message would say "no code" while
// the code was one message down.
type ReadResult struct {
	// Mails are the new messages, newest first, at most readAfterLimit.
	Mails []Mail
	// Code is the newest code among them, or "" when none states one.
	Code string
	// Cursor is where the next read continues. It advances past everything this
	// answer returned.
	Cursor string
	// Reset reports that the mailbox's generation changed, so the position the
	// caller held no longer named the same messages and the window was read
	// again. A caller may see a message twice when this is true.
	Reset bool
	// Mailbox names the mailbox that answered, so a caller can tell which
	// address's connection produced the mail.
	Mailbox string
}

const (
	// readAfterLimit is how many new messages one read reports. A verification
	// flow needs the newest one; the rest are there so a caller can recognise
	// which mail it is looking at.
	readAfterLimit = 5
	// pollInterval is how often a waiting read looks again on the same session.
	// Opening a new session per look would cost a TLS handshake and a login every
	// two seconds of waiting, which is what a provider throttles.
	pollInterval = 2 * time.Second
)

// ReadAfter reads the mail that arrived for one address after a position.
//
// It opens exactly one mailbox: the one that can receive the address. That is
// the difference from Read, which walks every configured mailbox until one
// answers — affordable for a single catch-all domain, not for a thousand bought
// addresses.
//
// wait keeps the session open and looks again on it until something arrives or
// the wait expires, so a caller asks once instead of polling in a loop.
func (p *ProviderImpl) ReadAfter(ctx context.Context, address, cursor string, wait time.Duration) (ReadResult, error) {
	wanted := strings.ToLower(strings.TrimSpace(address))
	if wanted == "" {
		return ReadResult{}, errors.New("email: a read needs an address to look for")
	}
	after, errCursor := DecodeCursor(cursor)
	if errCursor != nil {
		return ReadResult{}, errCursor
	}
	targets, errTargets := p.targets()
	if errTargets != nil {
		return ReadResult{}, errTargets
	}
	chosen, ok := targetFor(targets, wanted)
	if !ok {
		// No configured mailbox receives this address, so this service never
		// handed it out. The caller's answer is a manual path, not a retry.
		return ReadResult{}, supply.ErrUnknownIdentity
	}
	deadline := time.Now().Add(wait)
	for {
		mails, positions, errScan := p.scan(ctx, chosen, wanted, after, readAfterLimit)
		if errScan != nil {
			return ReadResult{}, errScan
		}
		next := Cursor{Nature: cursorNature(chosen.Auth), Folders: positions}
		if len(mails) > 0 {
			return ReadResult{
				Mails:   mails,
				Code:    firstCode(mails),
				Cursor:  EncodeCursor(next),
				Reset:   positionReset(after, positions),
				Mailbox: chosen.Account,
			}, nil
		}
		if wait <= 0 || !time.Now().Before(deadline) {
			// Nothing new. The position is handed back with the folder
			// generations refreshed, so a caller that polls again continues from
			// the same place.
			return ReadResult{Cursor: EncodeCursor(next), Mailbox: chosen.Account, Reset: positionReset(after, positions)}, nil
		}
		select {
		case <-ctx.Done():
			return ReadResult{}, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// positionReset reports whether a folder the caller held a position in now has a
// different generation, which invalidates every stored UID in it.
func positionReset(before Cursor, after []FolderPosition) bool {
	for _, position := range after {
		previous := before.For(position.Folder)
		if previous.UIDValidity == 0 || position.UIDValidity == 0 {
			continue
		}
		if previous.UIDValidity != position.UIDValidity {
			return true
		}
	}
	return false
}

// targetFor picks the one mailbox that can receive address.
func targetFor(targets []Target, address string) (Target, bool) {
	for _, target := range orderTargets(targets, address) {
		if target.Covers(address) {
			return target, true
		}
	}
	return Target{}, false
}

// firstCode returns the newest message's code, or the next one down when the
// newest states none.
func firstCode(mails []Mail) string {
	for _, mail := range mails {
		if code := strings.TrimSpace(mail.Code); code != "" {
			return code
		}
	}
	return ""
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
// "everything the channels hold", which is what a channel row reports.
//
// It deliberately does not walk the bought mailboxes: one address, one mailbox,
// is what ReadAfter is for. Opening a thousand bought mailboxes to fill one
// panel would cost a thousand connections per view, and a channel row has
// nothing to say about a mailbox that no channel issued.
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
	// A mailbox that cannot receive the address cannot hold its mail, so reading
	// it would only cost a connection. An empty address asks for the channels'
	// own mailboxes, which are the ones a row speaks for.
	narrowed := make([]Target, 0, len(targets))
	for _, target := range orderTargets(targets, wanted) {
		if wanted == "" {
			if strings.TrimSpace(target.ChannelID) != "" {
				narrowed = append(narrowed, target)
			}
			continue
		}
		if target.Covers(wanted) {
			narrowed = append(narrowed, target)
		}
	}
	if wanted != "" && len(narrowed) == 0 {
		// Nothing here receives this address, so this service never handed it
		// out. Saying "no mail" would hide that behind a convincing answer.
		return InboxReading{}, supply.ErrUnknownIdentity
	}
	targets = narrowed
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
		mails, _, errScan := p.scan(ctx, target, wanted, Cursor{}, limit)
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
			Transport:     transportName(target.Auth),
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
	ChannelID string `json:"channel_id"`
	Label     string `json:"label"`
	Mailbox   string `json:"mailbox"`
	Host      string `json:"host"`
	// Transport is how the mailbox is read: "imap", "oauth2", or "graph".
	//
	// It is reported because a Graph mailbox has no host to show, and an empty
	// host alone reads as "not configured" rather than "read another way".
	Transport     string `json:"transport"`
	Domain        string `json:"domain,omitempty"`
	Usage         string `json:"usage,omitempty"`
	SecretName    string `json:"secret_name,omitempty"`
	HasCredential bool   `json:"has_credential"`
}

// transportName names the transport an auth mode implies.
func transportName(auth AuthMode) string {
	switch auth {
	case AuthGraph:
		return "graph"
	case AuthOAuth2:
		return "oauth2"
	}
	return "imap"
}

// scan reads one mailbox and returns the messages that were addressed to
// address (or all of them when address is empty), plus the position each folder
// was read up to.
func (p *ProviderImpl) scan(ctx context.Context, target Target, address string, after Cursor, limit int) ([]Mail, []FolderPosition, error) {
	resolved, errCredential := p.withCredential(target)
	if errCredential != nil {
		return nil, nil, errCredential
	}
	// One mailbox is one connection. The gate is taken before dialling, so a
	// burst of readers queues instead of opening a session per caller against a
	// provider that will start refusing them.
	release, errGate := p.gate.acquire(ctx, gateKey(resolved))
	if errGate != nil {
		return nil, nil, errGate
	}
	defer release()
	session, errDial := p.dial(ctx, resolved)
	if errDial != nil {
		return nil, nil, errDial
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
	positions := make([]FolderPosition, 0, len(folders))
	scanned := false
	var firstErr error
	for _, mailbox := range junkMailboxes(folders) {
		mails, validity, errRecent := session.Recent(ctx, mailbox, since, after.For(mailbox), p.cfg.MaxMessages)
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
		if len(mails) > 0 {
			// The position moves past the newest message this folder returned,
			// so the next read does not report the same mail again.
			positions = append(positions, positionFor(mailbox, validity, mails[len(mails)-1]))
		} else {
			// Nothing new, but the folder's generation is still worth carrying:
			// a reset is what tells a caller its position no longer holds.
			previous := after.For(mailbox)
			previous.Folder = mailbox
			previous.UIDValidity = validity
			positions = append(positions, previous)
		}
		for _, mail := range mails {
			if !mail.Mentions(address) {
				continue
			}
			mail.ChannelID = target.ChannelID
			collected = append(collected, mail)
		}
	}
	if !scanned && firstErr != nil {
		return nil, nil, firstErr
	}
	// Newest first, then trim: the caller asked for the newest match, and a
	// folder returns its messages in arrival order, not by date.
	sortNewestFirst(collected)
	if len(collected) > limit {
		collected = collected[:limit]
	}
	return collected, positions, nil
}

// positionFor is the position that continues after newest in one folder.
func positionFor(folder string, validity uint32, newest Mail) FolderPosition {
	return FolderPosition{
		Folder:      folder,
		UIDValidity: validity,
		UID:         newest.UID,
		Received:    newest.Date.UTC().Format(time.RFC3339Nano),
	}
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
//
// A mailbox can be configured in two places, because they are two different
// things: a channel is one connection that covers many addresses, and a pool
// identity is one bought address that carries its own credential. Both are
// readable mailboxes, so both are returned here — channels first, because they
// are the general case, then the individually-held identities.
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
		// A channel declares one way of reading a mailbox. The order below is
		// kept from when a channel could declare the token transports: a
		// hand-edited document may still carry one, and reading it is better than
		// silently dropping the mailbox.
		connection, ok := config.Connections[supply.NatureOAuth2]
		auth := AuthOAuth2
		if !ok {
			connection, ok = config.Connections[supply.NatureGraph]
			auth = AuthGraph
		}
		if !ok {
			connection, ok = config.Connections[supply.NatureIMAP]
			auth = AuthPassword
		}
		if !ok {
			continue
		}
		if strings.TrimSpace(connection.Account) == "" {
			continue
		}
		// Graph has one fixed endpoint, so a Graph channel carries none; the
		// protocol ones cannot work without one.
		if auth != AuthGraph && strings.TrimSpace(connection.Endpoint) == "" {
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
			if auth == AuthOAuth2 || auth == AuthGraph {
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
			Egress:     p.connectionEgress(connection),
		})
	}
	return append(targets, p.poolTargets(targets)...), nil
}

// connectionEgress returns the exit one channel connection leaves through.
//
// A pool id wins over an address stored beside it: the address is a cache that
// goes stale the moment the exit is replaced, and honouring it would keep
// sending traffic from an address the operator already retired.
//
// An id that cannot be resolved fails closed. It does not fall back to the
// stored address and it does not fall back to a direct connection, because
// either would put the mailbox on an address nobody chose.
func (p *ProviderImpl) connectionEgress(connection supply.Connection) string {
	if connection.EgressID <= 0 {
		return firstNonEmpty(connection.Egress, p.cfg.Egress)
	}
	if p.cfg.ResolveEgress == nil {
		return supply.UnresolvedEgress
	}
	url, errResolve := p.cfg.ResolveEgress(connection.EgressID)
	if errResolve != nil || strings.TrimSpace(url) == "" {
		return supply.UnresolvedEgress
	}
	return url
}

// poolTargets turns the individually-held email identities into readable
// mailboxes.
//
// The order is deliberate. An identity that has never been handed out comes
// first, then the one used longest ago: a grab with no channel named picks the
// first target, so a stable order would spend the same mailbox forever and leave
// the rest of a bought batch untouched.
func (p *ProviderImpl) poolTargets(configured []Target) []Target {
	if p.cfg.Pool == nil {
		return nil
	}
	seen := make(map[string]bool, len(configured))
	for _, target := range configured {
		seen[strings.ToLower(strings.TrimSpace(target.Account))] = true
	}
	records := p.cfg.Pool.Mailboxes()
	// Newest-recorded first is the wrong order for spending a batch, so the list
	// is sorted by use: unused identities keep their recorded order among
	// themselves, and used ones follow oldest first.
	unused := make([]supply.Record, 0, len(records))
	used := make([]supply.Record, 0, len(records))
	for _, record := range records {
		box := record.Mailbox
		if box == nil || !box.Usable() {
			continue
		}
		account := strings.ToLower(strings.TrimSpace(record.Address))
		if account == "" || seen[account] {
			continue
		}
		if record.LastUsed == 0 && record.Target == "" {
			unused = append(unused, record)
			continue
		}
		used = append(used, record)
	}
	sort.SliceStable(used, func(i, j int) bool {
		return used[i].LastUsed < used[j].LastUsed
	})
	ordered := append(unused, used...)

	targets := make([]Target, 0, len(ordered))
	for _, record := range ordered {
		box := record.Mailbox
		auth := AuthPassword
		switch box.Nature {
		case supply.NatureGraph:
			auth = AuthGraph
		case supply.NatureOAuth2:
			auth = AuthOAuth2
		}
		secret := strings.TrimSpace(box.Secret)
		if secret == "" {
			secret = supply.EmailCredentialName(record.Address)
			if auth == AuthOAuth2 || auth == AuthGraph {
				secret = supply.EmailOAuth2CredentialName(record.Address)
			}
		}
		label := strings.TrimSpace(record.Address)
		targets = append(targets, Target{
			// No channel: this identity is not a source of addresses, so an
			// answer about it must not point at one.
			Label:      label,
			Host:       box.Endpoint,
			Account:    record.Address,
			Auth:       auth,
			ClientID:   box.ClientID,
			Usage:      "personal",
			SecretName: secret,
			Egress:     p.cfg.Egress,
		})
	}
	return targets
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
//
// egress is the channel's exit; empty means the process environment. The probe
// is the one call that can prove an exit works, so it has to take the same
// route the real read will.
func ProbeIMAP(ctx context.Context, host, account, password, egress string) (string, error) {
	return probeMailbox(ctx, Target{Host: host, Account: account, Password: password, Egress: egress})
}

// ProbeOAuth2 checks that a mailbox can be opened with an OAuth2 refresh token.
//
// The token exchange runs here too, so an expired or revoked refresh token is
// reported as a credential problem — which is what it is — instead of as an
// unreachable mailbox.
func ProbeOAuth2(ctx context.Context, host, account, clientID, refreshToken, egress string) (string, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("%w: no OAuth2 application id", ErrProbeUnready)
	}
	return probeMailbox(ctx, Target{
		Host:     host,
		Account:  account,
		Auth:     AuthOAuth2,
		ClientID: clientID,
		Password: refreshToken,
		Egress:   egress,
	})
}

// ProbeGraph checks that a mailbox can be read through Microsoft Graph.
//
// It is a separate entry point rather than a flag because the two transports
// answer different questions: an IMAP token opens IMAP and is refused by Graph,
// and a Graph token is the reverse. Reporting one as the other would tell the
// operator their credential is broken when it is simply the wrong kind.
func ProbeGraph(ctx context.Context, account, clientID, refreshToken, egress string) (string, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("%w: no OAuth2 application id", ErrProbeUnready)
	}
	return probeMailbox(ctx, Target{
		Account:  account,
		Auth:     AuthGraph,
		ClientID: clientID,
		Password: refreshToken,
		Egress:   egress,
	})
}

// probeMailbox opens a session, lists its folders, and closes again.
//
// It is read-only: nothing is sent anywhere, so it needs no passphrase — and it
// never repeats the credential in a detail or an error.
func probeMailbox(ctx context.Context, target Target) (string, error) {
	return probeMailboxWith(ctx, target, dialSession)
}

// probeMailboxWith is probeMailbox over a caller-supplied dial, so the probe can
// run through the provider's own dial (and therefore through its test seam)
// instead of always opening a real session.
func probeMailboxWith(ctx context.Context, target Target, dial func(ctx context.Context, target Target) (Session, error)) (string, error) {
	if target.Auth != AuthGraph && strings.TrimSpace(target.Host) == "" {
		return "", fmt.Errorf("%w: no mailbox host", ErrProbeUnready)
	}
	if strings.TrimSpace(target.Account) == "" {
		return "", fmt.Errorf("%w: no mailbox account", ErrProbeUnready)
	}
	if strings.TrimSpace(target.Password) == "" {
		return "", fmt.Errorf("%w: no mailbox credential", ErrProbeUnready)
	}
	session, errDial := dial(ctx, target)
	if errDial != nil {
		if errors.Is(errDial, ErrLoginRejected) {
			// Both kinds are kept in the chain: the credential exists but the
			// server refused it, which a caller may report differently from a
			// credential that could not even be read.
			return "", fmt.Errorf("%w: %w", ErrProbeUnready, errDial)
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

// ProbeAddress opens the mailbox that receives address and closes it again.
//
// It answers the panel's "can this identity be reached right now" question for
// an address that carries its own credential: such an address has no channel to
// probe, so the only honest answer comes from dialling the mailbox that covers
// it. The credential is read the way a real read reads it, so a mailbox whose
// credential is missing or unreadable reports that instead of a connection
// failure.
//
// Nothing is read from the mailbox: no message is listed, no code is extracted.
func (p *ProviderImpl) ProbeAddress(ctx context.Context, address string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("%w: no address", supply.ErrUnknownIdentity)
	}
	targets, errTargets := p.targets()
	if errTargets != nil {
		return "", errTargets
	}
	chosen, ok := targetFor(targets, address)
	if !ok {
		// No mailbox receives this address, which is a different defect from a
		// mailbox that refuses a login: the caller can neither retry nor wait.
		return "", fmt.Errorf("%w: no mailbox receives %s", supply.ErrUnknownIdentity, address)
	}
	resolved, errCredential := p.withCredential(chosen)
	if errCredential != nil {
		return "", errCredential
	}
	// The probe opens a session, so it queues behind the same bound a real read
	// does: a page that probes every identity must not look like a burst of
	// logins to the provider.
	release, errGate := p.gate.acquire(ctx, gateKey(resolved))
	if errGate != nil {
		return "", errGate
	}
	defer release()
	return probeMailboxWith(ctx, resolved, p.dial)
}

var _ supply.Provider = (*ProviderImpl)(nil)
