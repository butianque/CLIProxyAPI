// Package phone is the host-side phone supply kind: it rents a number from a
// code-receiving platform, reads the verification message, and records which
// account each number registered.
//
// It is the former plugin-side package (cpa/plugins/loomy/internal/sms) moved
// into the host, so a plugin no longer holds the ability to rent numbers or read
// the platform credential. Plugins ask the host through the host.supply.*
// callbacks (kind "phone") instead. Behaviour that used to sit in the plugin —
// keeping the channel set fresh, running the guardrail, crediting a delivery and
// suspending an unreliable channel — lives here too, so the ABI stays a small
// set of verbs (grab/read/link/release) and a plugin is unaware of the
// platform's mechanics.
//
// The package keeps its original shape because that shape is what the platform
// requires: a Provider talks to one platform, a Service layers the channel
// cache, the phone ledger, the spend budget and the channel guardrail on top of
// it, and a Store owns the two on-disk documents. Only stdlib is used, so the
// move carries no dependency into the host.
package phone

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// Config is everything needed to serve the phone kind. It is resolved by the
// host from configuration and the secret store; no value in it is a credential.
type Config struct {
	// Provider names the platform implementation, e.g. "haozhuma".
	Provider string
	// Secret is the already-decrypted platform credential. It is never logged
	// and never leaves this package.
	Secret HaozhumaSecret
	// Store locates the channel cache and the phone ledger.
	Store Store
	// Budget caps spending.
	Budget Budget
	// Project identifies the upstream service numbers are rented for.
	Project Project
	// Strategy tunes how price and reliability combine into the rent order.
	Strategy Strategy
	// CoolDownSeconds holds a just-failed channel out of the preferred order.
	CoolDownSeconds int64
	// Guardrail narrows the platform's enabled channels to the cheap, in-stock
	// ones on every grab, so a blind rental can only land on an affordable
	// channel. It is the host's equivalent of the plugin's sms_guardrail.
	Guardrail bool
	// Ledger is the cross-kind identity ledger, owned by the supply registry
	// and shared with every other kind. It is injected rather than loaded here
	// so one in-memory document backs the one file.
	Ledger *supply.Ledger
}

// ProviderImpl is the base-side supply provider for the phone kind. It adapts
// the platform Service to the shared supply.Provider contract so the host can
// route phone calls the same way it will route email calls.
type ProviderImpl struct {
	service   *Service
	project   Project
	secret    HaozhumaSecret
	guardrail bool

	// delivered tracks numbers whose delivery has already been credited to
	// their channel, so a repeated poll of the same inbox does not inflate the
	// channel's delivery count. It is in-memory on purpose: after a restart at
	// worst one extra delivery is recorded for a number that is still being
	// polled, which is harmless.
	deliveredMu sync.Mutex
	delivered   map[string]bool
}

// New builds the phone provider from a resolved configuration.
func New(cfg Config) (*ProviderImpl, error) {
	if strings.TrimSpace(cfg.Provider) != "" && !strings.EqualFold(strings.TrimSpace(cfg.Provider), "haozhuma") {
		return nil, fmt.Errorf("phone: unsupported provider %q", cfg.Provider)
	}
	platform, errPlatform := NewHaozhuma(cfg.Secret, nil)
	if errPlatform != nil {
		return nil, errPlatform
	}
	service := NewService(platform, cfg.Store, cfg.Budget)
	service.Strategy = cfg.Strategy
	if cfg.Ledger != nil {
		service.shared = cfg.Ledger
	}
	if cfg.CoolDownSeconds > 0 {
		service.CoolDownSeconds = cfg.CoolDownSeconds
	}
	return &ProviderImpl{
		service:   service,
		project:   cfg.Project,
		secret:    cfg.Secret,
		guardrail: cfg.Guardrail,
		delivered: map[string]bool{},
	}, nil
}

// Kind names the supply kind this provider serves.
func (p *ProviderImpl) Kind() supply.Kind { return supply.KindPhone }

// Service exposes the underlying platform service, so the management surface
// can report the channel cache, the ledger and the guardrail state.
func (p *ProviderImpl) Service() *Service { return p.service }

// Status reports whether the platform credential resolved and the kind is
// configured.
//
// It is deliberately local: reaching the platform belongs to the management
// surface (which needs the balance), not to the base status. A provider only
// exists once the credential parsed, so a built provider is a configured one;
// startup must not depend on a network round-trip to report its kinds.
func (p *ProviderImpl) Status(context.Context) (supply.Status, error) {
	return supply.Status{Enabled: true, Kinds: []supply.Kind{supply.KindPhone}}, nil
}

// Grab rents one number (or re-occupies a named one) and returns it as a shared
// identity.
//
// Before renting it brings the channel cache up to date and, when the guardrail
// is on, narrows the platform's enabled channels to the affordable in-stock
// ones. Both used to be the plugin's job before every login; they live here now
// so a plugin only asks for a number.
//
// Re-occupying a named number is restricted to numbers the ledger already
// recorded: an arbitrary number (the operator's own, say) belongs to the manual
// login path, and asking the platform to hand back a number it never rented to
// us would either fail or, worse, take somebody else's. That case is reported
// as ErrUnknownIdentity so a caller can tell it from a real rental failure.
func (p *ProviderImpl) Grab(ctx context.Context, opts supply.GrabOptions) (supply.Identity, error) {
	project := p.project
	if strings.TrimSpace(opts.Purpose) != "" {
		project.SID = strings.TrimSpace(opts.Purpose)
	}
	address := strings.TrimSpace(opts.Address)
	if address != "" && !p.service.Ledger().Knows(supply.KindPhone, address) {
		return supply.Identity{}, supply.ErrUnknownIdentity
	}

	// Channel maintenance is best-effort: a stale web session or a platform
	// hiccup must not stop a rental that could still succeed. It runs on the
	// caller's context, not the rental's own short deadline, because joining and
	// switching channels is a batch of platform calls that can legitimately take
	// longer than one rental.
	p.maintainChannels(ctx, project)

	ctxAcquire, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var number Number
	var errAcquire error
	if address != "" {
		number, _, errAcquire = p.service.Reacquire(ctxAcquire, project, address)
	} else {
		number, _, errAcquire = p.service.Acquire(ctxAcquire, project)
	}
	if errAcquire != nil {
		return supply.Identity{}, errAcquire
	}
	// A rental starts with a clean delivery slate: the flag is per rental, not
	// per number, so re-occupying a number that delivered before still credits
	// its channel when the next message arrives.
	p.deliveredMu.Lock()
	delete(p.delivered, number.Phone)
	p.deliveredMu.Unlock()
	return supply.Identity{
		Kind:    supply.KindPhone,
		Address: number.Phone,
		Code:    number.Code,
		Carrier: number.Carrier,
		Region:  number.Region,
	}, nil
}

// maintainChannels refreshes the joined channel set and runs the guardrail, so
// the platform's own picker can only land on an affordable channel.
func (p *ProviderImpl) maintainChannels(ctx context.Context, project Project) {
	count, errEnsure := p.service.EnsureChannels(ctx, strings.TrimSpace(project.SID), strings.TrimSpace(project.Name))
	if errEnsure != nil {
		if cache := p.service.Channels(); cache != nil && len(cache.Channels) > 0 {
			hostLogSafe("phone supply: channel refresh/join skipped, using cached list: " + errEnsure.Error())
			return
		}
		hostLogSafe("phone supply: channel refresh/join failed and no cache exists: " + errEnsure.Error())
		return
	}
	hostLogSafe(fmt.Sprintf("phone supply: %d affordable channels ready for project %s", count, project.SID))
	if !p.guardrail {
		return
	}
	changed, errGuard := p.service.GuardChannels(ctx, strings.TrimSpace(project.SID))
	if errGuard != nil {
		hostLogSafe("phone supply: channel guardrail skipped: " + errGuard.Error())
		return
	}
	if changed > 0 {
		hostLogSafe(fmt.Sprintf("phone supply: guardrail adjusted %d channel(s)", changed))
	}
}

// Read reads a number's inbox once. "No message yet" is Ready=false, not an
// error: it is the ordinary outcome of polling.
//
// When a message arrives the channel that produced the number is credited with
// a delivery, which clears its failure run. This is the one signal that keeps a
// channel which had a bad spell from being punished forever, and it is recorded
// once per number so repeated polls do not inflate the count.
func (p *ProviderImpl) Read(ctx context.Context, purpose, address string) (supply.Message, error) {
	project := p.project
	if strings.TrimSpace(purpose) != "" {
		project.SID = strings.TrimSpace(purpose)
	}
	address = strings.TrimSpace(address)
	message, errRead := p.service.Read(ctx, project, address)
	if errRead != nil {
		if errors.Is(errRead, ErrNotReady) {
			return supply.Message{Ready: false}, nil
		}
		return supply.Message{}, errRead
	}
	if message.Ready {
		p.recordDelivery(address)
	}
	return supply.Message{Ready: message.Ready, Code: message.Code, Text: message.Text}, nil
}

// recordDelivery credits one number's channel with a delivery, once per number.
func (p *ProviderImpl) recordDelivery(address string) {
	if address == "" {
		return
	}
	// Look the channel up first: if the ledger has no record yet there is
	// nothing to credit, and the flag must stay unset so a later poll can try
	// again.
	record, ok := p.service.Ledger().Get(supply.KindPhone, address)
	if !ok || strings.TrimSpace(record.MetaString("channel")) == "" {
		return
	}
	p.deliveredMu.Lock()
	if p.delivered[address] {
		p.deliveredMu.Unlock()
		return
	}
	p.delivered[address] = true
	p.deliveredMu.Unlock()
	p.service.RecordDelivery(record.MetaString("channel"), record.Price)
}

// Link records which account a number registered, and on which platform, so a
// later re-authentication can get back onto the exact same number.
func (p *ProviderImpl) Link(_ context.Context, address, target, account, authIndex string) error {
	return p.service.LinkAccount(strings.TrimSpace(address), strings.TrimSpace(target), strings.TrimSpace(account), strings.TrimSpace(authIndex))
}

// Release returns a number to the platform's pool.
//
// The outcome is recorded against the channel that produced the number. A
// timeout is a real failure of that channel, so after the failure is recorded
// the channel is suspended when it has failed enough times in a row — unless
// it still holds a number in the ledger, in which case pausing it would block
// re-acquiring that number and the channel is only demoted by the score.
func (p *ProviderImpl) Release(ctx context.Context, address, outcome string) error {
	project := p.project
	address = strings.TrimSpace(address)
	ctxRelease, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	channelOutcome := OutcomeReleased
	if strings.EqualFold(strings.TrimSpace(outcome), "timeout") {
		channelOutcome = OutcomeTimeout
	}
	// The price and the channel are taken from the ledger, which recorded them
	// at rental time.
	var price float64
	var channel string
	if record, ok := p.service.Ledger().Get(supply.KindPhone, address); ok {
		price = record.Price
		channel = strings.TrimSpace(record.MetaString("channel"))
	}
	errRelease := p.service.ReleaseUnused(ctxRelease, project, address, price, channelOutcome)
	if errRelease != nil {
		return errRelease
	}
	// A delivery that has already been credited must not be re-credited after
	// the number is released: the next rental of the same number starts fresh.
	p.deliveredMu.Lock()
	delete(p.delivered, address)
	p.deliveredMu.Unlock()

	if channelOutcome == OutcomeTimeout && channel != "" && p.service.ShouldSuspend(channel) {
		if _, errSuspend := p.service.SuspendUnreliable(ctxRelease, channel); errSuspend != nil {
			hostLogSafe("phone supply: suspend unreliable channel " + channel + ": " + errSuspend.Error())
		}
	}
	return nil
}

// ProviderImpl implements the shared supply provider contract.
var _ supply.Provider = (*ProviderImpl)(nil)
