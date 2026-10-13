package phone

import (
	"context"
	"time"
)

// This file exposes the platform's management operations on the provider, so
// the host's management surface can drive the same actions the panel used to
// reach through the plugin: refresh/join channels, apply the guardrail, switch
// one channel, blacklist a number, read the balance, and sign in to the web
// surface. They are thin wrappers over Service, kept here (not in the HTTP
// layer) so the platform semantics stay in one place.

// Balance reports the platform account balance in CNY. It is the reachability
// probe the management surface uses; the base status stays offline.
func (p *ProviderImpl) Balance(ctx context.Context) (float64, error) {
	ctxBalance, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return p.service.Balance(ctxBalance)
}

// Channels returns the cached channel list.
func (p *ProviderImpl) Channels() *ChannelCache { return p.service.Channels() }

// Ledger returns the phone ledger.
func (p *ProviderImpl) Ledger() *Ledger { return p.service.Ledger() }

// Health returns the channel health record.
func (p *ProviderImpl) Health() *ChannelHealth { return p.service.Health() }

// Budget returns the configured spend caps.
func (p *ProviderImpl) Budget() Budget { return p.service.Budget }

// Project returns the project numbers are rented for.
func (p *ProviderImpl) Project() Project { return p.project }

// RefreshChannels re-reads the joined channels and, when join is true, joins
// every affordable one it does not hold yet.
func (p *ProviderImpl) RefreshChannels(ctx context.Context, join bool) (int, error) {
	ctxRefresh, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return p.service.EnsureChannelsAndRefresh(ctxRefresh, p.project, join)
}

// Guardrail narrows the platform's enabled channel set to the cheap, in-stock
// channels and reports how many channels it changed.
func (p *ProviderImpl) Guardrail(ctx context.Context) (int, error) {
	ctxGuard, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return p.service.GuardChannels(ctxGuard, p.project.SID)
}

// SetChannelOpen pauses ("pause") or recovers ("recover") one joined channel.
func (p *ProviderImpl) SetChannelOpen(ctx context.Context, action string, uid string) error {
	ctxSwitch, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, errSwitch := p.service.SetChannelOpen(ctxSwitch, action, []string{uid}); errSwitch != nil {
		return errSwitch
	}
	// Re-read so callers see the platform's settled state, not just our intent.
	if _, errRefresh := p.service.EnsureChannelsAndRefresh(ctxSwitch, p.project, false); errRefresh != nil {
		return errRefresh
	}
	return nil
}

// Blacklist asks the platform never to hand back one number again.
func (p *ProviderImpl) Blacklist(ctx context.Context, phone string) error {
	ctxBlacklist, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return p.service.Blacklist(ctxBlacklist, p.project, phone)
}

// WebLogin signs in to the platform's web surface with the given account and
// password, solving its click-order captcha, and returns the session cookie and
// the number of channels it can now see. The caller persists the cookie.
func (p *ProviderImpl) WebLogin(ctx context.Context, user, pass string) (string, int, error) {
	provider, errProvider := NewHaozhuma(p.secret, nil)
	if errProvider != nil {
		return "", 0, errProvider
	}
	ctxLogin, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	result, errLogin := provider.WebLogin(ctxLogin, user, pass)
	if errLogin != nil {
		return "", 0, errLogin
	}
	return result.Cookie, result.Channels, nil
}
