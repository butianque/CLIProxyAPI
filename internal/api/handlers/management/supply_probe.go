package management

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/phone"
)

// This file is the probe surface: the panel's "is this actually reachable"
// question, answered with one cheap authenticated call per thing asked about.
//
// Two things get probed. A channel declares natures, and each declared nature is
// dialled once. An identity in the pool that carries its own credential has no
// channel to ask — the mailbox that receives it is the only thing that can
// answer — so it is probed by address instead.
//
// A probe is read-only: it needs no master passphrase, writes nothing, and
// never returns a credential value. What it reports is a state plus, when there
// is something useful to say, a short detail such as the account balance.

// The four states a probe reports.
const (
	// probeOnline: a real request was made and it succeeded.
	probeOnline = "online"
	// probeOffline: a real request was made and it failed.
	probeOffline = "offline"
	// probeUnready: the nature's credential could not be read, so nothing was
	// attempted. It is not offline, and must not be reported as it.
	probeUnready = "unready"
	// probeUnsupported: the base has no probe for this nature yet.
	probeUnsupported = "unsupported"
)

// probeTimeout bounds one nature's probe, so a slow platform cannot hold the
// whole request open. Channels and natures are probed concurrently, so this is
// the worst case for the request as a whole, not a per-item cost.
const probeTimeout = 8 * time.Second

// PostSupplyChannelProbe probes the declared natures of the named channels, or
// of every channel when no ids are given. An unknown id is skipped.
func (h *Handler) PostSupplyChannelProbe(c *gin.Context) {
	var body struct {
		IDs []string `json:"ids"`
	}
	// The body is optional: no body at all means "probe everything".
	_ = c.ShouldBindJSON(&body)

	store, errStore := h.supplyChannels()
	if errStore != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	wanted := make(map[string]bool, len(body.IDs))
	for _, id := range body.IDs {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			wanted[trimmed] = true
		}
	}
	channels := store.All()
	selected := make([]supply.Channel, 0, len(channels))
	for _, channel := range channels {
		if len(wanted) > 0 && !wanted[channel.ID] {
			continue
		}
		// A probe must reach the same address the real read will, so a channel
		// that names an exit by id is resolved here rather than read as the
		// address it used to hold.
		selected = append(selected, h.applyEgressIDs(channel))
	}

	ctx := c.Request.Context()
	// The probe reads the named credential, so it runs with the calling session's
	// authority: a session that has not unlocked the store probes nothing.
	vault := sessionVault(c)
	// A probe must take the route the real read will take, so it resolves the
	// same way the provider does: the channel's own exit, else the supply-wide one.
	egress := h.supplyExit()
	probes := make([]gin.H, len(selected))
	var wg sync.WaitGroup
	for i, channel := range selected {
		wg.Go(func() { probes[i] = probeChannel(ctx, channel, vault, egress) })
	}
	wg.Wait()

	c.JSON(http.StatusOK, gin.H{"status": "ok", "probes": probes})
}

// probeChannel probes every nature the channel declares, concurrently.
func probeChannel(ctx context.Context, channel supply.Channel, vault secretstore.Vault, egress string) gin.H {
	natures := map[string]gin.H{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	// Kinds are probed one after the other so that a nature name both kinds
	// declare reports one deterministic result instead of whichever goroutine
	// wins the lock.
	for _, kind := range []supply.Kind{supply.KindEmail, supply.KindPhone} {
		config := channel.KindConfigFor(kind)
		if config == nil {
			continue
		}
		for _, nature := range config.Natures {
			connection := config.Connections[nature]
			wg.Go(func() {
				result := probeNature(ctx, kind, nature, connection, vault, egress)
				mu.Lock()
				natures[string(nature)] = result
				mu.Unlock()
			})
		}
		wg.Wait()
	}
	return gin.H{"id": channel.ID, "natures": natures}
}

// probeNature runs one nature's probe. Only the natures a kind declares are
// ever probed, so an undeclared one never appears in the answer.
func probeNature(ctx context.Context, kind supply.Kind, nature supply.Nature, connection supply.Connection, vault secretstore.Vault, supplyEgress string) gin.H {
	credential, reason := probeCredential(vault, connection.Secret)
	if reason != "" {
		return gin.H{"state": probeUnready, "detail": reason}
	}
	ctxProbe, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	egress := strings.TrimSpace(connection.Egress)
	if egress == "" {
		egress = supplyEgress
	}

	var detail string
	var errProbe error
	switch {
	case kind == supply.KindEmail && nature == supply.NatureIMAP:
		detail, errProbe = email.ProbeIMAP(ctxProbe, connection.Endpoint, connection.Account, credential, egress)
	case kind == supply.KindEmail && nature == supply.NatureOAuth2:
		detail, errProbe = email.ProbeOAuth2(ctxProbe, connection.Endpoint, connection.Account, connection.ClientID, credential, egress)
	case kind == supply.KindEmail && nature == supply.NatureGraph:
		detail, errProbe = email.ProbeGraph(ctxProbe, connection.Account, connection.ClientID, credential, egress)
	case kind == supply.KindPhone && nature == supply.NatureAPI:
		detail, errProbe = phone.ProbeAPI(ctxProbe, connection.Endpoint, credential, egress)
	case kind == supply.KindPhone && nature == supply.NatureWeb:
		detail, errProbe = phone.ProbeWeb(ctxProbe, connection.Endpoint, credential, egress)
	default:
		return gin.H{"state": probeUnsupported}
	}
	if errProbe != nil {
		// A probe that could not even be attempted is not an unreachable
		// channel: the panel reports those as two different states.
		if errors.Is(errProbe, phone.ErrProbeUnready) || errors.Is(errProbe, email.ErrProbeUnready) {
			return gin.H{"state": probeUnready, "detail": errProbe.Error()}
		}
		return gin.H{"state": probeOffline, "detail": errProbe.Error()}
	}
	if detail == "" {
		return gin.H{"state": probeOnline}
	}
	return gin.H{"state": probeOnline, "detail": detail}
}

// probeCredential reads the secret a nature's connection names. A probe is
// read-only, so it never asks for a passphrase; a credential that cannot be
// read reports why, and nothing is sent anywhere.
//
// The reason never repeats the stored value. The field is meant to hold a
// secret-store name, but a channel can be saved with a raw credential in it, and
// an error string is not allowed to be the one place that value escapes.
func probeCredential(vault secretstore.Vault, name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "no credential is named for this nature"
	}
	value, errGet := vault.Get(name)
	if errGet != nil {
		if errors.Is(errGet, secretstore.ErrNotFound) {
			return "", "the named credential is not in the store"
		}
		if errors.Is(errGet, secretstore.ErrLocked) || errors.Is(errGet, secretstore.ErrUnauthorized) {
			return "", "the secret store is locked"
		}
		return "", "the named credential cannot be read"
	}
	return value, ""
}

// emailProbeLimit caps how many addresses one request may probe. Each address
// costs one mailbox session, so the cap is what keeps a page-wide probe from
// turning into an unbounded burst of logins.
const emailProbeLimit = 40

// emailProbeTimeout bounds one address's probe, waiting for a free session
// included. A probe that hangs therefore holds its worker, not the request.
const emailProbeTimeout = 15 * time.Second

// PostSupplyEmailProbe answers "can the mailbox that receives this address be
// opened right now", for one address or a batch.
//
// It exists because an identity that carries its own credential has no channel
// to probe: asking a channel about it would answer about a different mailbox.
// The answer is per address rather than per mailbox, because the caller asked
// about addresses — a catch-all domain has many of them behind one mailbox.
func (h *Handler) PostSupplyEmailProbe(c *gin.Context) {
	var body struct {
		Addresses []string `json:"addresses"`
	}
	// The body is required: with no address there is nothing to probe, and
	// answering "everything is fine" would be a lie about an empty question.
	_ = c.ShouldBindJSON(&body)

	provider, errProvider := emailProvider()
	if errProvider != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "error",
			"error":  "no email mailbox is configured",
			"code":   "email_unavailable",
		})
		return
	}
	addresses := make([]string, 0, len(body.Addresses))
	seen := make(map[string]bool, len(body.Addresses))
	for _, raw := range body.Addresses {
		address := strings.TrimSpace(raw)
		if address == "" {
			continue
		}
		key := strings.ToLower(address)
		if seen[key] {
			continue
		}
		seen[key] = true
		addresses = append(addresses, address)
		if len(addresses) == emailProbeLimit {
			break
		}
	}
	if len(addresses) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "no address to probe",
			"code":   "address_required",
		})
		return
	}

	ctx := c.Request.Context()
	probes := make([]gin.H, len(addresses))
	var wg sync.WaitGroup
	for i, address := range addresses {
		wg.Go(func() {
			ctxProbe, cancel := context.WithTimeout(ctx, emailProbeTimeout)
			defer cancel()
			detail, errProbe := provider.ProbeAddress(ctxProbe, address)
			probes[i] = addressProbeView(address, detail, errProbe)
		})
	}
	wg.Wait()

	c.JSON(http.StatusOK, gin.H{"status": "ok", "probes": probes})
}

// addressProbeView turns one address's outcome into the panel's vocabulary.
func addressProbeView(address, detail string, errProbe error) gin.H {
	view := gin.H{"address": address}
	switch {
	case errProbe == nil:
		view["state"] = probeOnline
		if detail != "" {
			view["detail"] = detail
		}
	case errors.Is(errProbe, email.ErrLoginRejected):
		// The credential was read and the mailbox refused it: this address
		// cannot receive mail until the credential is replaced.
		view["state"] = probeOffline
		view["detail"] = errProbe.Error()
	case errors.Is(errProbe, email.ErrProbeUnready), errors.Is(errProbe, email.ErrCredential):
		// Nothing was attempted, so nothing can be concluded about reachability.
		// Reporting this as offline would send the operator looking for a network
		// fault that does not exist.
		view["state"] = probeUnready
		view["detail"] = errProbe.Error()
	case errors.Is(errProbe, supply.ErrUnknownIdentity):
		// No mailbox receives this address, so it can never be used: that is a
		// real failure, not an untried one.
		view["state"] = probeOffline
		view["detail"] = "no configured mailbox receives this address"
	default:
		view["state"] = probeOffline
		view["detail"] = errProbe.Error()
	}
	return view
}
