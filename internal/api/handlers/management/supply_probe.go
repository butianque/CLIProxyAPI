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
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/phone"
)

// This file is the channel probe surface: the panel's "is this channel actually
// reachable" question, answered with one cheap authenticated call per declared
// nature.
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
		selected = append(selected, channel)
	}

	ctx := c.Request.Context()
	probes := make([]gin.H, len(selected))
	var wg sync.WaitGroup
	for i, channel := range selected {
		wg.Go(func() { probes[i] = probeChannel(ctx, channel) })
	}
	wg.Wait()

	c.JSON(http.StatusOK, gin.H{"status": "ok", "probes": probes})
}

// probeChannel probes every nature the channel declares, concurrently.
func probeChannel(ctx context.Context, channel supply.Channel) gin.H {
	natures := map[string]gin.H{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	// The phone kind is probed last so that a nature both kinds declare reports
	// the phone result: the email kind has no probe yet, and its "unsupported"
	// would otherwise hide a reachable phone connection behind the same name.
	// Waiting between the two kinds is what makes that order hold — launching
	// both together would let whichever goroutine wins the lock decide.
	for _, kind := range []supply.Kind{supply.KindEmail, supply.KindPhone} {
		config := channel.KindConfigFor(kind)
		if config == nil {
			continue
		}
		for _, nature := range config.Natures {
			connection := config.Connections[nature]
			wg.Go(func() {
				result := probeNature(ctx, kind, nature, connection)
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
func probeNature(ctx context.Context, kind supply.Kind, nature supply.Nature, connection supply.Connection) gin.H {
	// The email kind has no probe yet: IMAP is not implemented in the base, so
	// the honest answer is "unsupported" rather than a failure.
	if kind != supply.KindPhone {
		return gin.H{"state": probeUnsupported}
	}
	credential, reason := probeCredential(connection.Secret)
	if reason != "" {
		return gin.H{"state": probeUnready, "detail": reason}
	}
	ctxProbe, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	var detail string
	var errProbe error
	switch nature {
	case supply.NatureAPI:
		detail, errProbe = phone.ProbeAPI(ctxProbe, connection.Endpoint, credential)
	case supply.NatureWeb:
		detail, errProbe = phone.ProbeWeb(ctxProbe, connection.Endpoint, credential)
	default:
		return gin.H{"state": probeUnsupported}
	}
	if errProbe != nil {
		// A probe that could not even be attempted is not an unreachable
		// channel: the panel reports those as two different states.
		if errors.Is(errProbe, phone.ErrProbeUnready) {
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
func probeCredential(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "no credential is named for this nature"
	}
	store := secretstore.Default()
	if store == nil || !store.Unlocked() {
		return "", "the secret store is locked"
	}
	value, errGet := store.Get(name)
	if errGet != nil {
		if errors.Is(errGet, secretstore.ErrNotFound) {
			return "", "the named credential is not in the store"
		}
		return "", "the named credential cannot be read"
	}
	return value, ""
}
