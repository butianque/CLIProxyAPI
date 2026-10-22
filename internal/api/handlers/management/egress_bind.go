package management

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// This file is where a binding is made: one exit, one target, one write.
//
// It exists because the pool is not an address book. Assigning an exit by hand
// in every place an exit can be named does not scale past a handful of accounts,
// and it cannot be automated: a signup that finishes at 3am cannot wait for
// somebody to open a dropdown. Automation calls this, the panel calls this, and
// both end up writing the same durable reference.
//
// Only an id is written. The address is never copied into the target, because a
// copy is what makes replacing an exit an N-place edit.

// egressBindRequest is one binding request.
type egressBindRequest struct {
	// Kind is "account" or "channel".
	Kind string `json:"kind"`
	// Name is the auth file name (or auth id) for an account, the channel id for
	// a channel.
	Name string `json:"name"`
	// SupplyKind narrows a channel to "email" or "phone". Empty means "whichever
	// block exists".
	SupplyKind string `json:"supply_kind"`
	// Nature narrows a channel to one connection ("imap", "graph", "api", ...).
	// Empty means every nature the channel declares.
	Nature string `json:"nature"`
}

// PostEgressPoolBind points one target at one exit.
func (h *Handler) PostEgressPoolBind(c *gin.Context) {
	id, errID := egressPathID(c)
	if errID != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errID.Error()})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	entry, found := pool.Get(id)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "no such exit"})
		return
	}

	var body egressBindRequest
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	bound, errApply := h.applyEgressBinding(c, entry.ID, body)
	if errApply != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errApply.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "bound": bound, "exit": egressEntryView(entry)})
}

// PostEgressPoolUnbind releases one target from whatever exit it names.
//
// The address stored beside the id is cleared too. Keeping it would mean an
// account that was just released from a burnt exit quietly fell back to that
// same burnt address, which reads as "unbound" in the panel and behaves as
// "still on the old exit" on the wire.
func (h *Handler) PostEgressPoolUnbind(c *gin.Context) {
	var body egressBindRequest
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	bound, errApply := h.applyEgressBinding(c, 0, body)
	if errApply != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errApply.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "released": bound})
}

// applyEgressBinding writes the reference, or clears it when id is zero.
func (h *Handler) applyEgressBinding(c *gin.Context, id int, body egressBindRequest) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(body.Kind)) {
	case "account":
		name, errBind := h.bindAccountEgress(c, id, body.Name)
		if errBind != nil {
			return nil, errBind
		}
		return []string{name}, nil
	case "channel":
		return h.bindChannelEgress(id, body)
	case "":
		return nil, fmt.Errorf("kind is required (account or channel)")
	default:
		return nil, fmt.Errorf("unknown kind %q: expected account or channel", body.Kind)
	}
}

// bindAccountEgress sets or clears one credential's exit.
func (h *Handler) bindAccountEgress(c *gin.Context, id int, rawName string) (string, error) {
	if h.authManager == nil {
		return "", fmt.Errorf("core auth manager unavailable")
	}
	name := strings.TrimSpace(rawName)
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	target, errFind := h.findAuthForBinding(name)
	if errFind != nil {
		return "", errFind
	}
	if coreauth.IsPluginVirtualAuth(target) {
		return "", errPluginVirtualAuth
	}
	if target.Metadata == nil {
		target.Metadata = make(map[string]any)
	}
	if id > 0 {
		target.Metadata["egress_id"] = id
		// Take effect now rather than at the next reload, but only with an
		// address that actually resolved: writing the unresolved marker into
		// the in-memory credential would make the account unusable until the
		// pool is fixed, when the id alone already fails closed on its own.
		if url := sdkAuth.ResolveEgressID(id); url != sdkAuth.UnresolvedEgress {
			target.ProxyURL = url
		}
	} else {
		delete(target.Metadata, "egress_id")
		target.ProxyURL = ""
	}
	// The id is what every load resolves; the address beside it is what a
	// plugin executor dials, because it builds its own transports and can only
	// learn the exit from metadata. Keep the pair in step, so a credential is
	// never bound on paper while its traffic falls back to the host's address.
	if target.ProxyURL != "" {
		target.Metadata["proxy_url"] = target.ProxyURL
	} else {
		delete(target.Metadata, "proxy_url")
	}
	target.UpdatedAt = time.Now()
	updated, errUpdate := h.authManager.Update(c.Request.Context(), target)
	if errUpdate != nil {
		return "", fmt.Errorf("failed to update auth: %w", errUpdate)
	}
	if h.postAuthPersistHook != nil {
		hookAuth := updated
		if hookAuth == nil {
			hookAuth = target
		}
		if errHook := h.postAuthPersistHook(c.Request.Context(), hookAuth); errHook != nil {
			return "", fmt.Errorf("post-auth persist hook failed: %w", errHook)
		}
	}
	return target.FileName, nil
}

// findAuthForBinding resolves an auth by id or by file name.
func (h *Handler) findAuthForBinding(name string) (*coreauth.Auth, error) {
	if auth, ok := h.authManager.GetByID(name); ok {
		return auth, nil
	}
	for _, auth := range h.authManager.List() {
		if auth != nil && auth.FileName == name {
			return auth, nil
		}
	}
	return nil, fmt.Errorf("no account named %q", name)
}

// bindChannelEgress sets or clears one channel connection's exit.
func (h *Handler) bindChannelEgress(id int, body egressBindRequest) ([]string, error) {
	channelID := strings.TrimSpace(body.Name)
	if channelID == "" {
		return nil, fmt.Errorf("name is required")
	}
	store, errStore := h.supplyChannels()
	if errStore != nil {
		return nil, errStore
	}
	channel, found := store.Get(channelID)
	if !found {
		return nil, fmt.Errorf("no channel named %q", channelID)
	}
	wantedKind := supply.Kind(strings.ToLower(strings.TrimSpace(body.SupplyKind)))
	wantedNature := supply.Nature(strings.ToLower(strings.TrimSpace(body.Nature)))

	var bound []string
	for _, kind := range channel.Kinds() {
		if wantedKind != "" && kind != wantedKind {
			continue
		}
		block := channel.KindConfigFor(kind)
		if block == nil {
			continue
		}
		for nature, connection := range block.Connections {
			if wantedNature != "" && nature != wantedNature {
				continue
			}
			if id > 0 {
				connection.EgressID = id
			} else {
				connection.EgressID = 0
				// Clearing both is deliberate: an empty address means "inherit
				// the supply-wide exit", while a stale one would keep this
				// channel on the exit it was just released from.
				connection.Egress = ""
			}
			block.Connections[nature] = connection
			bound = append(bound, string(kind)+"/"+string(nature))
		}
	}
	if len(bound) == 0 {
		return nil, fmt.Errorf("channel %q declares no connection to bind", channelID)
	}
	if _, errSave := store.Upsert(channel, time.Now().Unix()); errSave != nil {
		return nil, errSave
	}
	return bound, nil
}
