package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

// callHostRoutingResetCooldown clears quota and cooldown routing state for one credential, the
// same reset POST /v8/management/routing/cooldown/reset performs, while ensuring token files are left alone.
func (h *Host) callHostRoutingResetCooldown(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostRoutingResetCooldownRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host routing reset cooldown request: %w", errUnmarshal)
	}
	authIndex := strings.TrimSpace(req.AuthIndex)
	auth, errGet := h.authByIndex(authIndex)
	if errGet != nil {
		return nil, errGet
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, fmt.Errorf("core auth manager unavailable")
	}
	resetCtx := coreauth.WithSkipPersist(ctx)
	updated, models, errReset := manager.ResetQuota(resetCtx, auth.ID)
	if errReset != nil {
		return nil, fmt.Errorf("reset cooldown: %w", errReset)
	}
	if updated == nil {
		return nil, fmt.Errorf("auth not found for auth_index %s", authIndex)
	}
	updated.EnsureIndex()
	log.WithFields(log.Fields{
		"plugin_id":  hostCallbackPluginIDFromContext(ctx),
		"auth_index": updated.Index,
		"models":     len(models),
	}).Info("pluginhost: plugin reset credential cooldown")
	return marshalRPCResult(pluginapi.HostRoutingResetCooldownResponse{
		AuthIndex: updated.Index,
		Models:    models,
	})
}

// callHostRoutingSetCooldown records a cooldown deadline a plugin learned from a
// provider. The plugin supplies the deadline and the host owns the routing
// decision, so the two cannot drift into separate clocks.
func (h *Host) callHostRoutingSetCooldown(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostRoutingSetCooldownRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host routing set cooldown request: %w", errUnmarshal)
	}
	authIndex := strings.TrimSpace(req.AuthIndex)
	auth, errGet := h.authByIndex(authIndex)
	if errGet != nil {
		return nil, errGet
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, fmt.Errorf("core auth manager unavailable")
	}
	until, errDeadline := cooldownDeadline(req)
	if errDeadline != nil {
		return nil, errDeadline
	}
	setCtx := coreauth.WithSkipPersist(ctx)
	updated, models, effective, errSet := manager.SetCooldown(setCtx, auth.ID, req.Model, until, req.Reason)
	if errSet != nil {
		return nil, fmt.Errorf("set cooldown: %w", errSet)
	}
	if updated == nil {
		return nil, fmt.Errorf("auth not found for auth_index %s", authIndex)
	}
	updated.EnsureIndex()
	cooldownUntil := ""
	if !effective.IsZero() {
		cooldownUntil = effective.UTC().Format(time.RFC3339)
	}
	log.WithFields(log.Fields{
		"plugin_id":      hostCallbackPluginIDFromContext(ctx),
		"auth_index":     updated.Index,
		"models":         len(models),
		"cooldown_until": cooldownUntil,
	}).Info("pluginhost: plugin set credential cooldown")
	return marshalRPCResult(pluginapi.HostRoutingSetCooldownResponse{
		AuthIndex:     updated.Index,
		Models:        models,
		CooldownUntil: cooldownUntil,
	})
}

// cooldownDeadline resolves the deadline a plugin asked for. Exactly one form may
// be set: accepting both would let a caller contradict itself, and quietly
// preferring one is how two clocks start disagreeing.
func cooldownDeadline(req pluginapi.HostRoutingSetCooldownRequest) (time.Time, error) {
	raw := strings.TrimSpace(req.CooldownUntil)
	switch {
	case raw != "" && req.RetryAfterSeconds != 0:
		return time.Time{}, fmt.Errorf("cooldown_until and retry_after_seconds are mutually exclusive")
	case raw == "" && req.RetryAfterSeconds == 0:
		return time.Time{}, fmt.Errorf("cooldown_until or retry_after_seconds is required")
	case raw != "":
		parsed, errParse := time.Parse(time.RFC3339, raw)
		if errParse != nil {
			return time.Time{}, fmt.Errorf("parse cooldown_until: %w", errParse)
		}
		return parsed, nil
	case req.RetryAfterSeconds < 0:
		return time.Time{}, fmt.Errorf("retry_after_seconds must be positive")
	default:
		return time.Now().Add(time.Duration(req.RetryAfterSeconds) * time.Second), nil
	}
}
