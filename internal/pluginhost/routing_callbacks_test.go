package pluginhost

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

type recordingTokenStore struct {
	saveCalls int
}

func (s *recordingTokenStore) List(ctx context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (s *recordingTokenStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	s.saveCalls++
	return auth.ID, nil
}
func (s *recordingTokenStore) Delete(ctx context.Context, id string) error { return nil }

func TestHostRoutingResetCooldownClearsCredentialCooldown(t *testing.T) {
	const model = "claude-sonnet-5-5"
	next := time.Now().Add(65 * time.Hour)
	auth := &coreauth.Auth{
		ID:             "claude-a.json",
		Provider:       "claude",
		FileName:       "claude-a.json",
		Status:         coreauth.StatusError,
		StatusMessage:  "quota exhausted",
		Unavailable:    true,
		NextRetryAfter: next,
		Quota:          coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: next, BackoffLevel: 1},
		ModelStates: map[string]*coreauth.ModelState{
			model: {
				Status:         coreauth.StatusError,
				Unavailable:    true,
				NextRetryAfter: next,
				Quota:          coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: next, BackoffLevel: 1},
				UpdatedAt:      time.Now(),
			},
		},
	}
	auth.EnsureIndex()

	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	if held, _ := manager.GetByID(auth.ID); held == nil || !held.Quota.Exceeded || !held.Unavailable {
		t.Fatalf("registered auth = %+v, want a held credential_quota cooldown", held)
	}

	request, errMarshal := json.Marshal(pluginapi.HostRoutingResetCooldownRequest{AuthIndex: auth.Index})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	rawResp, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingResetCooldown, request)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	resp, errDecode := decodeRPCEnvelope[pluginapi.HostRoutingResetCooldownResponse](rawResp)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if resp.AuthIndex != auth.Index {
		t.Fatalf("auth_index = %q, want %q", resp.AuthIndex, auth.Index)
	}
	if len(resp.Models) != 1 || resp.Models[0] != model {
		t.Fatalf("models = %v, want [%s]", resp.Models, model)
	}

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("auth %s missing after reset", auth.ID)
	}
	if updated.Status != coreauth.StatusActive || updated.Unavailable || !updated.NextRetryAfter.IsZero() {
		t.Fatalf("auth state = status %q unavailable %v next %v, want active and available", updated.Status, updated.Unavailable, updated.NextRetryAfter)
	}
	if updated.Quota.Exceeded || updated.Quota.Reason != "" || !updated.Quota.NextRecoverAt.IsZero() {
		t.Fatalf("auth quota = %+v, want cleared", updated.Quota)
	}
	state := updated.ModelStates[model]
	if state == nil || state.Unavailable || !state.NextRetryAfter.IsZero() || state.Quota.Exceeded {
		t.Fatalf("model state = %+v, want cleared", state)
	}
}

func TestHostRoutingResetCooldownLeavesTokenFilesAlone(t *testing.T) {
	const model = "claude-sonnet-5-5"
	next := time.Now().Add(48 * time.Hour)
	auth := &coreauth.Auth{
		ID:             "claude-token-test.json",
		Provider:       "claude",
		FileName:       "claude-token-test.json",
		Status:         coreauth.StatusError,
		StatusMessage:  "quota exhausted",
		Unavailable:    true,
		NextRetryAfter: next,
		Quota:          coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: next, BackoffLevel: 1},
		Metadata: map[string]any{
			"account_id": "claude-seat-123",
		},
		ModelStates: map[string]*coreauth.ModelState{
			model: {
				Status:         coreauth.StatusError,
				Unavailable:    true,
				NextRetryAfter: next,
				Quota:          coreauth.QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: next, BackoffLevel: 1},
				UpdatedAt:      time.Now(),
			},
		},
	}
	auth.EnsureIndex()

	store := &recordingTokenStore{}
	manager := coreauth.NewManager(store, nil, nil)
	host := New()
	host.SetAuthManager(manager)

	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	// Reset recorded save calls from registration
	store.saveCalls = 0

	request, errMarshal := json.Marshal(pluginapi.HostRoutingResetCooldownRequest{AuthIndex: auth.Index})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	rawResp, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingResetCooldown, request)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	resp, errDecode := decodeRPCEnvelope[pluginapi.HostRoutingResetCooldownResponse](rawResp)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if resp.AuthIndex != auth.Index {
		t.Fatalf("auth_index = %q, want %q", resp.AuthIndex, auth.Index)
	}

	// Verify token store Save was NOT called (token files left alone)
	if store.saveCalls != 0 {
		t.Fatalf("token store Save was called %d times during cooldown reset, want 0", store.saveCalls)
	}

	// Verify cooldown was still reset in memory
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("auth %s missing after reset", auth.ID)
	}
	if updated.Unavailable || updated.Quota.Exceeded {
		t.Fatalf("auth quota state = %+v, unavailable=%v; want cooldown cleared", updated.Quota, updated.Unavailable)
	}
}

func TestHostRoutingResetCooldownRejectsUnknownAuthIndex(t *testing.T) {
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))

	for _, authIndex := range []string{"", "missing"} {
		request, errMarshal := json.Marshal(pluginapi.HostRoutingResetCooldownRequest{AuthIndex: authIndex})
		if errMarshal != nil {
			t.Fatalf("marshal request: %v", errMarshal)
		}
		if _, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingResetCooldown, request); errCall == nil {
			t.Fatalf("callFromPlugin(%q) error = nil, want error", authIndex)
		}
	}
}

func TestHostRoutingResetCooldownRejectsInvalidJSON(t *testing.T) {
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))

	if _, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingResetCooldown, []byte("{invalid-json")); errCall == nil {
		t.Fatal("expected error on invalid JSON request, got nil")
	}
}

func TestHostRoutingResetCooldownRequiresAuthManager(t *testing.T) {
	host := New()
	host.SetAuthManager(nil)

	request, errMarshal := json.Marshal(pluginapi.HostRoutingResetCooldownRequest{AuthIndex: "any"})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	if _, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingResetCooldown, request); errCall == nil {
		t.Fatal("expected error when auth manager is unavailable, got nil")
	}
}

func TestHostRoutingResetCooldownLogsPluginID(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()

	auth := &coreauth.Auth{
		ID:          "claude-log-test.json",
		Provider:    "claude",
		FileName:    "claude-log-test.json",
		Status:      coreauth.StatusActive,
		ModelStates: map[string]*coreauth.ModelState{},
	}
	auth.EnsureIndex()

	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	request, errMarshal := json.Marshal(pluginapi.HostRoutingResetCooldownRequest{AuthIndex: auth.Index})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}

	pluginCtx := withHostCallbackPluginID(context.Background(), "claude-seat-pacer")
	if _, errCall := host.callFromPlugin(pluginCtx, pluginabi.MethodHostRoutingResetCooldown, request); errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}

	found := false
	for _, entry := range hook.AllEntries() {
		if entry.Level == log.InfoLevel && strings.Contains(entry.Message, "plugin reset credential cooldown") {
			if entry.Data["plugin_id"] == "claude-seat-pacer" && entry.Data["auth_index"] == auth.Index {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("expected info log entry with plugin_id=claude-seat-pacer and auth_index=%s, got entries: %+v", auth.Index, hook.AllEntries())
	}
}

func TestHostRoutingSetCooldownCoolsOneModel(t *testing.T) {
	const model = "claude-sonnet-5-5"
	auth := &coreauth.Auth{
		ID:       "claude-set-model.json",
		Provider: "claude",
		FileName: "claude-set-model.json",
		Status:   coreauth.StatusActive,
		ModelStates: map[string]*coreauth.ModelState{
			model: {Status: coreauth.StatusActive, UpdatedAt: time.Now()},
		},
	}
	auth.EnsureIndex()

	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	until := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	request, errMarshal := json.Marshal(pluginapi.HostRoutingSetCooldownRequest{
		AuthIndex:     auth.Index,
		Model:         model,
		CooldownUntil: until.Format(time.RFC3339),
		Reason:        "rate_limit",
	})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	rawResp, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingSetCooldown, request)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	resp, errDecode := decodeRPCEnvelope[pluginapi.HostRoutingSetCooldownResponse](rawResp)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	if resp.AuthIndex != auth.Index || len(resp.Models) != 1 || resp.Models[0] != model {
		t.Fatalf("response = %+v, want auth %s cooling [%s]", resp, auth.Index, model)
	}
	reported, errParse := time.Parse(time.RFC3339, resp.CooldownUntil)
	if errParse != nil || !reported.Equal(until) {
		t.Fatalf("cooldown_until = %q, want %s", resp.CooldownUntil, until.Format(time.RFC3339))
	}

	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("auth %s missing after set cooldown", auth.ID)
	}
	state := updated.ModelStates[model]
	if state == nil || !state.Unavailable || state.Status != coreauth.StatusError {
		t.Fatalf("model state = %+v, want unavailable with error status", state)
	}
	if !state.NextRetryAfter.Equal(until) {
		t.Fatalf("model next retry = %s, want %s", state.NextRetryAfter, until)
	}
	if !state.Quota.Exceeded || !state.Quota.NextRecoverAt.Equal(until) {
		t.Fatalf("model quota = %+v, want exceeded until %s", state.Quota, until)
	}
}

func TestHostRoutingSetCooldownCoolsWholeCredential(t *testing.T) {
	const model = "claude-sonnet-5-5"
	next := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)

	// A credential with no model state must keep the credential-level cooldown;
	// aggregation must not read "no models" as "nothing is down" and clear it.
	bare := &coreauth.Auth{
		ID:       "claude-set-bare.json",
		Provider: "claude",
		FileName: "claude-set-bare.json",
		Status:   coreauth.StatusActive,
	}
	bare.EnsureIndex()

	withModels := &coreauth.Auth{
		ID:       "claude-set-scope.json",
		Provider: "claude",
		FileName: "claude-set-scope.json",
		Status:   coreauth.StatusActive,
		ModelStates: map[string]*coreauth.ModelState{
			model: {Status: coreauth.StatusActive, UpdatedAt: time.Now()},
		},
	}
	withModels.EnsureIndex()

	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	for _, auth := range []*coreauth.Auth{bare, withModels} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register auth %s: %v", auth.ID, errRegister)
		}
		request, errMarshal := json.Marshal(pluginapi.HostRoutingSetCooldownRequest{
			AuthIndex:     auth.Index,
			CooldownUntil: next.Format(time.RFC3339),
		})
		if errMarshal != nil {
			t.Fatalf("marshal request: %v", errMarshal)
		}
		if _, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingSetCooldown, request); errCall != nil {
			t.Fatalf("callFromPlugin(%s) error = %v", auth.ID, errCall)
		}

		updated, ok := manager.GetByID(auth.ID)
		if !ok || updated == nil {
			t.Fatalf("auth %s missing after set cooldown", auth.ID)
		}
		if !updated.Unavailable || !updated.NextRetryAfter.Equal(next) {
			t.Fatalf("auth %s = unavailable %v next %s, want unavailable until %s", auth.ID, updated.Unavailable, updated.NextRetryAfter, next)
		}
		if !updated.Quota.Exceeded || updated.Quota.Reason != "credential_quota" || !updated.Quota.NextRecoverAt.Equal(next) {
			t.Fatalf("auth %s quota = %+v, want credential_quota until %s", auth.ID, updated.Quota, next)
		}
	}
	updated, _ := manager.GetByID(withModels.ID)
	state := updated.ModelStates[model]
	if state == nil || !state.Unavailable || !state.NextRetryAfter.Equal(next) || state.Quota.Reason != "credential_quota" {
		t.Fatalf("model state = %+v, want a propagated credential cooldown until %s", state, next)
	}
}

func TestHostRoutingSetCooldownNeverShortensLiveDeadline(t *testing.T) {
	const model = "claude-sonnet-5-5"
	held := time.Now().Add(5 * time.Hour).UTC().Truncate(time.Second)
	auth := &coreauth.Auth{
		ID:             "claude-set-long.json",
		Provider:       "claude",
		FileName:       "claude-set-long.json",
		Status:         coreauth.StatusError,
		Unavailable:    true,
		NextRetryAfter: held,
		Quota:          coreauth.QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: held},
		ModelStates: map[string]*coreauth.ModelState{
			model: {
				Status:         coreauth.StatusError,
				Unavailable:    true,
				NextRetryAfter: held,
				Quota:          coreauth.QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: held},
				UpdatedAt:      time.Now(),
			},
		},
	}
	auth.EnsureIndex()

	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	sooner := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	request, errMarshal := json.Marshal(pluginapi.HostRoutingSetCooldownRequest{
		AuthIndex:     auth.Index,
		Model:         model,
		CooldownUntil: sooner.Format(time.RFC3339),
	})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	rawResp, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingSetCooldown, request)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	resp, errDecode := decodeRPCEnvelope[pluginapi.HostRoutingSetCooldownResponse](rawResp)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	reported, errParse := time.Parse(time.RFC3339, resp.CooldownUntil)
	if errParse != nil || !reported.Equal(held) {
		t.Fatalf("cooldown_until = %q, want the live deadline %s", resp.CooldownUntil, held.Format(time.RFC3339))
	}
	updated, _ := manager.GetByID(auth.ID)
	if state := updated.ModelStates[model]; state == nil || !state.NextRetryAfter.Equal(held) {
		t.Fatalf("model state = %+v, want the longer deadline %s kept", state, held)
	}
}

func TestHostRoutingSetCooldownRejectsUnusableDeadlines(t *testing.T) {
	auth := &coreauth.Auth{
		ID:          "claude-set-reject.json",
		Provider:    "claude",
		FileName:    "claude-set-reject.json",
		Status:      coreauth.StatusActive,
		ModelStates: map[string]*coreauth.ModelState{},
	}
	auth.EnsureIndex()

	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	for _, tt := range []struct {
		name string
		req  pluginapi.HostRoutingSetCooldownRequest
	}{
		{name: "no deadline", req: pluginapi.HostRoutingSetCooldownRequest{AuthIndex: auth.Index}},
		{
			name: "both forms",
			req: pluginapi.HostRoutingSetCooldownRequest{
				AuthIndex:         auth.Index,
				CooldownUntil:     time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				RetryAfterSeconds: 60,
			},
		},
		{name: "past deadline", req: pluginapi.HostRoutingSetCooldownRequest{AuthIndex: auth.Index, CooldownUntil: past}},
		{name: "negative delay", req: pluginapi.HostRoutingSetCooldownRequest{AuthIndex: auth.Index, RetryAfterSeconds: -1}},
		{name: "unparseable deadline", req: pluginapi.HostRoutingSetCooldownRequest{AuthIndex: auth.Index, CooldownUntil: "tomorrow"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			request, errMarshal := json.Marshal(tt.req)
			if errMarshal != nil {
				t.Fatalf("marshal request: %v", errMarshal)
			}
			if _, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingSetCooldown, request); errCall == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}

	// A rejected request must leave the credential alone.
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("auth %s missing", auth.ID)
	}
	if updated.Unavailable || updated.Quota.Exceeded {
		t.Fatalf("auth = unavailable %v quota %+v, want untouched", updated.Unavailable, updated.Quota)
	}
}

func TestHostRoutingSetCooldownClampsAnImplausibleDeadline(t *testing.T) {
	const model = "claude-sonnet-5-5"
	auth := &coreauth.Auth{
		ID:       "claude-set-clamp.json",
		Provider: "claude",
		FileName: "claude-set-clamp.json",
		Status:   coreauth.StatusActive,
		ModelStates: map[string]*coreauth.ModelState{
			model: {Status: coreauth.StatusActive, UpdatedAt: time.Now()},
		},
	}
	auth.EnsureIndex()

	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	// A provider value read in the wrong unit must not park the credential for
	// years, so the host caps what a caller can state.
	request, errMarshal := json.Marshal(pluginapi.HostRoutingSetCooldownRequest{
		AuthIndex:     auth.Index,
		Model:         model,
		CooldownUntil: time.Now().Add(400 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	rawResp, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingSetCooldown, request)
	if errCall != nil {
		t.Fatalf("callFromPlugin() error = %v", errCall)
	}
	resp, errDecode := decodeRPCEnvelope[pluginapi.HostRoutingSetCooldownResponse](rawResp)
	if errDecode != nil {
		t.Fatalf("decode response: %v", errDecode)
	}
	reported, errParse := time.Parse(time.RFC3339, resp.CooldownUntil)
	if errParse != nil {
		t.Fatalf("parse cooldown_until: %v", errParse)
	}
	if remaining := time.Until(reported); remaining > 32*24*time.Hour || remaining < 30*24*time.Hour {
		t.Fatalf("cooldown until %s (%s away), want it capped near 31 days", reported, remaining)
	}
}

func TestHostRoutingSetCooldownRejectsUnknownAuthIndex(t *testing.T) {
	host := New()
	host.SetAuthManager(coreauth.NewManager(nil, nil, nil))

	for _, authIndex := range []string{"", "missing"} {
		request, errMarshal := json.Marshal(pluginapi.HostRoutingSetCooldownRequest{
			AuthIndex:         authIndex,
			RetryAfterSeconds: 60,
		})
		if errMarshal != nil {
			t.Fatalf("marshal request: %v", errMarshal)
		}
		if _, errCall := host.callFromPlugin(context.Background(), pluginabi.MethodHostRoutingSetCooldown, request); errCall == nil {
			t.Fatalf("callFromPlugin(%q) error = nil, want error", authIndex)
		}
	}
}
