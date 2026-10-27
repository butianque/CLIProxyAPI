package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func listAccounts(t *testing.T, h *Handler, target string) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, target, nil)
	h.ListAccounts(ginCtx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: status=%d body=%s", target, recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(recorder.Body.Bytes(), &payload); errUnmarshal != nil {
		t.Fatalf("failed to decode payload: %v", errUnmarshal)
	}
	return payload
}

func accountList(t *testing.T, payload map[string]any) []map[string]any {
	t.Helper()
	raw, ok := payload["accounts"].([]any)
	if !ok {
		t.Fatalf("expected accounts array, got %#v", payload["accounts"])
	}
	out := make([]map[string]any, 0, len(raw))
	for index, item := range raw {
		account, okAccount := item.(map[string]any)
		if !okAccount {
			t.Fatalf("expected account object at %d, got %#v", index, item)
		}
		out = append(out, account)
	}
	return out
}

// TestListAccountsReportsUnknownAsAbsent is the contract's rule 2: a value the
// host cannot determine is omitted or null, never reported as zero or false.
func TestListAccountsReportsUnknownAsAbsent(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	manager := coreauth.NewManager(nil, nil, nil)
	pinnedPolicy := pluginapi.AccountPolicyOnly("start-plan")
	record := &coreauth.Auth{
		ID:       "zcode-1",
		FileName: "zcode-1.json",
		Provider: "zcode",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"policy": pinnedPolicy},
		Success:  7,
		Failed:   2,
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}

	accounts := accountList(t, listAccounts(t, h, "/v8/management/accounts"))
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accounts))
	}
	account := accounts[0]

	if account["provider"] != "zcode" {
		t.Fatalf("provider = %#v", account["provider"])
	}
	if account["policy"] != pinnedPolicy {
		t.Fatalf("policy = %#v", account["policy"])
	}
	if account["manually_disabled"] != false {
		t.Fatalf("manually_disabled = %#v", account["manually_disabled"])
	}
	if account["request_count"] != float64(9) || account["success_count"] != float64(7) || account["failure_count"] != float64(2) {
		t.Fatalf("request counters = %#v", account)
	}

	// No quota snapshot exists, so the state is unknown and no timestamp claims
	// otherwise.
	if account["quota_state"] != pluginapi.QuotaStateUnknown {
		t.Fatalf("quota_state = %#v, want %s", account["quota_state"], pluginapi.QuotaStateUnknown)
	}
	if _, present := account["fetched_at"]; present {
		t.Fatalf("fetched_at must be absent without a snapshot, got %#v", account["fetched_at"])
	}
	// The plugin has not declared whether the credential can refresh, so the
	// field is present and explicitly null rather than a false claim.
	supportsRefresh, present := account["supports_refresh"]
	if !present || supportsRefresh != nil {
		t.Fatalf("supports_refresh = %#v (present=%v), want an explicit null", supportsRefresh, present)
	}
	// A failure with no last error carries no class.
	if _, present := account["failure_class"]; present {
		t.Fatalf("failure_class must be absent without a failure, got %#v", account["failure_class"])
	}

	// Every heatmap bucket reports its rate as null, because no bucket saw a
	// request; a rate of zero would claim every request failed.
	heatmap, ok := account["heatmap"].([]any)
	if !ok || len(heatmap) == 0 {
		t.Fatalf("expected heatmap buckets, got %#v", account["heatmap"])
	}
	for index, item := range heatmap {
		bucket, okBucket := item.(map[string]any)
		if !okBucket {
			t.Fatalf("expected heatmap bucket at %d, got %#v", index, item)
		}
		if label, okLabel := bucket["bucket"].(string); !okLabel || label == "" {
			t.Fatalf("heatmap bucket %d has no label: %#v", index, bucket)
		}
		if rate, present := bucket["success_rate"]; !present || rate != nil {
			t.Fatalf("heatmap bucket %d success_rate = %#v (present=%v), want null", index, rate, present)
		}
	}

	counts, ok := account["counts"].(map[string]any)
	if ok {
		t.Fatalf("counts must not be nested in an account, got %#v", counts)
	}
}

func TestListAccountsReportsTheAccountOpenedAt(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	manager := coreauth.NewManager(nil, nil, nil)
	// The plugin records the instant its upstream reports, with whatever offset
	// it was written in; the host normalizes it to UTC. A value that is not an
	// instant is dropped rather than shown as a guess.
	for _, record := range []*coreauth.Auth{
		{
			ID:       "loomy-1",
			FileName: "loomy-1.json",
			Provider: "loomy",
			Status:   coreauth.StatusActive,
			Metadata: map[string]any{"opened_at": "2026-10-06T23:03:15+08:00"},
		},
		{
			ID:       "loomy-2",
			FileName: "loomy-2.json",
			Provider: "loomy",
			Status:   coreauth.StatusActive,
			Metadata: map[string]any{"opened_at": "sometime last week"},
		},
		{
			ID:       "loomy-3",
			FileName: "loomy-3.json",
			Provider: "loomy",
			Status:   coreauth.StatusActive,
		},
	} {
		if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
			t.Fatalf("failed to register %s: %v", record.ID, errRegister)
		}
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}

	accounts := accountList(t, listAccounts(t, h, "/v8/management/accounts"))
	openedAt := map[string]any{}
	for _, account := range accounts {
		openedAt[account["auth_id"].(string)] = account["opened_at"]
	}
	if got := openedAt["loomy-1"]; got != "2026-10-06T15:03:15Z" {
		t.Fatalf("opened_at = %#v, want 2026-10-06T15:03:15Z", got)
	}
	for _, id := range []string{"loomy-2", "loomy-3"} {
		if got, present := openedAt[id]; present && got != nil {
			t.Fatalf("%s opened_at = %#v, want absent", id, got)
		}
	}
}

// TestListAccountsReportsTheExitABindingJustWrote pins the account view's half
// of the binding contract: the id the bind handler leaves in the live metadata
// has to come back out of /accounts immediately, not only once the watcher has
// reloaded the file from disk.
//
// The panel decides what the exit row says from this field alone. When it was
// missing, a bound credential rendered its resolved address under the "no exit"
// option: the row read as unbound, and the entry it actually pointed at was
// buried below it.
func TestListAccountsReportsTheExitABindingJustWrote(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	manager := coreauth.NewManager(nil, nil, nil)
	// One credential per shape the id can be held in: the Go int that
	// bindAccountEgress writes into live metadata, and the float64 that
	// encoding/json produces when the same file is read back off disk. Both
	// describe the same binding and must read the same way.
	for _, record := range []*coreauth.Auth{
		{
			ID:       "loomy-int",
			FileName: "loomy-int.json",
			Provider: "loomy",
			Status:   coreauth.StatusActive,
			Metadata: map[string]any{"egress_id": 2},
			ProxyURL: "socks5://user:pass@10.0.0.2:1080",
		},
		{
			ID:       "loomy-float",
			FileName: "loomy-float.json",
			Provider: "loomy",
			Status:   coreauth.StatusActive,
			Metadata: map[string]any{"egress_id": float64(2)},
		},
		{
			ID:       "loomy-none",
			FileName: "loomy-none.json",
			Provider: "loomy",
			Status:   coreauth.StatusActive,
		},
	} {
		if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
			t.Fatalf("failed to register %s: %v", record.ID, errRegister)
		}
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}

	accounts := accountList(t, listAccounts(t, h, "/v8/management/accounts"))
	exits := map[string]any{}
	for _, account := range accounts {
		exits[account["auth_id"].(string)] = account["egress_id"]
	}
	for _, id := range []string{"loomy-int", "loomy-float"} {
		if got := exits[id]; got != float64(2) {
			t.Fatalf("%s egress_id = %#v, want 2", id, got)
		}
	}
	// An unbound credential reports nothing rather than a zero id.
	if got := exits["loomy-none"]; got != nil {
		t.Fatalf("loomy-none egress_id = %#v, want it absent", got)
	}
}

func TestListAccountsFiltersAndCounts(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	manager := coreauth.NewManager(nil, nil, nil)
	for _, record := range []*coreauth.Auth{
		// The operator's enable switch sets the credential's own disabled flag, so
		// that flag — not a routing policy — is what reports manually_disabled.
		{ID: "loomy-1", FileName: "loomy-1.json", Provider: "loomy", Status: coreauth.StatusDisabled, Disabled: true,
			Metadata: map[string]any{"policy": pluginapi.AccountPolicyAuto}},
		{ID: "zcode-1", FileName: "zcode-1.json", Provider: "zcode", Status: coreauth.StatusActive,
			Metadata: map[string]any{"policy": "not-a-policy"}},
	} {
		if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
			t.Fatalf("failed to register auth record: %v", errRegister)
		}
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}

	payload := listAccounts(t, h, "/v8/management/accounts")
	accounts := accountList(t, payload)
	if len(accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(accounts))
	}
	// Accounts are ordered by provider so the panel's list is stable.
	if accounts[0]["provider"] != "loomy" || accounts[1]["provider"] != "zcode" {
		t.Fatalf("unexpected order: %#v", accounts)
	}
	if accounts[0]["manually_disabled"] != true {
		t.Fatalf("a disabled credential must report manually_disabled: %#v", accounts[0]["manually_disabled"])
	}
	// An unrecognized policy is not echoed back as if the host honoured it.
	if _, present := accounts[1]["policy"]; present {
		t.Fatalf("an unknown policy must not be reported, got %#v", accounts[1]["policy"])
	}

	counts, ok := payload["counts"].(map[string]any)
	if !ok {
		t.Fatalf("expected counts object, got %#v", payload["counts"])
	}
	if counts["total"] != float64(2) {
		t.Fatalf("counts.total = %#v", counts["total"])
	}
	byProvider, ok := counts["by_provider"].(map[string]any)
	if !ok || byProvider["loomy"] != float64(1) || byProvider["zcode"] != float64(1) {
		t.Fatalf("counts.by_provider = %#v", counts["by_provider"])
	}

	if got := len(accountList(t, listAccounts(t, h, "/v8/management/accounts?provider=LOOMY"))); got != 1 {
		t.Fatalf("provider filter returned %d accounts, want 1", got)
	}
	// No identity pool record exists in this fixture, so a kind filter matches
	// nothing rather than inventing accounts.
	if got := len(accountList(t, listAccounts(t, h, "/v8/management/accounts?kind=phone"))); got != 0 {
		t.Fatalf("kind filter returned %d accounts, want 0", got)
	}
}

// TestListAccountsNeverProbesForQuota pins the rule that a read is free: the
// account view must report the host's cached snapshot and must not spend the
// credential's upstream quota to fill it in.
func TestListAccountsNeverProbesForQuota(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{ID: "zcode-1", FileName: "zcode-1.json", Provider: "zcode", Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	probes := 0
	host := pluginhost.New()
	host.RegisterPluginForTest("zcode-plugin", pluginapi.Plugin{
		Metadata: pluginapi.Metadata{Name: "ZCode Plugin"},
		Capabilities: pluginapi.Capabilities{
			QuotaProvider: &mockQuotaProvider{
				identifier: "zcode",
				fetchFn: func(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
					probes++
					return pluginapi.QuotaFetchResponse{}, errors.New("upstream probe")
				},
			},
		},
	})

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}
	h.SetPluginHost(host)

	account := accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if account["quota_state"] != pluginapi.QuotaStateUnknown {
		t.Fatalf("quota_state = %#v, want %s", account["quota_state"], pluginapi.QuotaStateUnknown)
	}
	if probes != 0 {
		t.Fatalf("the account view probed upstream %d times, want 0", probes)
	}
}

func TestListAccountsReportsCachedQuotaAndFailedProbe(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	ctx := context.Background()

	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{ID: "zcode-1", FileName: "zcode-1.json", Provider: "zcode", Status: coreauth.StatusActive}
	index := record.EnsureIndex()
	if _, errRegister := manager.Register(ctx, record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	remaining, total := 12.0, 100.0
	fail := false
	probes := 0
	host := pluginhost.New()
	host.RegisterPluginForTest("zcode-plugin", pluginapi.Plugin{
		Metadata: pluginapi.Metadata{Name: "ZCode Plugin"},
		Capabilities: pluginapi.Capabilities{
			QuotaProvider: &mockQuotaProvider{
				identifier: "zcode",
				fetchFn: func(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
					probes++
					if fail {
						return pluginapi.QuotaFetchResponse{}, errors.New("probe failed")
					}
					return pluginapi.QuotaFetchResponse{
						Subscription: &pluginapi.QuotaSubscription{Plan: "Start Plan", TierName: "start-plan"},
						Channels: []pluginapi.QuotaChannel{
							{Key: "start-plan", Label: "Start Plan (free)"},
							{Key: "  api-key  ", Label: "Coding Plan (paid)"},
							{Key: "   ", Label: "unusable"},
						},
						Groups: []pluginapi.QuotaGroup{{
							DisplayName: "start-plan",
							Buckets: []pluginapi.QuotaBucket{{
								Model:             "glm-5.3",
								Label:             "  Coding Plan  ",
								Window:            "plan",
								RemainingFraction: 0.12,
								Remaining:         &remaining,
								Total:             &total,
							}},
						}},
					}, nil
				},
			},
		},
	})

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.tokenStore = &memoryAuthStore{}
	h.SetPluginHost(host)

	if _, handled, errFetch := host.FetchQuota(ctx, pluginapi.QuotaFetchRequest{Provider: "zcode", AuthIndex: index}); errFetch != nil || !handled {
		t.Fatalf("failed to prime the quota cache: handled=%v err=%v", handled, errFetch)
	}

	account := accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if probes != 1 {
		t.Fatalf("the account view ran %d probes, want only the priming one", probes)
	}
	if account["quota_state"] != pluginapi.QuotaStateEntitled {
		t.Fatalf("quota_state = %#v, want %s", account["quota_state"], pluginapi.QuotaStateEntitled)
	}
	if _, ok := account["fetched_at"].(string); !ok {
		t.Fatalf("fetched_at = %#v, want an RFC3339 string", account["fetched_at"])
	}
	if account["plan_id"] != "Start Plan" {
		t.Fatalf("plan_id = %#v", account["plan_id"])
	}
	buckets, ok := account["quota"].([]any)
	if !ok || len(buckets) != 1 {
		t.Fatalf("expected 1 quota bucket, got %#v", account["quota"])
	}
	bucket, ok := buckets[0].(map[string]any)
	if !ok {
		t.Fatalf("expected a quota bucket object, got %#v", buckets[0])
	}
	if bucket["model"] != "glm-5.3" || bucket["remaining"] != float64(12) || bucket["total"] != float64(100) {
		t.Fatalf("quota bucket = %#v", bucket)
	}
	// The row title is its own field, independent of the model, and padded
	// whitespace is trimmed on the way out.
	if bucket["label"] != "Coding Plan" {
		t.Fatalf("quota bucket label = %#v, want trimmed %q", bucket["label"], "Coding Plan")
	}

	// The channel list is what the credential can actually route through: a
	// padded key is trimmed, and a channel without a key is dropped because a
	// policy selects a channel by its key.
	channels, ok := account["channels"].([]any)
	if !ok || len(channels) != 2 {
		t.Fatalf("expected 2 channels, got %#v", account["channels"])
	}
	first, ok := channels[0].(map[string]any)
	if !ok || first["key"] != "start-plan" || first["label"] != "Start Plan (free)" {
		t.Fatalf("channel[0] = %#v", channels[0])
	}
	second, ok := channels[1].(map[string]any)
	if !ok || second["key"] != "api-key" {
		t.Fatalf("a padded channel key must be trimmed, got %#v", channels[1])
	}

	// A failed probe is a query error, not an exhausted account, and the last
	// good reading keeps its own timestamp.
	fail = true
	if _, handled, _ := host.FetchQuota(ctx, pluginapi.QuotaFetchRequest{Provider: "zcode", AuthIndex: index}); !handled {
		t.Fatal("expected the failing probe to be handled")
	}
	account = accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if account["quota_state"] != pluginapi.QuotaStateQueryError {
		t.Fatalf("quota_state = %#v, want %s", account["quota_state"], pluginapi.QuotaStateQueryError)
	}
	if _, ok := account["fetched_at"].(string); !ok {
		t.Fatalf("the last good reading must keep its timestamp, got %#v", account["fetched_at"])
	}
	// The channel list rides the last good reading too, so a failed probe keeps
	// offering the channels the credential is known to carry.
	channels, ok = account["channels"].([]any)
	if !ok || len(channels) != 2 {
		t.Fatalf("a failed probe must keep the last known channels, got %#v", account["channels"])
	}

	// A reading past its freshness window is still reported, but flagged stale,
	// so the panel can show it as an old number instead of a live balance.
	host.SetQuotaClockForTest(func() time.Time { return time.Now().Add(time.Hour) })
	account = accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if account["quota_stale"] != true {
		t.Fatalf("quota_stale = %#v, want true for a reading past its freshness window", account["quota_stale"])
	}
	if _, ok := account["fetched_at"].(string); !ok {
		t.Fatalf("a stale reading must keep reporting when it was fetched, got %#v", account["fetched_at"])
	}
}

func TestCredentialFailureClass(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lastErr    *coreauth.Error
		statusText string
		want       string
	}{
		{"no failure", nil, "", ""},
		{"host request scoped", &coreauth.Error{Code: coreauth.ErrorCodeRequestScoped}, "", failureClassRequest},
		{"host transient transport", &coreauth.Error{Code: coreauth.ErrorCodeTransientTransport}, "", failureClassNetwork},
		{"host refresh unauthorized", &coreauth.Error{Code: "unauthorized", HTTPStatus: http.StatusUnauthorized}, "", failureClassAuth},
		{"host model not found", &coreauth.Error{Code: "model_not_found", HTTPStatus: http.StatusNotFound}, "", failureClassRequest},
		{"loomy session expired", &coreauth.Error{Code: "session_expired"}, "", failureClassAuth},
		{"loomy sms failed", &coreauth.Error{Code: "sms_failed"}, "", failureClassUpstream},
		{"loomy sms without a number", &coreauth.Error{Code: "sms_no_number"}, "", failureClassUpstream},
		{"zcode credential refused", &coreauth.Error{Code: "missing_credential"}, "", failureClassAuth},
		{"zcode invalid_auth over a 400", &coreauth.Error{Code: "invalid_auth", HTTPStatus: http.StatusBadRequest}, "", failureClassAuth},
		{"zcode unknown route", &coreauth.Error{Code: "not_found", HTTPStatus: http.StatusNotFound}, "", failureClassRequest},
		// A generic plugin code must not shadow the upstream status: zcode folds
		// its numeric business codes into that status, so the status is the only
		// signal that separates throttling from a request fault.
		{"zcode upstream, throttled", &coreauth.Error{Code: "upstream_error", HTTPStatus: http.StatusTooManyRequests}, "", failureClassRate},
		{"zcode upstream, refused the credential", &coreauth.Error{Code: "upstream_error", HTTPStatus: http.StatusUnauthorized}, "", failureClassAuth},
		{"zcode upstream, request fault", &coreauth.Error{Code: "upstream_error", HTTPStatus: http.StatusBadRequest}, "", failureClassRequest},
		{"zcode upstream, outage", &coreauth.Error{Code: "upstream_error", HTTPStatus: http.StatusBadGateway}, "", failureClassUpstream},
		{"loomy business error keeps the upstream status", &coreauth.Error{Code: "upstream_business_error", HTTPStatus: http.StatusPaymentRequired}, "", failureClassQuota},
		{"status message only", nil, "cloudflare challenge", failureClassRisk},
		{"status message quota", nil, "quota exhausted", failureClassQuota},
		{"status message credential quota", nil, "credential_quota", failureClassQuota},
		// A plugin's own wording is not a class source, so an unrecognised status
		// message yields no class rather than a guess.
		{"unrecognised status message", nil, "upstream HTTP 400", ""},
		// An operator-disabled credential is a state, not a failure.
		{"operator disabled", nil, "disabled via management API", ""},
		{"http unauthorized", &coreauth.Error{HTTPStatus: http.StatusUnauthorized}, "", failureClassAuth},
		{"http payment required", &coreauth.Error{HTTPStatus: http.StatusPaymentRequired}, "", failureClassQuota},
		{"http too many requests", &coreauth.Error{HTTPStatus: http.StatusTooManyRequests}, "", failureClassRate},
		{"http bad request", &coreauth.Error{HTTPStatus: http.StatusBadRequest}, "", failureClassRequest},
		{"http server error", &coreauth.Error{HTTPStatus: http.StatusBadGateway}, "", failureClassUpstream},
		{"unknown code is an upstream fault", &coreauth.Error{Code: "who-knows"}, "", failureClassUpstream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialFailureClass(tc.lastErr, tc.statusText); got != tc.want {
				t.Fatalf("credentialFailureClass = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPatchAuthFileFieldsAccountPolicy(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	fileName := "zcode-1.json"
	filePath := filepath.Join(authDir, fileName)
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, nil, nil)
	record := &coreauth.Auth{
		ID:         fileName,
		FileName:   fileName,
		Provider:   "zcode",
		Attributes: map[string]string{"path": filePath},
		Metadata:   map[string]any{"type": "zcode"},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	patch := func(body string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(recorder)
		ginCtx.Request = httptest.NewRequest(http.MethodPatch, "/v8/management/credentials/fields", strings.NewReader(body))
		ginCtx.Request.Header.Set("Content-Type", "application/json")
		h.PatchAuthFileFields(ginCtx)
		return recorder
	}

	pinnedPolicy := pluginapi.AccountPolicyOnly("start-plan")
	rejected := patch(`{"name":"` + fileName + `","policy":"start-plan-onlyy"}`)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rejected.Code, rejected.Body.String())
	}
	// The rejection must describe the accepted shape rather than list values: a
	// policy names a plugin-owned channel key the host cannot enumerate.
	rejection := rejected.Body.String()
	if !strings.Contains(rejection, pluginapi.AccountPolicyAuto) || !strings.Contains(rejection, pluginapi.AccountPolicyOnlyPrefix) {
		t.Fatalf("the rejection must describe the accepted policies, got %s", rejection)
	}

	accepted := patch(`{"name":"` + fileName + `","policy":"` + pinnedPolicy + `"}`)
	if accepted.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", accepted.Code, accepted.Body.String())
	}
	// The policy must reach the account view through the credential's metadata,
	// so an operator can move a credential between channels without editing the
	// credential file.
	account := accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if account["policy"] != pinnedPolicy {
		t.Fatalf("policy = %#v, want %q", account["policy"], pinnedPolicy)
	}
	if account["manually_disabled"] != false {
		t.Fatalf("manually_disabled = %#v, want false", account["manually_disabled"])
	}

	// Manual disabling is the credential's own state, so the enable switch — not
	// a policy — is what moves manually_disabled.
	disabled := patch(`{"name":"` + fileName + `","disabled":true}`)
	if disabled.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", disabled.Code, disabled.Body.String())
	}
	account = accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if account["manually_disabled"] != true {
		t.Fatalf("a disabled credential must report manually_disabled, got %#v", account["manually_disabled"])
	}
	if account["policy"] != pinnedPolicy {
		t.Fatalf("disabling a credential must not touch its routing policy, got %#v", account["policy"])
	}
}
