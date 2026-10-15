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
	record := &coreauth.Auth{
		ID:       "zcode-1",
		FileName: "zcode-1.json",
		Provider: "zcode",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"policy": pluginapi.AccountPolicyStartPlanFirst},
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
	if account["policy"] != pluginapi.AccountPolicyStartPlanFirst {
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

func TestListAccountsFiltersAndCounts(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	manager := coreauth.NewManager(nil, nil, nil)
	for _, record := range []*coreauth.Auth{
		{ID: "loomy-1", FileName: "loomy-1.json", Provider: "loomy", Status: coreauth.StatusActive,
			Metadata: map[string]any{"policy": pluginapi.AccountPolicyDisabled}},
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
		t.Fatalf("a disabled policy must set manually_disabled: %#v", accounts[0]["manually_disabled"])
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
						Groups: []pluginapi.QuotaGroup{{
							DisplayName: "start-plan",
							Buckets: []pluginapi.QuotaBucket{{
								Model:             "glm-5.3",
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

	rejected := patch(`{"name":"` + fileName + `","policy":"start-plan-onlyy"}`)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rejected.Code, rejected.Body.String())
	}
	if !strings.Contains(rejected.Body.String(), pluginapi.AccountPolicyStartPlanFirst) {
		t.Fatalf("the rejection must name the accepted policies, got %s", rejected.Body.String())
	}

	accepted := patch(`{"name":"` + fileName + `","policy":"` + pluginapi.AccountPolicyStartPlanFirst + `"}`)
	if accepted.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", accepted.Code, accepted.Body.String())
	}
	// The policy must reach the account view through the credential's metadata,
	// so an operator can move a credential between channels without editing the
	// credential file.
	account := accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if account["policy"] != pluginapi.AccountPolicyStartPlanFirst {
		t.Fatalf("policy = %#v, want %q", account["policy"], pluginapi.AccountPolicyStartPlanFirst)
	}
	if account["manually_disabled"] != false {
		t.Fatalf("manually_disabled = %#v, want false", account["manually_disabled"])
	}

	disabled := patch(`{"name":"` + fileName + `","policy":"` + pluginapi.AccountPolicyDisabled + `"}`)
	if disabled.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", disabled.Code, disabled.Body.String())
	}
	account = accountList(t, listAccounts(t, h, "/v8/management/accounts"))[0]
	if account["manually_disabled"] != true {
		t.Fatalf("a disabled policy must set manually_disabled, got %#v", account["manually_disabled"])
	}
}
