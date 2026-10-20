package management

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// This file is the account-centric view. A credential's data lives in five
// layers, and the panel used to read four endpoints and stitch them together,
// guessing which layer owned each field. This surface answers that once, so a
// field has exactly one source:
//
//	auth store    -> identity, parsed, enabled, manually_disabled, auth_state
//	supply pool   -> source_kind (which identity is behind the credential)
//	auth metadata -> policy
//	quota cache   -> quota_state, fetched_at, plan_id, channel, quota
//	auth health   -> request counts and the heatmap
//
// Two rules are not negotiable. A value that cannot be determined is omitted or
// null, never reported as zero or false. And a read never probes upstream: quota
// comes from the host's snapshot cache, because a probe spends the credential's
// real quota and can trip the provider's risk controls.

// accountView is one account. The field names are the contract the panel reads.
type accountView struct {
	Provider    string `json:"provider"`
	AuthIndex   string `json:"auth_index"`
	AuthID      string `json:"auth_id"`
	AccountID   string `json:"account_id,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Site        string `json:"site,omitempty"`
	SourceKind  string `json:"source_kind,omitempty"`

	Parsed          bool   `json:"parsed"`
	Enabled         bool   `json:"enabled"`
	SupportsRefresh *bool  `json:"supports_refresh"`
	AuthState       string `json:"auth_state"`

	// EgressID names the proxy-pool exit this credential leaves through, and
	// Egress is the address actually in force, redacted. Both are reported
	// because a credential can be bound by id or typed by hand, and the panel
	// has to show which of the two it is looking at instead of assuming a pool
	// entry exists for every account.
	EgressID int    `json:"egress_id,omitempty"`
	Egress   string `json:"egress,omitempty"`

	Eligible         bool   `json:"eligible"`
	ManuallyDisabled bool   `json:"manually_disabled"`
	CooldownUntil    string `json:"cooldown_until,omitempty"`
	FailureClass     string `json:"failure_class,omitempty"`
	FailureReason    string `json:"failure_reason,omitempty"`
	FailureRetryable *bool  `json:"failure_retryable,omitempty"`

	PlanID      string `json:"plan_id,omitempty"`
	Channel     string `json:"channel,omitempty"`
	Policy      string `json:"policy,omitempty"`
	Entitlement string `json:"entitlement,omitempty"`
	// OpenedAt is when the account was first opened on its platform, as the
	// owning plugin recorded it. It is a fact about the account, not about the
	// credential: the plugin writes it from what its upstream reports.
	OpenedAt string `json:"opened_at,omitempty"`

	QuotaState string               `json:"quota_state"`
	FetchedAt  string               `json:"fetched_at,omitempty"`
	Quota      []accountQuotaBucket `json:"quota,omitempty"`
	// Channels lists every routing channel the credential actually carries, so
	// the management UI can offer a routing choice that exists instead of a
	// fixed vocabulary that may not match the account.
	Channels []accountChannel `json:"channels,omitempty"`

	RequestCount int64               `json:"request_count"`
	SuccessCount int64               `json:"success_count"`
	FailureCount int64               `json:"failure_count"`
	Heatmap      []accountHeatBucket `json:"heatmap"`
}

// accountQuotaBucket is one quota window of one account. Model is the model the
// window applies to, so a provider that reports per-model limits no longer has
// to pack the model name into a description.
type accountQuotaBucket struct {
	Group             string   `json:"group,omitempty"`
	Model             string   `json:"model,omitempty"`
	Window            string   `json:"window,omitempty"`
	RemainingFraction float64  `json:"remaining_fraction"`
	Remaining         *float64 `json:"remaining,omitempty"`
	Total             *float64 `json:"total,omitempty"`
	ResetAt           string   `json:"reset_at,omitempty"`
	Description       string   `json:"description,omitempty"`
}

// accountChannel is one routing channel the credential carries. Key is the
// plugin-owned identifier an account policy selects; Label is the name the
// plugin derived from what the upstream reports, and is what the operator sees.
type accountChannel struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// accountHeatBucket is one fixed-width window of an account's request history.// SuccessRate is null when the window saw no requests, because "no requests" and
// "every request failed" are different facts.
type accountHeatBucket struct {
	Bucket      string   `json:"bucket"`
	Success     int64    `json:"success"`
	Failed      int64    `json:"failed"`
	SuccessRate *float64 `json:"success_rate"`
}

// ListAccounts reports every credential as one account view.
//
// Optional filters: ?provider=<provider key> and ?kind=phone|email.
func (h *Handler) ListAccounts(c *gin.Context) {
	filterProvider := strings.ToLower(strings.TrimSpace(c.Query("provider")))
	filterKind := supply.Kind(strings.ToLower(strings.TrimSpace(c.Query("kind"))))
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "accounts": []accountView{}, "counts": gin.H{"total": 0}})
		return
	}

	now := time.Now().UTC()
	poolByAuthIndex := h.poolRecordsByAuthIndex()
	h.mu.Lock()
	host := h.pluginHost
	h.mu.Unlock()

	auths := h.authManager.List()
	accounts := make([]accountView, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		auth.EnsureIndex()
		if filterProvider != "" && strings.ToLower(strings.TrimSpace(auth.Provider)) != filterProvider {
			continue
		}
		poolRecord, hasPoolRecord := poolByAuthIndex[auth.Index]
		if filterKind.Valid() && (!hasPoolRecord || poolRecord.Kind != filterKind) {
			continue
		}
		accounts = append(accounts, buildAccountView(auth, poolRecord, hasPoolRecord, host, now))
	}
	sort.SliceStable(accounts, func(i, j int) bool {
		if accounts[i].Provider != accounts[j].Provider {
			return accounts[i].Provider < accounts[j].Provider
		}
		return accounts[i].AuthIndex < accounts[j].AuthIndex
	})

	byProvider := make(map[string]int, len(accounts))
	byState := make(map[string]int, len(accounts))
	for _, account := range accounts {
		byProvider[account.Provider]++
		byState[account.AuthState]++
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"accounts": accounts,
		"counts": gin.H{
			"total":       len(accounts),
			"by_provider": byProvider,
			"by_state":    byState,
		},
	})
}

// buildAccountView merges the layers for one credential.
func buildAccountView(auth *coreauth.Auth, poolRecord supply.Record, hasPoolRecord bool, host *pluginhost.Host, now time.Time) accountView {
	unavailable, authState, statusMessage, nextRetry := reconcileAuthFileCooldownState(auth, now)

	view := accountView{
		Provider:     strings.TrimSpace(auth.Provider),
		AuthIndex:    auth.Index,
		AuthID:       auth.ID,
		AccountID:    accountIdentifier(auth),
		DisplayName:  accountDisplayName(auth),
		Parsed:       auth.Index != "",
		Enabled:      !auth.Disabled,
		AuthState:    string(authState),
		Eligible:     !unavailable,
		QuotaState:   pluginapi.QuotaStateUnknown,
		RequestCount: auth.Success + auth.Failed,
		SuccessCount: auth.Success,
		FailureCount: auth.Failed,
		// Manually disabled is the credential's own state, not a routing policy:
		// the operator's enable switch sets the credential's disabled flag, and a
		// policy only decides which channels the credential may route through.
		ManuallyDisabled: auth.Disabled,
	}
	if view.AuthState == "" {
		view.AuthState = string(coreauth.StatusUnknown)
	}
	if hasPoolRecord {
		view.SourceKind = string(poolRecord.Kind)
	}
	if id, ok := egressIDValue(auth.Metadata["egress_id"]); ok {
		view.EgressID = id
	}
	if proxy := strings.TrimSpace(auth.ProxyURL); proxy != "" {
		view.Egress = proxyutil.Redact(proxy)
	}

	// The routing policy is account metadata, so an operator can move a
	// credential between channels without copying the credential file. It is
	// only the routing decision: it never says whether the credential itself is
	// switched on.
	if policy := authMetadataString(auth, "policy"); pluginapi.ValidAccountPolicy(policy) {
		view.Policy = policy
	}

	// The account's age belongs to the account, not to the credential: the
	// plugin records the instant its upstream reports, so an import or a token
	// refresh never moves it.
	view.OpenedAt = accountOpenedAt(auth)

	if !nextRetry.IsZero() {
		view.CooldownUntil = nextRetry.UTC().Format(time.RFC3339)
	}
	view.FailureClass = credentialFailureClass(auth.LastError, statusMessage)
	if auth.LastError != nil {
		retryable := auth.LastError.Retryable
		view.FailureRetryable = &retryable
	}
	view.FailureReason = logging.SafeDiagnosticForLog(statusMessage)

	applyCachedQuota(&view, host)
	view.Heatmap = accountHeatmap(auth, now)
	return view
}

// applyCachedQuota fills the plan and quota fields from the host's snapshot
// cache. It never probes: a missing snapshot is reported as an unknown quota
// state rather than paid for with an upstream request.
func applyCachedQuota(view *accountView, host *pluginhost.Host) {
	snapshot, ok := host.CachedQuota(view.Provider, view.AuthIndex)
	if !ok {
		return
	}
	switch {
	case snapshot.Failed:
		view.QuotaState = pluginapi.QuotaStateQueryError
	case !snapshot.Fetched:
		view.QuotaState = pluginapi.QuotaStateUnknown
	case quotaExhausted(snapshot.Response):
		view.QuotaState = pluginapi.QuotaStateExhausted
	default:
		view.QuotaState = pluginapi.QuotaStateEntitled
	}
	if !snapshot.Fetched {
		return
	}
	view.FetchedAt = snapshot.FetchedAt.UTC().Format(time.RFC3339)
	if subscription := snapshot.Response.Subscription; subscription != nil {
		view.PlanID = strings.TrimSpace(subscription.Plan)
		view.Channel = strings.TrimSpace(subscription.TierName)
	}
	// The channel list rides the last good reading, so a failed probe keeps
	// offering the channels it already knew about. A channel without a key is
	// unusable (a policy selects a channel by its key), so it is dropped rather
	// than reported as an anonymous choice.
	for _, channel := range snapshot.Response.Channels {
		key := strings.TrimSpace(channel.Key)
		if key == "" {
			continue
		}
		view.Channels = append(view.Channels, accountChannel{
			Key:   key,
			Label: strings.TrimSpace(channel.Label),
		})
	}
	for _, group := range snapshot.Response.Groups {
		for _, bucket := range group.Buckets {
			view.Quota = append(view.Quota, accountQuotaBucket{
				Group:             strings.TrimSpace(group.DisplayName),
				Model:             strings.TrimSpace(bucket.Model),
				Window:            strings.TrimSpace(bucket.Window),
				RemainingFraction: bucket.RemainingFraction,
				Remaining:         bucket.Remaining,
				Total:             bucket.Total,
				ResetAt:           strings.TrimSpace(bucket.ResetTime),
				Description:       strings.TrimSpace(bucket.Description),
			})
		}
	}
}

// quotaExhausted reports whether every bucket the provider reported is spent. It
// demands positive evidence of a limit, so a provider that reports nothing is
// not mistaken for an exhausted account.
func quotaExhausted(response pluginapi.QuotaFetchResponse) bool {
	evidence := false
	for _, group := range response.Groups {
		for _, bucket := range group.Buckets {
			switch {
			case bucket.Remaining != nil:
				evidence = true
				if *bucket.Remaining > 0 {
					return false
				}
			case bucket.Total != nil && *bucket.Total > 0:
				evidence = true
				if bucket.RemainingFraction > 0 {
					return false
				}
			}
		}
	}
	return evidence
}

// accountHeatmap converts the credential's request history into buckets that
// carry their own success rate. The bucket width and count are the host's
// existing fixed granularity; only the rate is added.
func accountHeatmap(auth *coreauth.Auth, now time.Time) []accountHeatBucket {
	history := auth.RecentRequestsSnapshot(now)
	heatmap := make([]accountHeatBucket, 0, len(history))
	for _, bucket := range history {
		entry := accountHeatBucket{Bucket: bucket.Time, Success: bucket.Success, Failed: bucket.Failed}
		if total := bucket.Success + bucket.Failed; total > 0 {
			rate := float64(bucket.Success) / float64(total)
			entry.SuccessRate = &rate
		}
		heatmap = append(heatmap, entry)
	}
	return heatmap
}

// poolRecordsByAuthIndex indexes the identity pool by credential index, so an
// account view can name the identity behind a credential. The pool never
// creates accounts here: a record with no credential is left out.
func (h *Handler) poolRecordsByAuthIndex() map[string]supply.Record {
	pool := supply.DefaultPool()
	if pool == nil {
		return nil
	}
	index := h.authIndexByName()
	out := make(map[string]supply.Record)
	for _, record := range pool.All() {
		authIndex, _ := resolveAuthIndex(record, index)
		if authIndex == "" {
			continue
		}
		if _, exists := out[authIndex]; exists {
			continue
		}
		out[authIndex] = record
	}
	return out
}

// accountIdentifier returns the provider-side account this credential belongs
// to, as the credential's own metadata declares it. It reads the email and the
// project id directly instead of calling AccountInfo, which for an API-key
// credential returns the key itself and would put a secret in the response.
func accountIdentifier(auth *coreauth.Auth) string {
	if email := authEmail(auth); email != "" {
		return email
	}
	return authProjectID(auth)
}

// accountDisplayName returns the name to show for a credential.
func accountDisplayName(auth *coreauth.Auth) string {
	if label := strings.TrimSpace(auth.Label); label != "" {
		return label
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}
	return auth.ID
}

// authMetadataString reads a string field out of a credential's metadata.
func authMetadataString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, ok := auth.Metadata[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

// accountOpenedAt reports when the account was first opened on its platform, as
// the owning plugin recorded it. The plugin knows what its upstream reports, so
// the host only validates the shape: a value that is not an instant is not
// shown at all rather than rendered as a guess.
func accountOpenedAt(auth *coreauth.Auth) string {
	raw := authMetadataString(auth, "opened_at")
	if raw == "" {
		return ""
	}
	instant, errParse := time.Parse(time.RFC3339, raw)
	if errParse != nil {
		return ""
	}
	return instant.UTC().Format(time.RFC3339)
}
