package pluginhost

import (
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// This file is the host's quota snapshot store. Probing a credential's quota
// spends that credential's real upstream quota and can trip a provider's risk
// controls, so a management read must never trigger one. The host therefore
// records the result of every probe it does take, and readers report the last
// record instead of asking again.
//
// A record keeps the last good reading and the last failure separately: a failed
// probe does not erase what the provider last reported, and it must not be
// reported as "exhausted" either.

// quotaSnapshotRecord is the host's last view of one credential's quota.
type quotaSnapshotRecord struct {
	// response is the last reading the provider returned. It is zero when every
	// probe so far has failed.
	response pluginapi.QuotaFetchResponse
	// fetchedAt is when response was taken. It is the zero time when there is
	// no reading yet.
	fetchedAt time.Time
	// failed is true when the most recent probe attempt failed.
	failed bool
}

// QuotaSnapshot is a credential's last recorded quota, as a reader sees it.
type QuotaSnapshot struct {
	Response  pluginapi.QuotaFetchResponse
	FetchedAt time.Time
	// Failed reports whether the most recent probe attempt failed. A reader
	// must report that as a query error rather than as an exhausted account.
	Failed bool
	// Fetched reports whether a reading was ever taken. A snapshot with no
	// reading is still useful: it says the last attempt failed.
	Fetched bool
}

// quotaSnapshotKey identifies one credential's snapshot. The provider is part of
// the key because the same credential can be probed through more than one quota
// provider.
func quotaSnapshotKey(provider, authIndex string) string {
	return strings.TrimSpace(provider) + "\x00" + strings.TrimSpace(authIndex)
}

// rememberQuotaSnapshot records a successful probe and returns the response
// stamped with the time the host recorded it.
func (h *Host) rememberQuotaSnapshot(provider, authIndex string, resp pluginapi.QuotaFetchResponse) pluginapi.QuotaFetchResponse {
	if h == nil {
		return resp
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return resp
	}
	fetchedAt := time.Now().UTC()
	resp.FetchedAt = fetchedAt.Format(time.RFC3339)
	h.quotaMu.Lock()
	if h.quotaSnapshots == nil {
		h.quotaSnapshots = make(map[string]quotaSnapshotRecord)
	}
	h.quotaSnapshots[quotaSnapshotKey(provider, authIndex)] = quotaSnapshotRecord{response: resp, fetchedAt: fetchedAt}
	h.quotaMu.Unlock()
	return resp
}

// rememberQuotaSnapshotFailure records a failed probe attempt. The last good
// reading is kept, so a reader can still say when the credential was last known
// to have quota.
func (h *Host) rememberQuotaSnapshotFailure(provider, authIndex string) {
	if h == nil {
		return
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return
	}
	h.quotaMu.Lock()
	if h.quotaSnapshots == nil {
		h.quotaSnapshots = make(map[string]quotaSnapshotRecord)
	}
	key := quotaSnapshotKey(provider, authIndex)
	record := h.quotaSnapshots[key]
	record.failed = true
	h.quotaSnapshots[key] = record
	h.quotaMu.Unlock()
}

// CachedQuota returns the last recorded snapshot for a credential without
// probing upstream. The second result is false when the credential was never
// probed.
func (h *Host) CachedQuota(provider, authIndex string) (QuotaSnapshot, bool) {
	if h == nil {
		return QuotaSnapshot{}, false
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return QuotaSnapshot{}, false
	}
	h.quotaMu.Lock()
	record, ok := h.quotaSnapshots[quotaSnapshotKey(provider, authIndex)]
	h.quotaMu.Unlock()
	if !ok {
		return QuotaSnapshot{}, false
	}
	return QuotaSnapshot{
		Response:  record.response,
		FetchedAt: record.fetchedAt,
		Failed:    record.failed,
		Fetched:   !record.fetchedAt.IsZero(),
	}, true
}

// ForgetQuotaSnapshots drops every snapshot for a credential. A reset must not
// leave the reading it just invalidated in place.
func (h *Host) ForgetQuotaSnapshots(authIndex string) {
	if h == nil {
		return
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return
	}
	suffix := "\x00" + authIndex
	h.quotaMu.Lock()
	for key := range h.quotaSnapshots {
		if strings.HasSuffix(key, suffix) {
			delete(h.quotaSnapshots, key)
		}
	}
	h.quotaMu.Unlock()
}
