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
//
// A reading carries two deadlines because "this is old" and "forget this" are
// different questions. Past expiresAt the reading is reported as Stale: it is
// still returned, because the plan and channel list it carries are facts about
// the credential that a failed probe must not destroy, but a reader can no
// longer pass it off as a live balance. Past retainUntil the record is dropped,
// which is what keeps the store tracking live credentials instead of growing
// with every credential ever probed.

const (
	// quotaSnapshotFreshFor is how long a reading counts as current. A plugin's
	// own cache must not outlive it, or the host would be reporting a balance
	// the plugin already considers expired.
	quotaSnapshotFreshFor = 15 * time.Minute
	// quotaSnapshotRetainFor is how long a record survives without being
	// rewritten. It is long enough to keep a plan and channel list readable
	// across a provider outage, and short enough that a removed credential's
	// record does not live forever.
	quotaSnapshotRetainFor = 24 * time.Hour
	// maxQuotaSnapshots caps the store so credential churn cannot grow it
	// without bound.
	maxQuotaSnapshots = 4096
)

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
	// expiresAt is when response stops counting as a live balance. It is the
	// zero time when there is no reading yet.
	expiresAt time.Time
	// retainUntil is when the record is evicted. Every write refreshes it, so an
	// actively probed credential is never evicted.
	retainUntil time.Time
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
	// Stale reports that a reading exists but is older than the freshness
	// window. The reading is still returned, and the reader decides how to show
	// it. It is false when no reading was ever taken.
	Stale bool
}

// quotaClock reads the host's snapshot clock. Tests replace it to exercise
// expiry without waiting on the wall clock.
func (h *Host) quotaClock() time.Time {
	if h != nil && h.quotaNow != nil {
		return h.quotaNow()
	}
	return time.Now()
}

// quotaSnapshotKey identifies one credential's snapshot. The provider is part of
// the key because the same credential can be probed through more than one quota
// provider.
func quotaSnapshotKey(provider, authIndex string) string {
	return strings.TrimSpace(provider) + "\x00" + strings.TrimSpace(authIndex)
}

// sweepQuotaSnapshotsLocked drops every record whose retention has passed and,
// when the store is full, evicts the record nearest its retention so an insert
// still has room. The caller holds quotaMu.
func (h *Host) sweepQuotaSnapshotsLocked(now time.Time) {
	for key, record := range h.quotaSnapshots {
		if !record.retainUntil.IsZero() && !now.Before(record.retainUntil) {
			delete(h.quotaSnapshots, key)
		}
	}
	if len(h.quotaSnapshots) < maxQuotaSnapshots {
		return
	}
	evictKey := ""
	var evictAt time.Time
	for key, record := range h.quotaSnapshots {
		if evictKey == "" || record.retainUntil.Before(evictAt) {
			evictKey, evictAt = key, record.retainUntil
		}
	}
	if evictKey != "" {
		delete(h.quotaSnapshots, evictKey)
	}
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
	fetchedAt := h.quotaClock().UTC()
	resp.FetchedAt = fetchedAt.Format(time.RFC3339)
	h.quotaMu.Lock()
	if h.quotaSnapshots == nil {
		h.quotaSnapshots = make(map[string]quotaSnapshotRecord)
	}
	key := quotaSnapshotKey(provider, authIndex)
	if _, exists := h.quotaSnapshots[key]; !exists {
		h.sweepQuotaSnapshotsLocked(fetchedAt)
	}
	h.quotaSnapshots[key] = quotaSnapshotRecord{
		response:    resp,
		fetchedAt:   fetchedAt,
		expiresAt:   fetchedAt.Add(quotaSnapshotFreshFor),
		retainUntil: fetchedAt.Add(quotaSnapshotRetainFor),
	}
	h.quotaMu.Unlock()
	return resp
}

// rememberQuotaSnapshotFailure records a failed probe attempt. The last good
// reading is kept, so a reader can still say when the credential was last known
// to have quota, and a failure refreshes retention without reviving an expired
// reading.
func (h *Host) rememberQuotaSnapshotFailure(provider, authIndex string) {
	if h == nil {
		return
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return
	}
	now := h.quotaClock().UTC()
	h.quotaMu.Lock()
	if h.quotaSnapshots == nil {
		h.quotaSnapshots = make(map[string]quotaSnapshotRecord)
	}
	key := quotaSnapshotKey(provider, authIndex)
	record, exists := h.quotaSnapshots[key]
	if !exists {
		h.sweepQuotaSnapshotsLocked(now)
	}
	record.failed = true
	record.retainUntil = now.Add(quotaSnapshotRetainFor)
	h.quotaSnapshots[key] = record
	h.quotaMu.Unlock()
}

// CachedQuota returns the last recorded snapshot for a credential without
// probing upstream. The second result is false when the credential was never
// probed, or when its record has outlived its retention.
func (h *Host) CachedQuota(provider, authIndex string) (QuotaSnapshot, bool) {
	if h == nil {
		return QuotaSnapshot{}, false
	}
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return QuotaSnapshot{}, false
	}
	now := h.quotaClock()
	key := quotaSnapshotKey(provider, authIndex)
	h.quotaMu.Lock()
	record, ok := h.quotaSnapshots[key]
	if ok && !record.retainUntil.IsZero() && !now.Before(record.retainUntil) {
		delete(h.quotaSnapshots, key)
		ok = false
	}
	h.quotaMu.Unlock()
	if !ok {
		return QuotaSnapshot{}, false
	}
	return QuotaSnapshot{
		Response:  record.response,
		FetchedAt: record.fetchedAt,
		Failed:    record.failed,
		Fetched:   !record.fetchedAt.IsZero(),
		Stale:     !record.expiresAt.IsZero() && !now.Before(record.expiresAt),
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
