package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Credential concurrency admission.
//
// Until this gate existed, the only thing limiting how many requests one
// credential served at once was the upstream provider noticing. The gateway had
// selection (priority + weight) and stickiness (session affinity) but no
// admission control, so a burst of parallel sessions could all land on one
// credential, trip the provider's own limit, and fail — the zcode case returns
// code 3008/3009, which the plugin does not treat as retryable, so the request
// surfaced as a 502 even though other credentials were idle.
//
// The rules this file implements:
//
//   - The cap is hard. A saturated credential is skipped at selection, so the
//     request spills to another credential inside the same pick. Nothing queues
//     on the normal path.
//   - A slot is held for the request's lifetime and released when the request
//     ends. It is not tied to the session-affinity TTL: that would let one
//     credential serve a single request per TTL window.
//   - Saturated is a normal state, not a failure. It records no result, counts
//     no failure, and starts no cooldown, because the credential is healthy.
//   - Spilling does not move the session-affinity binding. A busy credential is
//     still the right home for the session once it has room.
//   - Capacity scales by adding credentials, not by raising one credential's
//     cap, so the effective cap of a credential is small by design.

const (
	// credentialCapQueueWait bounds how long a request waits when every eligible
	// credential is saturated. It applies only to that terminal state: as soon as
	// any credential frees a slot the request proceeds.
	credentialCapQueueWait = 2 * time.Second

	// credentialCapPollInterval is how often the full-pool wait re-checks.
	credentialCapPollInterval = 25 * time.Millisecond

	// credentialCapHoldAttempts bounds how many times selection is retried when
	// another request takes the last slot between admission and the reservation.
	credentialCapHoldAttempts = 3
)

// providerDefaultMaxConcurrency returns the cap used when a credential does not
// set one. The values are per provider because the upstream limits differ: a
// zcode Start Plan credential is measured at roughly 3 concurrent requests, the
// loomy client caps itself at 5, and workbuddy tolerates 2. A single shared
// default would either waste two thirds of a zcode credential or guarantee 429s.
func providerDefaultMaxConcurrency(provider string) int {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch {
	case provider == "":
		return 2
	case strings.HasPrefix(provider, "zcode"):
		return 3
	case strings.HasPrefix(provider, "loomy"):
		return 5
	case strings.HasPrefix(provider, "workbuddy"):
		return 2
	default:
		return 2
	}
}

// ProviderDefaultMaxConcurrency exposes the provider default cap so the
// management listing can tell the panel what an unlisted model inherits.
func ProviderDefaultMaxConcurrency(provider string) int {
	return providerDefaultMaxConcurrency(provider)
}

// credentialConcurrencyLimit resolves a credential's effective cap at read time.
//
// Resolving on read rather than injecting on write is deliberate: auth files are
// written by four unrelated paths with no shared helper, so a write-time default
// would need to be added to each of them and every existing file migrated. Read
// time gives every credential that has no field a working default immediately,
// and it keeps a provider default change from requiring a rewrite of stored
// files.
//
// An absent field inherits the provider default. An explicit 0 disables the cap.
// A value that cannot be honored is treated as unset, so a bad file cannot take a
// credential out of service; the management API rejects it at write time instead.
func credentialConcurrencyLimit(auth *Auth) int {
	if auth == nil {
		return 0
	}
	if raw, ok := auth.Metadata[AttributeMaxConcurrency]; ok {
		if limit, errParse := ParseAuthMaxConcurrency(raw); errParse == nil {
			return limit
		}
	}
	if raw, ok := auth.Attributes[AttributeMaxConcurrency]; ok {
		if limit, errParse := ParseAuthMaxConcurrency(raw); errParse == nil {
			return limit
		}
	}
	return providerDefaultMaxConcurrency(auth.Provider)
}

// ParseAuthMaxConcurrency reads one stored max_concurrency value.
//
// The value comes from a JSON auth file or from the management API, so it may
// arrive as a number, a numeric string, or a json.Number. Only whole numbers are
// accepted: a fractional cap has no meaning here and silently rounding it would
// make the panel and the gate disagree about the effective limit.
func ParseAuthMaxConcurrency(raw any) (int, error) {
	var text string
	switch value := raw.(type) {
	case nil:
		return 0, fmt.Errorf("max_concurrency is empty")
	case string:
		text = strings.TrimSpace(value)
	case int:
		text = strconv.Itoa(value)
	case int64:
		text = strconv.FormatInt(value, 10)
	case float64:
		if value != float64(int(value)) {
			return 0, fmt.Errorf("max_concurrency must be a whole number")
		}
		text = strconv.FormatInt(int64(value), 10)
	case bool:
		return 0, fmt.Errorf("max_concurrency must be a number")
	default:
		text = strings.TrimSpace(fmt.Sprint(value))
	}
	if text == "" {
		return 0, fmt.Errorf("max_concurrency is empty")
	}
	limit, errParse := strconv.Atoi(text)
	if errParse != nil {
		return 0, fmt.Errorf("max_concurrency must be a whole number")
	}
	if limit < 0 {
		return 0, fmt.Errorf("max_concurrency must not be negative")
	}
	return limit, nil
}

// ParseAuthModelMaxConcurrency reads the per-model concurrency table stored on a
// credential and returns it keyed by normalized model name.
//
// The stored shape is a list of {"model", "max_concurrency"} objects, but the
// {model: limit} object shape and a JSON string carrying either of them are
// accepted too, because auth files are also edited by hand. An entry that cannot
// be honored is skipped instead of failing the whole table: a bad file must not
// take a credential out of service. A later entry for the same model wins.
//
// The returned map is never nil and empty means "no per-model cap configured",
// which falls back to the scalar max_concurrency and then to the provider
// default.
func ParseAuthModelMaxConcurrency(raw any) (map[string]int, error) {
	limits := make(map[string]int)
	switch value := raw.(type) {
	case nil:
		return limits, nil
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return limits, nil
		}
		var decoded any
		if errUnmarshal := json.Unmarshal([]byte(trimmed), &decoded); errUnmarshal != nil {
			return limits, fmt.Errorf(`model_max_concurrency must be a list of {"model", "max_concurrency"} objects`)
		}
		return ParseAuthModelMaxConcurrency(decoded)
	case []any:
		for _, item := range value {
			addModelConcurrencyEntry(limits, item)
		}
		return limits, nil
	case []map[string]any:
		for _, item := range value {
			addModelConcurrencyEntry(limits, item)
		}
		return limits, nil
	case map[string]any:
		for model, limitRaw := range value {
			key := credentialModelCapKey(model)
			if key == "" {
				continue
			}
			limit, errLimit := ParseAuthMaxConcurrency(limitRaw)
			if errLimit != nil {
				continue
			}
			limits[key] = limit
		}
		return limits, nil
	default:
		return limits, fmt.Errorf(`model_max_concurrency must be a list of {"model", "max_concurrency"} objects`)
	}
}

// addModelConcurrencyEntry folds one stored entry into the table, ignoring an
// entry the gate could not honor.
func addModelConcurrencyEntry(limits map[string]int, item any) {
	entry, okEntry := item.(map[string]any)
	if !okEntry || entry == nil || limits == nil {
		return
	}
	model, _ := entry["model"].(string)
	key := credentialModelCapKey(model)
	if key == "" {
		return
	}
	limit, errLimit := ParseAuthMaxConcurrency(entry["max_concurrency"])
	if errLimit != nil {
		return
	}
	limits[key] = limit
}

// credentialModelCapKey normalizes a model name into the key the per-model table
// is stored under.
//
// It folds case on top of the canonical model name because a client sends the
// model with whatever case it likes while the operator types the name into the
// panel, and a cap that only matches one spelling would silently not apply.
func credentialModelCapKey(model string) string {
	return strings.ToLower(canonicalModelKey(model))
}

// credentialModelConcurrencyLimits reads the per-model table from an auth.
// Metadata wins over Attributes, matching how the scalar cap is resolved.
func credentialModelConcurrencyLimits(auth *Auth) map[string]int {
	if auth == nil {
		return nil
	}
	if raw, ok := auth.Metadata[AttributeModelMaxConcurrency]; ok {
		if limits, errParse := ParseAuthModelMaxConcurrency(raw); errParse == nil && len(limits) > 0 {
			return limits
		}
	}
	if raw, ok := auth.Attributes[AttributeModelMaxConcurrency]; ok {
		if limits, errParse := ParseAuthModelMaxConcurrency(raw); errParse == nil && len(limits) > 0 {
			return limits
		}
	}
	return nil
}

// credentialConcurrencyLimitForModel resolves the cap for one credential serving
// routeModel.
//
// A model listed in the per-model table wins over the scalar cap, whether it was
// matched through the upstream model name or through the requested one (prefix
// and alias rewriting can make the two differ). Everything else falls back to the
// scalar max_concurrency and then to the provider default, so a credential with
// no table behaves exactly as before.
func (m *Manager) credentialConcurrencyLimitForModel(auth *Auth, routeModel string) int {
	if auth == nil {
		return 0
	}
	limits := credentialModelConcurrencyLimits(auth)
	if len(limits) == 0 {
		return credentialConcurrencyLimit(auth)
	}
	candidates := []string{m.selectionModelKeyForAuth(auth, routeModel), canonicalModelKey(routeModel)}
	for _, candidate := range candidates {
		key := credentialModelCapKey(candidate)
		if key == "" {
			continue
		}
		if limit, okLimit := limits[key]; okLimit {
			return limit
		}
	}
	return credentialConcurrencyLimit(auth)
}

// credentialCapScopeKey is the counting key for one credential and one model.
// An empty model key degrades to the credential-level key, which is what a
// request without a model name gets.
func credentialCapScopeKey(auth *Auth, modelKey string) string {
	key := credentialConcurrencyKey(auth)
	if key == "" || modelKey == "" {
		return key
	}
	return key + "|" + modelKey
}

// credentialCapScope resolves the counting key and the cap for one credential
// serving routeModel.
//
// Saturation checks and reservations must agree on the key: a request that was
// refused by the slot it already holds would spill for no reason.
func (m *Manager) credentialCapScope(auth *Auth, routeModel string) (string, int) {
	limit := m.credentialConcurrencyLimitForModel(auth, routeModel)
	if strings.TrimSpace(routeModel) == "" {
		return credentialCapScopeKey(auth, ""), limit
	}
	modelKey := credentialModelCapKey(m.selectionModelKeyForAuth(auth, routeModel))
	if modelKey == "" {
		modelKey = credentialModelCapKey(routeModel)
	}
	return credentialCapScopeKey(auth, modelKey), limit
}

// credentialConcurrencyKey identifies the thing a cap applies to.
//
// It is the source auth file, not auth.ID, because one file can expand into
// several Auth values (a plugin-owned source, AttributeVirtualSource). Counting
// per ID would multiply the effective cap by however many Auths that file
// produced. No plugin does this today, but the counting key must not depend on
// that staying true.
func credentialConcurrencyKey(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if source := strings.TrimSpace(auth.Attributes[AttributeVirtualSource]); source != "" {
		return "src:" + source
	}
	if path := strings.TrimSpace(auth.Attributes[AttributePath]); path != "" {
		return "src:" + path
	}
	return "id:" + strings.TrimSpace(auth.ID)
}

// credentialConcurrencyGate counts in-flight requests per credential.
//
// The map is created lazily so Manager needs no constructor change, and every
// access goes through the mutex: check-then-take races are resolved here rather
// than by trusting the availability snapshot, which is taken under a different
// lock and released before selection runs.
type credentialConcurrencyGate struct {
	mu       sync.Mutex
	inFlight map[string]int
}

func (g *credentialConcurrencyGate) tryAcquire(key string, limit int) bool {
	if key == "" || limit <= 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.inFlight == nil {
		g.inFlight = make(map[string]int)
	}
	if g.inFlight[key] >= limit {
		return false
	}
	g.inFlight[key]++
	return true
}

func (g *credentialConcurrencyGate) release(key string, limit int) {
	if key == "" || limit <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	current := g.inFlight[key]
	if current <= 1 {
		delete(g.inFlight, key)
		return
	}
	g.inFlight[key] = current - 1
}

func (g *credentialConcurrencyGate) saturated(key string, limit int) bool {
	if key == "" || limit <= 0 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight[key] >= limit
}

func (g *credentialConcurrencyGate) usage(key string) int {
	if key == "" {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight[key]
}

// CredentialConcurrencyUsage is a read-only view of one credential's admission
// state, for the panel to show "in flight / cap" without guessing.
type CredentialConcurrencyUsage struct {
	InFlight int
	Limit    int
}

// credentialCapLedger tracks the slot one request holds.
//
// A request touches at most one credential at a time: when it fails over it moves
// to another credential, so the previous slot is released as the new one is
// taken. Holding every attempted credential's slot would let a single request
// occupy the whole pool.
type credentialCapLedger struct {
	mu       sync.Mutex
	gate     *credentialConcurrencyGate
	key      string
	limit    int
	detached bool
}

type credentialCapLedgerKey struct{}

func withCredentialCapLedger(ctx context.Context, ledger *credentialCapLedger) context.Context {
	if ledger == nil {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, credentialCapLedgerKey{}, ledger)
}

func credentialCapLedgerFromContext(ctx context.Context) *credentialCapLedger {
	if ctx == nil {
		return nil
	}
	ledger, _ := ctx.Value(credentialCapLedgerKey{}).(*credentialCapLedger)
	return ledger
}

// newCredentialCapLedger starts the ledger for one request. It returns nil when
// admission control does not apply, which keeps Home mode explicitly out of
// scope: Home owns its own dispatch and concurrency accounting, and silently
// running a second limiter on top of it would make the two disagree.
func (m *Manager) newCredentialCapLedger() *credentialCapLedger {
	if m == nil || m.HomeEnabled() {
		return nil
	}
	return &credentialCapLedger{gate: &m.credentialCap}
}

// hold reserves a slot for key. It returns false when the credential is already
// at its cap, in which case the caller must pick another credential; that is a
// normal outcome, not an error.
func (l *credentialCapLedger) hold(key string, limit int) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.key == key {
		return true
	}
	if !l.gate.tryAcquire(key, limit) {
		return false
	}
	previousKey, previousLimit := l.key, l.limit
	l.key, l.limit = key, limit
	if previousKey != "" {
		l.gate.release(previousKey, previousLimit)
	}
	return true
}

// release frees the held slot. It is safe to call more than once and after detach.
func (l *credentialCapLedger) release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.releaseLocked()
}

func (l *credentialCapLedger) releaseLocked() {
	if l.key == "" {
		return
	}
	l.gate.release(l.key, l.limit)
	l.key, l.limit = "", 0
}

// detach transfers ownership of the held slot to a stream pump. The request
// handler must stop releasing after this point: for a stream the request is not
// over when ExecuteStream returns, it is over when the last chunk is delivered.
//
// It reports true only for the call that actually took ownership, so the pump
// releases exactly once even if the stream is wrapped more than once.
func (l *credentialCapLedger) detach() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.detached || l.key == "" {
		return false
	}
	l.detached = true
	return true
}

// releaseUnlessDetached frees the slot for a request that ends in this call
// frame. A detached ledger is owned by a stream pump and must not be freed here.
func (l *credentialCapLedger) releaseUnlessDetached() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.detached {
		return
	}
	l.releaseLocked()
}

// holds reports whether this request already owns a slot on key. A credential the
// request already holds must not be treated as saturated by its own slot, or a
// failover retry would refuse to reuse the credential it is already admitted to.
func (l *credentialCapLedger) holds(key string) bool {
	if l == nil || key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.key == key
}

// holdCredentialSlot reserves this request's concurrency slot on auth. It reports
// false when the credential is already at its cap; that is a normal outcome the
// caller resolves by selecting another credential.
//
// The reservation lives in a per-request ledger carried by ctx, so it is released
// exactly once, when the request ends.
func (m *Manager) holdCredentialSlot(ctx context.Context, auth *Auth, routeModel string) bool {
	ledger := credentialCapLedgerFromContext(ctx)
	if ledger == nil || auth == nil || m == nil {
		return true
	}
	key, limit := m.credentialCapScope(auth, routeModel)
	return ledger.hold(key, limit)
}

// credentialConcurrencyLimitFor resolves the cap for an auth the manager is about
// to use. It is the model-agnostic fallback; the gate itself resolves the cap per
// model through credentialConcurrencyLimitForModel.
func (m *Manager) credentialConcurrencyLimitFor(auth *Auth) int {
	return credentialConcurrencyLimit(auth)
}

// credentialCapSaturated reports whether the credential has no free slot for this
// request. It is a snapshot: the authoritative decision is the reservation taken
// by hold().
func (m *Manager) credentialCapSaturated(ctx context.Context, auth *Auth, routeModel string) bool {
	if m == nil || m.HomeEnabled() || auth == nil {
		return false
	}
	key, limit := m.credentialCapScope(auth, routeModel)
	if key == "" || limit <= 0 {
		return false
	}
	if credentialCapLedgerFromContext(ctx).holds(key) {
		return false
	}
	return m.credentialCap.saturated(key, limit)
}

// admitCredentialConcurrency removes saturated credentials from the candidate
// lists and reports which ones were removed, so the selector can leave an
// affinity binding in place instead of migrating it to another credential.
//
// When every candidate is saturated the pool is genuinely full: the request waits
// up to credentialCapQueueWait for a slot and then fails with the same busy error
// shape Home uses, which short-circuits retry rounds and emits Retry-After.
func (m *Manager) admitCredentialConcurrency(ctx context.Context, available, selectorAuths []*Auth, routeModel string) ([]*Auth, []*Auth, map[string]struct{}, error) {
	if m == nil || m.HomeEnabled() || len(selectorAuths) == 0 {
		return available, selectorAuths, nil, nil
	}
	deadline := time.Now().Add(m.credentialCapQueueWaitForTest())
	for {
		admittedSelector := make([]*Auth, 0, len(selectorAuths))
		saturated := make(map[string]struct{})
		for _, auth := range selectorAuths {
			if auth == nil {
				continue
			}
			if m.credentialCapSaturated(ctx, auth, routeModel) {
				saturated[auth.ID] = struct{}{}
				continue
			}
			admittedSelector = append(admittedSelector, auth)
		}
		if len(admittedSelector) > 0 {
			if len(saturated) == 0 {
				return available, selectorAuths, nil, nil
			}
			admittedAvailable := make([]*Auth, 0, len(available))
			for _, auth := range available {
				if auth == nil {
					continue
				}
				if _, isSaturated := saturated[auth.ID]; isSaturated {
					continue
				}
				admittedAvailable = append(admittedAvailable, auth)
			}
			if len(admittedAvailable) == 0 {
				// Every credential in the highest priority tier is busy while a lower
				// tier has room. Hand the scheduler the credentials that do have
				// capacity: refusing the request because its preferred tier is full
				// would defeat the point of spilling.
				admittedAvailable = admittedSelector
			}
			return admittedAvailable, admittedSelector, saturated, nil
		}
		if !time.Now().Before(deadline) {
			return nil, nil, nil, newCredentialConcurrencyBusyError(len(saturated))
		}
		if !waitForCredentialCap(ctx, m.credentialCapPollIntervalForTest()) {
			return nil, nil, nil, newCredentialConcurrencyBusyError(len(saturated))
		}
	}
}

func waitForCredentialCap(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	if ctx == nil {
		<-timer.C
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// newCredentialConcurrencyBusyError builds the terminal "pool is full" error.
//
// It reuses the Home busy error type on purpose. That type already means
// "admission was refused by a concurrency limit", and the rest of the pipeline
// already treats it correctly: retry rounds short-circuit instead of waiting for a
// cooldown that will never help, and the response carries Retry-After. A 503 plus
// a cooldown wait — what the generic unavailable error produces — would be the
// wrong shape for a pool that is merely busy.
func newCredentialConcurrencyBusyError(saturatedCount int) error {
	message := "every eligible credential is at its concurrency limit"
	if saturatedCount > 0 {
		message = fmt.Sprintf("all %d eligible credentials are at their concurrency limit", saturatedCount)
	}
	return NewHomeConcurrencyBusyError(message, credentialCapQueueWait)
}

// credentialCapQueueWaitForTest and credentialCapPollIntervalForTest keep the
// wall-clock wait out of unit tests, where it would only add latency and
// flakiness. Production values are the constants above.
func (m *Manager) credentialCapQueueWaitForTest() time.Duration {
	if m != nil && m.credentialCapQueueWait > 0 {
		return m.credentialCapQueueWait
	}
	return credentialCapQueueWait
}

func (m *Manager) credentialCapPollIntervalForTest() time.Duration {
	if m != nil && m.credentialCapPollInterval > 0 {
		return m.credentialCapPollInterval
	}
	return credentialCapPollInterval
}

// credentialCapPressure reports whether any credential that could serve these
// providers is at its concurrency cap for this model right now.
//
// The scheduler fast path in pickNext/pickNextMixed selects without admission
// control, so a pick made under pressure is handed to the legacy path, which
// removes saturated credentials from the candidate list before selecting. That
// keeps a single implementation of admission instead of two: the fast path stays
// the cheap path while the pool has room, and the general path takes over exactly
// when a pick has to reason about capacity.
//
// The check is per credential and per model: a credential that is full on one
// model must not make the whole provider look full, or every request would be
// routed through the legacy path for no reason.
func (m *Manager) credentialCapPressure(providers []string, routeModel string) bool {
	if m == nil || m.HomeEnabled() {
		return false
	}
	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if key := canonicalSchedulingProvider(provider); key != "" {
			providerSet[key] = struct{}{}
		}
	}
	if len(providerSet) == 0 {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, auth := range m.auths {
		if auth == nil || auth.Disabled {
			continue
		}
		if _, okProvider := providerSet[canonicalSchedulingProvider(executorKeyFromAuth(auth))]; !okProvider {
			continue
		}
		if m.credentialCapSaturated(nil, auth, routeModel) {
			return true
		}
	}
	return false
}

// CredentialConcurrencySnapshot reports in-flight counts and caps for the given
// credentials and model. It is read-only and never blocks admission.
func (m *Manager) CredentialConcurrencySnapshot(auths []*Auth, routeModel string) map[string]CredentialConcurrencyUsage {
	out := make(map[string]CredentialConcurrencyUsage, len(auths))
	if m == nil || m.HomeEnabled() {
		return out
	}
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		key, limit := m.credentialCapScope(auth, routeModel)
		out[auth.ID] = CredentialConcurrencyUsage{
			InFlight: m.credentialCap.usage(key),
			Limit:    limit,
		}
	}
	return out
}
