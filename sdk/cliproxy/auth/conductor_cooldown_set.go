package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

const (
	// maxSetCooldownDuration bounds a deadline a caller states directly. A plugin
	// reads a reset time from a provider, and a misread (a milliseconds value, a
	// date in the wrong century) would otherwise park a credential for years
	// with nothing to notice it. Thirty-one days is longer than any plan window
	// a provider reports.
	maxSetCooldownDuration = 31 * 24 * time.Hour
	// credentialQuotaReason is the reason token for a credential-wide cooldown.
	// The rest of the host keys on this exact string (selection, the panel, the
	// reset path), so a caller cannot choose it.
	credentialQuotaReason = "credential_quota"
	// modelQuotaReason is the reason token for a model-scoped quota cooldown,
	// matching what a quota failure on one model records.
	modelQuotaReason = "quota"
)

// extendCooldownDeadline returns the later of the deadline already in force and
// the one just reported. A cooldown never shortens: a second report saying
// "retry sooner" must not make the credential look healthier than the deadline
// already established from the first one. Clearing is ResetQuota's job.
func extendCooldownDeadline(current, reported time.Time) time.Time {
	if current.After(reported) {
		return current
	}
	return reported
}

// SetCooldown records an explicit cooldown for one credential, or for one model
// on it, until a stated time, and reports the deadline actually in force.
//
// It is the host's one way to accept a deadline learned outside a request: a
// plugin that reads a provider's 429 Retry-After, or a quota response that says
// when the plan refills, reports it here instead of keeping a second clock. The
// routing decision and the reported state then come from the same store, which
// is what a credential-wide and a model-wide view of "when can I retry" needs.
//
// A deadline in the past is rejected rather than treated as a clear, because the
// caller that wanted a clear would have asked for one. An existing later
// deadline is kept. Empty model means the whole credential.
func (m *Manager) SetCooldown(ctx context.Context, authID, model string, until time.Time, reason string) (*Auth, []string, time.Time, error) {
	if m == nil {
		return nil, nil, time.Time{}, nil
	}
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return nil, nil, time.Time{}, fmt.Errorf("auth id is required")
	}
	if until.IsZero() {
		return nil, nil, time.Time{}, fmt.Errorf("cooldown deadline is required")
	}
	now := time.Now()
	until = until.UTC().Round(0)
	if !until.After(now) {
		return nil, nil, time.Time{}, fmt.Errorf("cooldown deadline %s is not in the future", until.Format(time.RFC3339))
	}
	if until.Sub(now) > maxSetCooldownDuration {
		until = now.Add(maxSetCooldownDuration)
	}
	modelKey := canonicalModelKey(model)
	reason = strings.TrimSpace(reason)

	var snapshot *Auth
	var effective time.Time
	models := make([]string, 0, 1)
	cooldownStateChanged := false

	releaseMutation := m.lockAuthMutation(authID)
	defer releaseMutation()
	m.mu.Lock()
	auth, ok := m.auths[authID]
	if !ok || auth == nil {
		m.mu.Unlock()
		return nil, nil, time.Time{}, nil
	}

	var cooldownRecordsBefore []CooldownStateRecord
	trackCooldownState := m.cooldownStore != nil
	if trackCooldownState {
		cooldownRecordsBefore = m.cooldownStateRecordsForAuthLocked(auth, now)
	}

	if modelKey == "" {
		// Credential scope: the provider rejected the credential itself (a spent
		// plan, a revoked key), so every model on it is out until the deadline.
		auth.Unavailable = true
		auth.NextRetryAfter = extendCooldownDeadline(auth.NextRetryAfter, until)
		applyCooldownFields(&auth.Quota, QuotaState{
			Exceeded:      true,
			Reason:        credentialQuotaReason,
			NextRecoverAt: extendCooldownDeadline(auth.Quota.NextRecoverAt, until),
			BackoffLevel:  auth.Quota.BackoffLevel,
		})
		if auth.Status != StatusDisabled {
			auth.Status = StatusError
		}
		for stateKey, state := range auth.ModelStates {
			if state == nil {
				continue
			}
			models = append(models, stateKey)
			state.Unavailable = true
			state.NextRetryAfter = extendCooldownDeadline(state.NextRetryAfter, until)
			applyCooldownFields(&state.Quota, QuotaState{
				Exceeded:      true,
				Reason:        credentialQuotaReason,
				NextRecoverAt: extendCooldownDeadline(state.Quota.NextRecoverAt, until),
				BackoffLevel:  state.Quota.BackoffLevel,
			})
			if state.Status != StatusDisabled {
				state.Status = StatusError
			}
			state.UpdatedAt = now
		}
		// A credential with no model state keeps its credential-level cooldown;
		// aggregation would otherwise treat "no models" as "nothing is down" and
		// clear what was just set.
		if len(auth.ModelStates) > 0 {
			updateAggregatedAvailability(auth, now)
		}
		effective = extendCooldownDeadline(auth.NextRetryAfter, auth.Quota.NextRecoverAt)
	} else {
		state := ensureModelState(auth, modelKey)
		if state == nil {
			m.mu.Unlock()
			return nil, nil, time.Time{}, fmt.Errorf("model %q cannot be cooled down", modelKey)
		}
		models = append(models, modelKey)
		state.Unavailable = true
		state.NextRetryAfter = extendCooldownDeadline(state.NextRetryAfter, until)
		quotaReason := modelQuotaReason
		if reason != "" {
			quotaReason = reason
		}
		applyCooldownFields(&state.Quota, QuotaState{
			Exceeded:      true,
			Reason:        quotaReason,
			NextRecoverAt: extendCooldownDeadline(state.Quota.NextRecoverAt, until),
			BackoffLevel:  state.Quota.BackoffLevel,
		})
		if state.Status != StatusDisabled {
			state.Status = StatusError
		}
		state.UpdatedAt = now
		updateAggregatedAvailability(auth, now)
		effective = state.NextRetryAfter
	}

	auth.Generation++
	auth.UpdatedAt = now
	snapshot = auth.Clone()
	if trackCooldownState {
		cooldownRecordsAfter := m.cooldownStateRecordsForAuthLocked(auth, now)
		cooldownStateChanged = !cooldownStateRecordsEqual(cooldownRecordsBefore, cooldownRecordsAfter)
	}
	errPersist := m.persistLocked(ctx, auth)
	m.mu.Unlock()
	releaseMutation()

	if cooldownStateChanged {
		m.persistCooldownStates(context.Background())
	}
	if m.scheduler != nil && snapshot != nil {
		m.scheduler.upsertAuthResult(snapshot, models, modelKey == "")
	}
	if snapshot != nil {
		supportedModels, regEpoch := registry.GetGlobalRegistry().GetModelsAndEpochForClient(authID)
		projections := make([]registry.ClientModelProjection, 0, len(supportedModels))
		for _, supportedModel := range supportedModels {
			if supportedModel == nil || strings.TrimSpace(supportedModel.ID) == "" {
				continue
			}
			projections = append(projections, m.clientModelProjectionForAuth(snapshot, supportedModel.ID, now))
		}
		registry.GetGlobalRegistry().ApplyClientModelProjections(authID, regEpoch, snapshot.Generation, projections)
	}
	if errPersist != nil {
		return nil, nil, time.Time{}, errPersist
	}
	return snapshot, models, effective, nil
}
