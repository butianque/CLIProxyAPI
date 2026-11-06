package auth

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	homekv "github.com/router-for-me/CLIProxyAPI/v8/internal/home"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestFindAllAntigravityCreditsCandidateAuths_PrefersKnownCreditsThenUnknown(t *testing.T) {
	m := &Manager{
		auths: map[string]*Auth{
			"zz-credits": {ID: "zz-credits", Provider: "antigravity"},
			"aa-unknown": {ID: "aa-unknown", Provider: "antigravity"},
			"mm-no":      {ID: "mm-no", Provider: "antigravity"},
		},
		executors: map[string]ProviderExecutor{
			"antigravity": schedulerTestExecutor{},
		},
	}

	SetAntigravityCreditsHint("zz-credits", AntigravityCreditsHint{
		Known:     true,
		Available: true,
		UpdatedAt: time.Now(),
	})
	SetAntigravityCreditsHint("mm-no", AntigravityCreditsHint{
		Known:     true,
		Available: false,
		UpdatedAt: time.Now(),
	})

	opts := cliproxyexecutor.Options{}

	candidates, errCandidates := m.findAllAntigravityCreditsCandidateAuths(context.Background(), "claude-sonnet-4-6", opts)
	if errCandidates != nil {
		t.Fatalf("findAllAntigravityCreditsCandidateAuths() error = %v", errCandidates)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates len = %d, want 2", len(candidates))
	}
	if candidates[0].auth.ID != "zz-credits" {
		t.Fatalf("candidates[0].auth.ID = %q, want %q", candidates[0].auth.ID, "zz-credits")
	}
	if candidates[1].auth.ID != "aa-unknown" {
		t.Fatalf("candidates[1].auth.ID = %q, want %q", candidates[1].auth.ID, "aa-unknown")
	}

	nonClaude, errNonClaude := m.findAllAntigravityCreditsCandidateAuths(context.Background(), "gemini-3-flash", opts)
	if errNonClaude != nil {
		t.Fatalf("findAllAntigravityCreditsCandidateAuths(non claude) error = %v", errNonClaude)
	}
	if len(nonClaude) != 0 {
		t.Fatalf("nonClaude len = %d, want 0", len(nonClaude))
	}

	pinnedOpts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: "aa-unknown"},
	}
	pinned, errPinned := m.findAllAntigravityCreditsCandidateAuths(context.Background(), "claude-sonnet-4-6", pinnedOpts)
	if errPinned != nil {
		t.Fatalf("findAllAntigravityCreditsCandidateAuths(pinned) error = %v", errPinned)
	}
	if len(pinned) != 1 {
		t.Fatalf("pinned len = %d, want 1", len(pinned))
	}
	if pinned[0].auth.ID != "aa-unknown" {
		t.Fatalf("pinned[0].auth.ID = %q, want %q", pinned[0].auth.ID, "aa-unknown")
	}
}

func TestFindAllAntigravityCreditsCandidateAuths_HomeKVUnavailableReturnsError(t *testing.T) {
	homekv.SetCurrent(homekv.New(internalconfig.HomeConfig{Enabled: false}))
	t.Cleanup(homekv.ClearCurrent)

	m := &Manager{
		auths: map[string]*Auth{
			"ag-home-kv": {ID: "ag-home-kv", Provider: "antigravity"},
		},
		executors: map[string]ProviderExecutor{
			"antigravity": schedulerTestExecutor{},
		},
	}

	candidates, errCandidates := m.findAllAntigravityCreditsCandidateAuths(context.Background(), "claude-sonnet-4-6", cliproxyexecutor.Options{})
	if errCandidates == nil {
		t.Fatalf("findAllAntigravityCreditsCandidateAuths() error = nil, candidates=%#v", candidates)
	}
	if status := statusCodeFromError(errCandidates); status != http.StatusServiceUnavailable {
		t.Fatalf("statusCodeFromError() = %d, want %d; err=%v", status, http.StatusServiceUnavailable, errCandidates)
	}
	if !strings.Contains(errCandidates.Error(), "home kv store unavailable") {
		t.Fatalf("error = %v, want home kv store unavailable", errCandidates)
	}
}

// TestFindAllAntigravityCreditsCandidateAuths_RespectsKeyPoolScope pins the
// invariant credential selection documents for scoped keys: "a restricted key
// never silently falls back onto an unrelated credential". The credits fallback
// rebuilds its own candidate set, so it has to apply the key's pool scope itself;
// nothing upstream narrows this list.
func TestFindAllAntigravityCreditsCandidateAuths_RespectsKeyPoolScope(t *testing.T) {
	m := &Manager{
		auths: map[string]*Auth{
			"ag-in":  {ID: "ag-in", FileName: "ag-in.json", Provider: "antigravity"},
			"ag-out": {ID: "ag-out", FileName: "ag-out.json", Provider: "antigravity"},
		},
		executors: map[string]ProviderExecutor{
			"antigravity": schedulerTestExecutor{},
		},
	}

	candidateIDs := func(opts cliproxyexecutor.Options) []string {
		t.Helper()
		candidates, errCandidates := m.findAllAntigravityCreditsCandidateAuths(context.Background(), "claude-sonnet-4-6", opts)
		if errCandidates != nil {
			t.Fatalf("findAllAntigravityCreditsCandidateAuths() error = %v", errCandidates)
		}
		ids := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			ids = append(ids, candidate.auth.ID)
		}
		sort.Strings(ids)
		return ids
	}

	// A key scoped to one credential must not see another antigravity account.
	t.Run("scoped key sees only the credential it names", func(t *testing.T) {
		scoped := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "ag-in"}}
		if got := candidateIDs(scoped); strings.Join(got, ",") != "ag-in" {
			t.Fatalf("scoped candidates = %v, want [ag-in]: the credits fallback escaped the key's scope", got)
		}
	})

	// Without a scope every antigravity credential stays a candidate.
	t.Run("unscoped key sees every credential", func(t *testing.T) {
		if got := candidateIDs(cliproxyexecutor.Options{}); strings.Join(got, ",") != "ag-in,ag-out" {
			t.Fatalf("unscoped candidates = %v, want [ag-in ag-out]", got)
		}
	})

	// Pinning a credential outside the scope must leave no candidate at all.
	t.Run("pinned credential outside scope yields none", func(t *testing.T) {
		pinned := cliproxyexecutor.Options{Metadata: map[string]any{
			cliproxyexecutor.AllowedPoolsMetadataKey: "ag-in",
			cliproxyexecutor.PinnedAuthMetadataKey:   "ag-out",
		}}
		if got := candidateIDs(pinned); len(got) != 0 {
			t.Fatalf("pinned + scoped candidates = %v, want none", got)
		}
	})
}
