package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// A scoped caller that cannot reach any credential must be told which scope hid
// the candidates. Without the scope in the message, a misconfigured scope looks
// exactly like a missing credential, and the fast path is the only place an
// operator can tell them apart.
func TestSchedulerScopeExclusionIsNamedInError(t *testing.T) {
	ctx := context.Background()
	const model = "scope-error-model"
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "loomy"})
	auth := &Auth{ID: "loomy-main", FileName: "loomy-main.json", Provider: "loomy"}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	registerSchedulerModels(t, "loomy", model, auth.ID)
	manager.RefreshSchedulerEntry(auth.ID)

	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.AllowedPoolsMetadataKey: "zcode-bigmodel",
	}}
	_, errPick := manager.scheduler.pickSingle(ctx, "loomy", model, opts, nil)
	if errPick == nil {
		t.Fatal("pickSingle() error = nil, want the scoped request to fail")
	}
	var authErr *Error
	if !errors.As(errPick, &authErr) || authErr == nil {
		t.Fatalf("pickSingle() error = %v, want an *Error", errPick)
	}
	if !strings.Contains(authErr.Message, "outside the key's scope") {
		t.Fatalf("message = %q, want it to say the credential is outside the scope", authErr.Message)
	}
	if !strings.Contains(authErr.Message, "zcode-bigmodel") {
		t.Fatalf("message = %q, want it to name the scoped entry", authErr.Message)
	}
}

// The scope clause is added only when a scope actually hid candidates. An
// unscoped request keeps the wording it had before.
func TestSchedulerUnscopedErrorKeepsOriginalWording(t *testing.T) {
	ctx := context.Background()
	const model = "unscoped-error-model"
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "loomy"})
	auth := &Auth{ID: "loomy-main", FileName: "loomy-main.json", Provider: "loomy"}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	registerSchedulerModels(t, "loomy", model, auth.ID)
	manager.RefreshSchedulerEntry(auth.ID)

	// Ask for a model no credential covers so the pick has to fail.
	_, errPick := manager.scheduler.pickSingle(ctx, "loomy", "model-nobody-covers", cliproxyexecutor.Options{}, nil)
	if errPick == nil {
		t.Fatal("pickSingle() error = nil, want the uncovered model to fail")
	}
	var authErr *Error
	if !errors.As(errPick, &authErr) || authErr == nil {
		t.Fatalf("pickSingle() error = %v, want an *Error", errPick)
	}
	if strings.Contains(authErr.Message, "outside the key's scope") || strings.Contains(authErr.Message, "in scope") {
		t.Fatalf("message = %q, want no scope clause for an unscoped request", authErr.Message)
	}
	if !strings.Contains(authErr.Message, "loomy") {
		t.Fatalf("message = %q, want it to still name the provider", authErr.Message)
	}
}

// Pool membership is matched case-insensitively and ignores padding, so a
// hand-written entry that differs only in case still resolves to the credential
// it names. Blank entries are dropped rather than stored as an empty key.
func TestCredentialPoolMembersAreNormalized(t *testing.T) {
	t.Cleanup(func() { setCredentialPools(nil) })

	setCredentialPools(map[string][]string{
		" Loomy ": {"  Loomy-Main  ", "", "   ", "own-7598"},
	})

	for _, tc := range []struct {
		pool string
		name string
		want bool
	}{
		{"loomy", "loomy-main", true},
		{"LOOMY", "  Loomy-Main ", true},
		{"loomy", "own-7598", true},
		{"loomy", "", false},
		{"loomy", "other", false},
		{"zcode-bigmodel", "loomy-main", false},
	} {
		if got := credentialContains(tc.pool, tc.name); got != tc.want {
			t.Fatalf("credentialContains(%q, %q) = %v, want %v", tc.pool, tc.name, got, tc.want)
		}
	}
}
