package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// poolAuth builds a credential addressed by its backing file name, which is how
// credential-pools identifies membership. There is no attribute: pool membership
// is declared in configuration, never inferred from a credential's provider.
func poolAuth(fileName string) *Auth {
	return &Auth{ID: fileName, FileName: fileName + ".json", Provider: "zcode"}
}

func TestCredentialNameUsesAuthFileBase(t *testing.T) {
	cases := []struct {
		name string
		auth *Auth
		want string
	}{
		{"file name wins over id", &Auth{ID: "ignored", FileName: "/creds/loomy-main.json"}, "loomy-main"},
		{"relative path", &Auth{ID: "ignored", FileName: "/tmp/my credential.json"}, "my credential"},
		{"falls back to id", &Auth{ID: "only-id"}, "only-id"},
		{"nil auth", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialName(tc.auth); got != tc.want {
				t.Fatalf("credentialName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAllowsCredentialUsesExplicitPoolTable(t *testing.T) {
	setCredentialPools(map[string][]string{
		"loomy":       {"loomy-main", "own-7598"},
		"zcode-free":  {"zcode-free-1"},
		"ZCODE-PAID!": {"zcode-paid-1"},
	})
	t.Cleanup(func() { setCredentialPools(nil) })

	cases := []struct {
		name    string
		auth    *Auth
		allowed []string
		want    bool
	}{
		{"unrestricted caller allows any credential", poolAuth("loomy-main"), nil, true},
		{"listed credential matches its pool", poolAuth("loomy-main"), []string{"loomy"}, true},
		{"another member of the same pool matches", poolAuth("own-7598"), []string{"loomy"}, true},
		{"unlisted credential is rejected", poolAuth("loomy-16723433586"), []string{"loomy"}, false},
		{"pool name is matched case-insensitively", poolAuth("zcode-paid-1"), []string{"zcode-paid!"}, true},
		{"wrong pool is rejected", poolAuth("loomy-main"), []string{"zcode-free"}, false},
		{"membership is not inferred from provider", poolAuth("loomy-unknown"), []string{"zcode"}, false},
		{"one of several scopes matches", poolAuth("zcode-free-1"), []string{"loomy", "zcode-free"}, true},
		{"nil auth with restriction is rejected", nil, []string{"loomy"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eligibility := authSelectionEligibility{allowedPools: tc.allowed}
			if got := eligibility.allows(tc.auth); got != tc.want {
				t.Fatalf("allows() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestAllowsCredentialRejectsEverythingWhenTableIsEmpty(t *testing.T) {
	// A scoped caller cannot match anything when no pool membership is declared.
	// This is the safety property: a restricted key must never silently fall back
	// onto an unrelated credential.
	setCredentialPools(nil)
	eligibility := authSelectionEligibility{allowedPools: []string{"loomy"}}
	if eligibility.allows(poolAuth("loomy-main")) {
		t.Fatal("a scoped caller was allowed through an empty credential-pools table")
	}
}

func TestSetCredentialPoolsPrunesAndNormalizes(t *testing.T) {
	setCredentialPools(map[string][]string{
		"  Loomy  ": {" loomy-main ", "", "own-7598"},
		"empty":     nil,
		"":          {"orphan"},
	})
	t.Cleanup(func() { setCredentialPools(nil) })

	if !credentialContains("loomy", "loomy-main") {
		t.Fatal("expected normalized pool name and trimmed credential to match")
	}
	if !credentialContains("loomy", "own-7598") {
		t.Fatal("expected second credential to match")
	}
	if credentialContains("empty", "anything") {
		t.Fatal("a pool with no members must not match")
	}
	if credentialContains("", "orphan") {
		t.Fatal("a blank pool name must be dropped")
	}
}

func TestAllowedPoolsFromMetadata(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]any
		want []string
	}{
		{"absent key", map[string]any{}, nil},
		{"empty string", map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: ""}, nil},
		{"whitespace string", map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "   "}, nil},
		{
			"normalizes case and blanks",
			map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: " Loomy , , zcode-bigmodel "},
			[]string{"loomy", "zcode-bigmodel"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := allowedPoolsFromMetadata(tc.meta)
			if len(got) != len(tc.want) {
				t.Fatalf("allowedPoolsFromMetadata() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("allowedPoolsFromMetadata() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestAuthSelectionEligibilityAppliesPoolScope(t *testing.T) {
	setCredentialPools(map[string][]string{"loomy": {"loomy-auth"}})
	t.Cleanup(func() { setCredentialPools(nil) })

	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "loomy"},
	}
	eligibility := authSelectionEligibilityForRequest(context.Background(), opts)

	if !eligibility.allows(poolAuth("loomy-auth")) {
		t.Fatal("expected the listed credential to be eligible for a loomy-scoped caller")
	}
	if eligibility.allows(poolAuth("zai-auth")) {
		t.Fatal("expected an unlisted credential to be ineligible for a loomy-scoped caller")
	}
}

func TestSelectAuthHonorsCredentialPoolScopeEndToEnd(t *testing.T) {
	const model = "glm-5.3"
	reg := registry.GetGlobalRegistry()

	loomyAuth := poolAuth("pool-loomy")
	loomyAuth.Provider = "loomy"
	zcodeAuth := poolAuth("pool-zcode")
	setCredentialPools(map[string][]string{
		"loomy":          {"pool-loomy"},
		"zcode-bigmodel": {"pool-zcode"},
	})
	t.Cleanup(func() { setCredentialPools(nil) })

	for _, auth := range []*Auth{loomyAuth, zcodeAuth} {
		reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		authID := auth.ID
		t.Cleanup(func() { reg.UnregisterClient(authID) })
	}

	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.executors["loomy"] = schedulerTestExecutor{}
	manager.executors["zcode"] = schedulerTestExecutor{}
	for _, auth := range []*Auth{loomyAuth, zcodeAuth} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
		}
	}

	// A loomy-scoped caller reaches only the loomy credential.
	loomyOpts := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "loomy"}}
	selected, errSelect := manager.SelectAuth(context.Background(), "loomy", model, loomyOpts)
	if errSelect != nil {
		t.Fatalf("SelectAuth(loomy scope) error = %v", errSelect)
	}
	if selected.ID != "pool-loomy" {
		t.Fatalf("SelectAuth(loomy scope) selected %q, want pool-loomy", selected.ID)
	}

	// A zcode-bigmodel-scoped caller cannot reach the loomy credential: the pool
	// table lists only pool-zcode, so there is nothing to select.
	if _, errWrong := manager.SelectAuth(context.Background(), "loomy", model, cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "zcode-bigmodel"},
	}); errWrong == nil {
		t.Fatal("SelectAuth(zcode scope on loomy provider) error = nil, want auth_not_found")
	} else {
		var authErr *Error
		if !errors.As(errWrong, &authErr) || authErr.Code != "auth_not_found" {
			t.Fatalf("SelectAuth(zcode scope on loomy provider) error = %v, want auth_not_found", errWrong)
		}
	}

	// An unrestricted caller can still reach both credentials.
	selectedZcode, errZcode := manager.SelectAuth(context.Background(), "zcode", model, cliproxyexecutor.Options{})
	if errZcode != nil {
		t.Fatalf("SelectAuth(unrestricted zcode) error = %v", errZcode)
	}
	if selectedZcode.ID != "pool-zcode" {
		t.Fatalf("SelectAuth(unrestricted zcode) selected %q, want pool-zcode", selectedZcode.ID)
	}
}
