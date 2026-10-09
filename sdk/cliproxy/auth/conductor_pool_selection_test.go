package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func poolAuth(id string, pools ...string) *Auth {
	attributes := map[string]string{}
	if len(pools) > 0 {
		joined := pools[0]
		for _, pool := range pools[1:] {
			joined += "," + pool
		}
		attributes[cliproxyexecutor.AuthPoolAttribute] = joined
	}
	return &Auth{ID: id, Provider: "zcode", Attributes: attributes}
}

func TestAuthMatchesAllowedPools(t *testing.T) {
	cases := []struct {
		name    string
		auth    *Auth
		allowed []string
		want    bool
	}{
		{"unrestricted caller allows untagged auth", poolAuth("a"), nil, true},
		{"unrestricted caller allows tagged auth", poolAuth("a", "loomy"), nil, true},
		{"restricted caller allows matching pool", poolAuth("a", "loomy"), []string{"loomy"}, true},
		{"restricted caller allows one of several auth pools", poolAuth("a", "loomy", "zcode-zai"), []string{"zcode-zai"}, true},
		{"restricted caller rejects other pool", poolAuth("a", "loomy"), []string{"zcode-bigmodel"}, false},
		{
			"untagged auth belongs to its provider pool",
			&Auth{ID: "a", Provider: "loomy"},
			[]string{"loomy"},
			true,
		},
		{
			"provider pool does not collide with platform pool",
			&Auth{ID: "a", Provider: "zcode"},
			[]string{"zcode-bigmodel"},
			false,
		},
		{"nil auth with restriction is rejected", nil, []string{"loomy"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authMatchesAllowedPools(tc.auth, tc.allowed); got != tc.want {
				t.Fatalf("authMatchesAllowedPools() = %t, want %t", got, tc.want)
			}
		})
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
	opts := cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "loomy"},
	}
	eligibility := authSelectionEligibilityForRequest(context.Background(), opts)

	if !eligibility.allows(poolAuth("loomy-auth", "loomy")) {
		t.Fatal("expected loomy credential to be eligible for a loomy-scoped caller")
	}
	if eligibility.allows(poolAuth("zai-auth", "zcode-zai")) {
		t.Fatal("expected zcode-zai credential to be ineligible for a loomy-scoped caller")
	}
	if eligibility.allows(poolAuth("untagged-auth")) {
		t.Fatal("expected untagged zcode credential to be ineligible for a loomy-scoped caller")
	}
}

func TestSelectAuthHonorsPoolScopeEndToEnd(t *testing.T) {
	const model = "glm-5.3"
	reg := registry.GetGlobalRegistry()

	loomyAuth := &Auth{ID: "pool-loomy", Provider: "loomy"}
	zcodeAuth := &Auth{ID: "pool-zcode", Provider: "zcode", Attributes: map[string]string{"pool": "zcode-bigmodel"}}
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

	// A zcode-bigmodel-scoped caller cannot reach the zcode credential through the
	// loomy provider, and vice versa: the provider name is not a pool alias.
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
