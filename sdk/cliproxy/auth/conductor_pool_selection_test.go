package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// poolAuth builds a credential addressed by its backing file name, which is how
// the credential-pools table identifies membership. Its provider is the account
// category a scope entry may also name.
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
		{"scope names the credential's category", poolAuth("unlisted"), []string{"zcode"}, true},
		{"scope names this credential directly", &Auth{ID: "ignored", FileName: "/creds/zcode-main.json", Provider: "zcode"}, []string{"zcode-main"}, true},
		{"scope names another credential", &Auth{ID: "ignored", FileName: "/creds/zcode-main.json", Provider: "zcode"}, []string{"unlisted"}, false},
		{"another category is rejected", &Auth{ID: "l", FileName: "l.json", Provider: "loomy"}, []string{"zcode"}, false},
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

func TestAllowsCredentialScopesByCategoryWithoutPoolTable(t *testing.T) {
	// A scope entry that names an account category needs no declared membership:
	// the category is the credential's provider, so it follows the live credential
	// set. This is what makes a scoped key track accounts being added or removed
	// without a configuration write.
	setCredentialPools(nil)

	if !(authSelectionEligibility{allowedPools: []string{"zcode"}}).allows(poolAuth("any-name")) {
		t.Fatal("a key scoped to the credential's category must be allowed through an empty pool table")
	}
	if (authSelectionEligibility{allowedPools: []string{"loomy"}}).allows(poolAuth("any-name")) {
		t.Fatal("a key scoped to another category must not reach a zcode credential")
	}
	// The safety property: a scope that matches neither a category nor a pool
	// entry allows nothing, so a restricted key never silently falls back onto an
	// unrelated credential.
	if (authSelectionEligibility{allowedPools: []string{"no-such-category"}}).allows(poolAuth("any-name")) {
		t.Fatal("an unmatched scope must reject every credential")
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

	// A zcode-bigmodel-scoped caller cannot reach the loomy credential: neither the
	// declared pool nor the category matches, so there is nothing to select. The
	// error must name the scope, otherwise the caller cannot tell a misconfigured
	// scope apart from a missing credential.
	if _, errWrong := manager.SelectAuth(context.Background(), "loomy", model, cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "zcode-bigmodel"},
	}); errWrong == nil {
		t.Fatal("SelectAuth(zcode scope on loomy provider) error = nil, want auth_not_found")
	} else {
		var authErr *Error
		if !errors.As(errWrong, &authErr) || authErr.Code != "auth_not_found" {
			t.Fatalf("SelectAuth(zcode scope on loomy provider) error = %v, want auth_not_found", errWrong)
		}
		if !strings.Contains(authErr.Message, "outside the key's scope") {
			t.Fatalf("SelectAuth(zcode scope on loomy provider) message = %q, want it to name the scope", authErr.Message)
		}
		if !strings.Contains(authErr.Message, "zcode-bigmodel") {
			t.Fatalf("SelectAuth(zcode scope on loomy provider) message = %q, want it to name the scoped entry", authErr.Message)
		}
	}

	// Without a scope the same miss keeps the plain message: nothing was excluded
	// by scoping, so naming the scope would be misleading.
	if _, errPlain := manager.SelectAuth(context.Background(), "loomy", "no-such-model", cliproxyexecutor.Options{}); errPlain == nil {
		t.Fatal("SelectAuth(unrestricted unknown model) error = nil, want auth_not_found")
	} else {
		var authErr *Error
		if !errors.As(errPlain, &authErr) || authErr.Code != "auth_not_found" {
			t.Fatalf("SelectAuth(unrestricted unknown model) error = %v, want auth_not_found", errPlain)
		}
		if strings.Contains(authErr.Message, "key's scope") {
			t.Fatalf("SelectAuth(unrestricted unknown model) message = %q, want no scope wording", authErr.Message)
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

func TestSelectAuthScopesByAccountCategoryEndToEnd(t *testing.T) {
	const model = "glm-5.3"
	reg := registry.GetGlobalRegistry()

	// No credential-pools table at all: the category alone has to decide.
	setCredentialPools(nil)

	loomyAuth := &Auth{ID: "cat-loomy", FileName: "cat-loomy.json", Provider: "loomy"}
	workbuddyAuth := &Auth{ID: "cat-wb", FileName: "cat-wb.json", Provider: "workbuddy-global"}
	for _, auth := range []*Auth{loomyAuth, workbuddyAuth} {
		reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		authID := auth.ID
		t.Cleanup(func() { reg.UnregisterClient(authID) })
	}

	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.executors["loomy"] = schedulerTestExecutor{}
	manager.executors["workbuddy-global"] = schedulerTestExecutor{}
	for _, auth := range []*Auth{loomyAuth, workbuddyAuth} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
		}
	}

	// Each category reaches exactly its own credential, even though both serve the
	// same model through the same selector.
	for _, tc := range []struct{ category, want string }{
		{"loomy", "cat-loomy"},
		{"workbuddy-global", "cat-wb"},
	} {
		selected, errSelect := manager.SelectAuth(context.Background(), tc.category, model, cliproxyexecutor.Options{
			Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: tc.category},
		})
		if errSelect != nil {
			t.Fatalf("SelectAuth(%s scope) error = %v", tc.category, errSelect)
		}
		if selected.ID != tc.want {
			t.Fatalf("SelectAuth(%s scope) selected %q, want %q", tc.category, selected.ID, tc.want)
		}
	}

	// A scope naming a category that no credential belongs to must fail loudly
	// rather than fall back onto the unrestricted set.
	if _, errMiss := manager.SelectAuth(context.Background(), "loomy", model, cliproxyexecutor.Options{
		Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "zcode-bigmodel"},
	}); errMiss == nil {
		t.Fatal("SelectAuth(unmatched category scope) error = nil, want auth_not_found")
	}
}

// scopedAttemptRecorder is a provider executor that records which credentials it
// is handed and always fails with a credential-scoped upstream error, which is
// the state an exhausted account pool is in.
type scopedAttemptRecorder struct {
	provider string
	attempts *[]string
}

func (e scopedAttemptRecorder) Identifier() string { return e.provider }

func (e scopedAttemptRecorder) record(auth *Auth) error {
	if e.attempts != nil && auth != nil {
		*e.attempts = append(*e.attempts, auth.ID)
	}
	return &Error{Code: "quota_exceeded", Message: "quota exceeded", HTTPStatus: http.StatusTooManyRequests}
}

func (e scopedAttemptRecorder) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, e.record(auth)
}

func (e scopedAttemptRecorder) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, e.record(auth)
}

func (e scopedAttemptRecorder) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e scopedAttemptRecorder) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e scopedAttemptRecorder) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// TestScopedExecutionProvidersNarrowToScope pins the outer boundary: the provider
// list a request carries must never name an account category outside the key's
// scope, because every later selection path inherits that list.
func TestScopedExecutionProvidersNarrowToScope(t *testing.T) {
	resolved := []string{"zcode-zai", "workbuddy-cn", "loomy"}
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	for _, auth := range []*Auth{
		{ID: "narrow-zcode", FileName: "narrow-zcode.json", Provider: "zcode-zai"},
		{ID: "narrow-wb", FileName: "narrow-wb.json", Provider: "workbuddy-cn"},
		{ID: "narrow-loomy", FileName: "narrow-loomy.json", Provider: "loomy"},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
		}
	}
	scopeOpts := func(scope string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: scope}}
	}

	// An unrestricted caller keeps every provider.
	if got, errScope := manager.scopedExecutionProviders(resolved, "glm-5.3", cliproxyexecutor.Options{}); errScope != nil || strings.Join(got, ",") != strings.Join(resolved, ",") {
		t.Fatalf("unscoped providers = %v (err %v), want %v", got, errScope, resolved)
	}

	// A category scope keeps only the categories that have a credential in scope.
	if got, errScope := manager.scopedExecutionProviders(resolved, "glm-5.3", scopeOpts("zcode-zai")); errScope != nil {
		t.Fatalf("zcode-scoped providers error = %v", errScope)
	} else if strings.Join(got, ",") != "zcode-zai" {
		t.Fatalf("zcode-scoped providers = %v, want [zcode-zai]", got)
	}

	// A scope may also name a single credential; its category stays reachable.
	if got, errScope := manager.scopedExecutionProviders(resolved, "glm-5.3", scopeOpts("narrow-loomy")); errScope != nil {
		t.Fatalf("credential-scoped providers error = %v", errScope)
	} else if strings.Join(got, ",") != "loomy" {
		t.Fatalf("credential-scoped providers = %v, want [loomy]", got)
	}

	// A scope that reaches no provider is a failure, not an empty hand-off.
	_, errScope := manager.scopedExecutionProviders(resolved, "glm-5.3", scopeOpts("zcode-bigmodel"))
	if errScope == nil {
		t.Fatal("unmatched scope providers error = nil, want auth_not_found")
	}
	if errScope.Code != "auth_not_found" || !strings.Contains(errScope.Message, "zcode-bigmodel") {
		t.Fatalf("unmatched scope providers error = %+v, want auth_not_found naming the scope", errScope)
	}
}

// TestScopedExecutionNeverFallsBackWhenThePoolIsExhausted is the security
// property the pool scope exists for: once every credential inside the scope has
// failed, the request must fail instead of being served by another category.
// A model shared by several categories is the case where that is easy to get
// wrong, so both the first attempt and the all-cooling retry are checked, over
// the buffered and the streaming entry points.
func TestScopedExecutionNeverFallsBackWhenThePoolIsExhausted(t *testing.T) {
	const model = "glm-5.3-flash"
	reg := registry.GetGlobalRegistry()
	setCredentialPools(nil)
	t.Cleanup(func() { setCredentialPools(nil) })

	auths := []*Auth{
		{ID: "exhausted-zcode-1", FileName: "exhausted-zcode-1.json", Provider: "zcode-zai"},
		{ID: "exhausted-zcode-2", FileName: "exhausted-zcode-2.json", Provider: "zcode-zai"},
		{ID: "exhausted-wb", FileName: "exhausted-wb.json", Provider: "workbuddy-cn"},
		{ID: "exhausted-loomy", FileName: "exhausted-loomy.json", Provider: "loomy"},
	}
	for _, auth := range auths {
		reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		authID := auth.ID
		t.Cleanup(func() { reg.UnregisterClient(authID) })
	}

	var attempts []string
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	for _, provider := range []string{"zcode-zai", "workbuddy-cn", "loomy"} {
		manager.executors[provider] = scopedAttemptRecorder{provider: provider, attempts: &attempts}
	}
	for _, auth := range auths {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
		}
	}

	// The resolved provider list covers every category that advertises the model;
	// exactly as the handler resolves it before auth selection.
	providers := []string{"zcode-zai", "workbuddy-cn", "loomy"}
	scoped := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "zcode-zai"}}

	assertOnlyZcode := func(phase string, requireAttempt bool) {
		t.Helper()
		for _, id := range attempts {
			if id == "exhausted-wb" || id == "exhausted-loomy" {
				t.Fatalf("%s: out-of-scope credential %q was attempted (attempts=%v)", phase, id, attempts)
			}
		}
		if requireAttempt && len(attempts) == 0 {
			t.Fatalf("%s: no in-scope credential was attempted", phase)
		}
	}

	attempts = attempts[:0]
	if _, errExec := manager.Execute(context.Background(), providers, cliproxyexecutor.Request{Model: model}, scoped); errExec == nil {
		t.Fatalf("Execute with an exhausted scope returned no error (attempts=%v)", attempts)
	}
	assertOnlyZcode("first Execute", true)

	// Every in-scope credential is now cooling down. The scope must still hold:
	// this is the state reported as "all accounts are dead", and the moment a
	// fallback would be visible to the caller.
	attempts = attempts[:0]
	if _, errExec := manager.Execute(context.Background(), providers, cliproxyexecutor.Request{Model: model}, scoped); errExec == nil {
		t.Fatalf("Execute with every in-scope credential cooling returned no error (attempts=%v)", attempts)
	}
	assertOnlyZcode("cooling Execute", false)

	attempts = attempts[:0]
	streamOpts := cliproxyexecutor.Options{
		Stream:   true,
		Metadata: map[string]any{cliproxyexecutor.AllowedPoolsMetadataKey: "zcode-zai"},
	}
	if _, errStream := manager.ExecuteStream(context.Background(), providers, cliproxyexecutor.Request{Model: model}, streamOpts); errStream == nil {
		t.Fatalf("ExecuteStream with every in-scope credential cooling returned no error (attempts=%v)", attempts)
	}
	assertOnlyZcode("cooling ExecuteStream", false)
}

// TestPoolScopeCatalogMatchesCredentialSelection pins the claim the catalogue and
// credential selection both make: the model catalogue and credential selection
// apply the same scope rule. A pool-named entry is a form selection accepts, so
// the catalogue has to accept it too; otherwise a key scoped to a hand-written
// pool is advertised an empty catalogue while routing would have served it.
func TestPoolScopeCatalogMatchesCredentialSelection(t *testing.T) {
	const model = "poolscope-catalog-probe"
	reg := registry.GetGlobalRegistry()
	for _, id := range []string{"poolscope-in.json", "poolscope-out.json"} {
		clientID := id
		reg.RegisterClient(clientID, "zcode", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { reg.UnregisterClient(clientID) })
	}
	setCredentialPools(map[string][]string{"handwritten-pool": {"poolscope-in"}})
	t.Cleanup(func() { setCredentialPools(nil) })

	scope := []string{"handwritten-pool"}

	// Selection: the pool member is routable, the other credential is not.
	eligibility := authSelectionEligibility{allowedPools: scope}
	if !eligibility.allowsCredential(&Auth{ID: "poolscope-in", FileName: "poolscope-in.json", Provider: "zcode"}) {
		t.Fatal("selection rejected a credential named by its pool")
	}
	if eligibility.allowsCredential(&Auth{ID: "poolscope-out", FileName: "poolscope-out.json", Provider: "zcode"}) {
		t.Fatal("selection accepted a credential outside the pool")
	}

	advertised := func(entries []string) bool {
		t.Helper()
		for _, m := range reg.GetAvailableModelsForScope("openai", entries) {
			if got, _ := m["id"].(string); got == model {
				return true
			}
		}
		return false
	}

	// Control: the provider form already agreed before the pool form, so it proves
	// the probe itself is sound (a broken catalogue would fail here too).
	if !advertised([]string{"zcode"}) {
		t.Fatalf("catalogue for the provider form does not advertise %q; probe is unsound", model)
	}
	// The catalogue must agree with selection on the same entry form.
	if !advertised(scope) {
		t.Fatalf("catalogue for scope %v does not advertise %q, but selection accepts its credential", scope, model)
	}
}
