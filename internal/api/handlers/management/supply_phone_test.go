package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/phone"
)

// N1: the supply config section resolves the phone kind's built-in defaults.
func TestSupplyConfigDefaults(t *testing.T) {
	cfg := config.SupplyConfig{}.WithDefaults()
	if cfg.Phone.Provider != config.DefaultSupplyPhoneProvider {
		t.Fatalf("provider = %q, want %q", cfg.Phone.Provider, config.DefaultSupplyPhoneProvider)
	}
	if cfg.Phone.Project != config.DefaultSupplyPhoneProject {
		t.Fatalf("project = %q, want %q", cfg.Phone.Project, config.DefaultSupplyPhoneProject)
	}
	if cfg.Phone.APISecret != "haozhuma" || cfg.Phone.CookieSecret != "haozhuma-ck" {
		t.Fatalf("secret names = %q/%q, want haozhuma/haozhuma-ck", cfg.Phone.APISecret, cfg.Phone.CookieSecret)
	}
	if cfg.Phone.MaxPerNumberCNY != config.DefaultSupplyPhoneMaxPerNumber || cfg.Phone.MaxTotalCNY != config.DefaultSupplyPhoneMaxTotal {
		t.Fatalf("budget = %v/%v, want %v/%v", cfg.Phone.MaxPerNumberCNY, cfg.Phone.MaxTotalCNY, config.DefaultSupplyPhoneMaxPerNumber, config.DefaultSupplyPhoneMaxTotal)
	}
	if cfg.Phone.CooldownSeconds != config.DefaultSupplyPhoneCooldownSecs {
		t.Fatalf("cooldown = %d, want %d", cfg.Phone.CooldownSeconds, config.DefaultSupplyPhoneCooldownSecs)
	}
	// An explicit value is never overwritten by a default.
	explicit := config.SupplyConfig{Phone: config.SupplyPhoneConfig{Project: "99999", MaxTotalCNY: 3}}
	got := explicit.WithDefaults()
	if got.Phone.Project != "99999" || got.Phone.MaxTotalCNY != 3 {
		t.Fatalf("explicit values overwritten: project=%q maxTotal=%v", got.Phone.Project, got.Phone.MaxTotalCNY)
	}

	// The guardrail is an opt-out: unset means on, only an explicit false
	// turns it off. This mirrors how the phone kind behaved before it moved
	// into the host.
	if !cfg.Phone.GuardrailEnabled() {
		t.Fatal("guardrail should default to on")
	}
	off := false
	if (config.SupplyPhoneConfig{Guardrail: &off}).GuardrailEnabled() {
		t.Fatal("an explicit guardrail:false must turn the guardrail off")
	}
	on := true
	if !(config.SupplyPhoneConfig{Guardrail: &on}).GuardrailEnabled() {
		t.Fatal("an explicit guardrail:true must keep the guardrail on")
	}
}

// lockedStore installs an initialized-but-locked store for the duration of a test.
func lockedStore(t *testing.T) {
	t.Helper()
	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	if errInitialize := store.Initialize("master"); errInitialize != nil {
		t.Fatalf("initialize store: %v", errInitialize)
	}
	// Initialize adopts the storage key, leaving the store unlocked; lock it so
	// the test exercises the locked path.
	store.Lock()
	if store.Unlocked() {
		t.Fatal("store should be locked")
	}
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })
}

// N3: with no phone provider registered, status reports the honest
// not-configured state rather than an error, and names no credentials.
func TestSupplyPhoneStatusUnconfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := supply.Default()
	supply.SetDefault(nil)
	t.Cleanup(func() { supply.SetDefault(previous) })
	lockedStore(t)

	h := &Handler{}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v8/management/supply/phone/status", nil)
	h.GetSupplyPhoneStatus(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", recorder.Code)
	}
	var payload map[string]any
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode: %v", errDecode)
	}
	if payload["enabled"] != false {
		t.Fatalf("enabled = %v, want false", payload["enabled"])
	}
	// A locked store must not leak the set of stored names.
	if names, ok := payload["credentials"].([]any); ok && len(names) > 0 {
		t.Fatalf("locked store leaked credentials: %v", names)
	}
}

// N3b: enabled reports the kind actually serving, not the raw config flag.
//
// Reporting a config flag made the panel show "disabled" while the kind was
// demonstrably working (the store was unlocked and the credential present),
// because a working install may never have written a supply section. A
// registered provider is the truth.
func TestSupplyPhoneStatusEnabledFollowsRegisteredProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })
	lockedStore(t)

	// A real phone provider, built the way the command layer builds it, because
	// the management surface reaches the concrete implementation.
	provider, errProvider := phone.New(phone.Config{
		Provider: "haozhuma",
		Secret:   phone.HaozhumaSecret{Token: "test-token"},
		Store:    phone.Store{Dir: t.TempDir()},
		Budget:   phone.Budget{MaxPerNumberCNY: 0.5, MaxTotalCNY: 20},
		Project:  phone.Project{SID: "21614"},
	})
	if errProvider != nil {
		t.Fatalf("build phone provider: %v", errProvider)
	}
	registry := supply.NewRegistry()
	if errRegister := registry.Register(provider); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	supply.SetDefault(registry)

	h := &Handler{cfg: &config.Config{}} // No supply section written at all.
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v8/management/supply/phone/status", nil)
	h.GetSupplyPhoneStatus(ctx)

	var payload map[string]any
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode: %v", errDecode)
	}
	if payload["enabled"] != true {
		t.Fatalf("enabled = %v, want true when a phone provider is registered", payload["enabled"])
	}
}

// N5: unlocking the store rebuilds the supply service.
//
// The service is built at startup from credentials the store can read, and the
// store is locked at startup on a passphrase-protected install. Without a
// rebuild on unlock, the phone kind stayed absent for the whole session even
// though its credential was right there — the panel showed the feature as off
// while the operator had just unlocked it. The unlock handler must rebuild.
func TestSecretUnlockRebuildsSupply(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })

	// A passphrase store, initialized then locked, holding the phone credential.
	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	if errInitialize := store.Initialize("master"); errInitialize != nil {
		t.Fatalf("initialize store: %v", errInitialize)
	}
	if errPut := store.Set("haozhuma", `{"token":"test-token"}`); errPut != nil {
		t.Fatalf("seed credential: %v", errPut)
	}
	store.Lock()
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })

	// The startup state: no provider registered because the store was locked.
	supply.SetDefault(supply.NewRegistry())
	rebuilds := 0
	SetSupplyReloader(func() {
		rebuilds++
		// Mimic the command layer: build a provider now that the store is open.
		provider, errProvider := phone.New(phone.Config{
			Provider: "haozhuma",
			Secret:   phone.HaozhumaSecret{Token: "test-token"},
			Store:    phone.Store{Dir: t.TempDir()},
			Budget:   phone.Budget{MaxPerNumberCNY: 0.5, MaxTotalCNY: 20},
			Project:  phone.Project{SID: "21614"},
		})
		if errProvider != nil {
			t.Errorf("build provider: %v", errProvider)
			return
		}
		registry := supply.NewRegistry()
		if errRegister := registry.Register(provider); errRegister != nil {
			t.Errorf("register: %v", errRegister)
			return
		}
		supply.SetDefault(registry)
	})
	t.Cleanup(func() { SetSupplyReloader(nil) })

	h := &Handler{}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v8/management/secrets/unlock",
		strings.NewReader(`{"passphrase":"master"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.PostSecretUnlock(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unlock status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if rebuilds == 0 {
		t.Fatal("unlock did not rebuild the supply service")
	}
	if _, errProvider := supply.ProviderFor(supply.KindPhone); errProvider != nil {
		t.Fatalf("phone provider not available after unlock: %v", errProvider)
	}
}

// N2: the phone management routes are mounted under /v8/management/supply/phone.
func TestSupplyPhoneRoutesMounted(t *testing.T) {
	// Covered structurally by server_management_v8_test.go's route contract;
	// this asserts the handler set exists so a rename cannot silently drop one.
	h := &Handler{}
	_ = []func(*gin.Context){
		h.GetSupplyPhoneStatus,
		h.PostSupplyPhoneRefresh,
		h.PostSupplyPhoneGuardrail,
		h.PostSupplyPhoneChannel,
		h.PostSupplyPhoneAPI,
		h.PostSupplyPhoneCookie,
		h.PostSupplyPhoneWebLogin,
		h.PostSupplyPhoneWebCredential,
		h.PostSupplyPhoneBlacklist,
	}
}

// N4: a credential write is refused while the store is locked, and the refusal
// never echoes a credential value.
func TestSupplyPhoneAPIWriteRequiresGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lockedStore(t)

	h := &Handler{cfg: &config.Config{}}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v8/management/supply/phone/api",
		strings.NewReader(`{"api_user":"someone","api_pass":"secret-value"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.PostSupplyPhoneAPI(ctx)

	if recorder.Code == http.StatusOK {
		t.Fatalf("locked store accepted a credential write")
	}
	if strings.Contains(recorder.Body.String(), "secret-value") {
		t.Fatalf("response echoed the credential value: %s", recorder.Body.String())
	}
}

// N6: the shared registry still routes phone calls and reports the kind.
func TestRegistryProviderLookup(t *testing.T) {
	registry := supply.NewRegistry()
	if errRegister := registry.Register(stubKindProvider{kind: supply.KindPhone}); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	provider, errProvider := registry.Provider(supply.KindPhone)
	if errProvider != nil {
		t.Fatalf("provider lookup: %v", errProvider)
	}
	if provider.Kind() != supply.KindPhone {
		t.Fatalf("kind = %q, want phone", provider.Kind())
	}
	if _, errMissing := registry.Provider(supply.KindEmail); errMissing == nil {
		t.Fatal("unregistered kind should be unavailable")
	}
}
