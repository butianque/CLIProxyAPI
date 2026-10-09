package secretstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// initStore creates a fresh passphrase-protected store and returns it unlocked.
func initStore(t *testing.T, path, passphrase string) *Store {
	t.Helper()
	store, errOpen := Open(path)
	if errOpen != nil {
		t.Fatalf("open: %v", errOpen)
	}
	if errInit := store.Initialize(passphrase); errInit != nil {
		t.Fatalf("initialize: %v", errInit)
	}
	return store
}

func TestOpenFreshStoreIsLockedAndUninitialized(t *testing.T) {
	store, errOpen := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open: %v", errOpen)
	}
	if store.Initialized() {
		t.Fatal("a brand-new store must not be initialized")
	}
	if store.Unlocked() {
		t.Fatal("a brand-new store must stay locked until an unlock policy exists")
	}
	if errSet := store.Set("a", "1"); !errors.Is(errSet, ErrLocked) {
		t.Fatalf("set on a locked store: got %v, want ErrLocked", errSet)
	}
}

func TestInitializeThenRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store := initStore(t, path, "master-pass")
	if !store.Unlocked() || !store.Initialized() {
		t.Fatal("initialized store must be unlocked and initialized")
	}
	if !store.HasPassphrase() {
		t.Fatal("Initialize must install a passphrase")
	}
	if errSet := store.Set("haozhuma", "user=abc&key=def"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	if got, _ := store.Get("haozhuma"); got != "user=abc&key=def" {
		t.Fatalf("get = %q", got)
	}

	// A reopen must be locked: the passphrase is required, and no key file is
	// written in pure passphrase mode.
	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen: %v", errReopen)
	}
	if reopened.Unlocked() {
		t.Fatal("a passphrase store must open locked")
	}
	if _, errGet := reopened.Get("haozhuma"); !errors.Is(errGet, ErrLocked) {
		t.Fatalf("get before unlock: got %v, want ErrLocked", errGet)
	}
	if errUnlock := reopened.Unlock("master-pass"); errUnlock != nil {
		t.Fatalf("unlock: %v", errUnlock)
	}
	if got, _ := reopened.Get("haozhuma"); got != "user=abc&key=def" {
		t.Fatalf("get after unlock = %q", got)
	}
	if _, errKey := os.Stat(path + ".key"); !errors.Is(errKey, os.ErrNotExist) {
		t.Fatal("a passphrase-only store must not write a machine key file")
	}
}

func TestUnlockRejectsWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	initStore(t, path, "correct")
	reopened, _ := Open(path)
	if errUnlock := reopened.Unlock("wrong"); !errors.Is(errUnlock, ErrInvalidPassphrase) {
		t.Fatalf("unlock with wrong passphrase: got %v, want ErrInvalidPassphrase", errUnlock)
	}
	if errUnlock := reopened.Unlock(""); !errors.Is(errUnlock, ErrEmptyPassphrase) {
		t.Fatalf("unlock with empty passphrase: got %v, want ErrEmptyPassphrase", errUnlock)
	}
}

func TestMultipleSecretsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store := initStore(t, path, "pw")
	for _, name := range []string{"zeta", "alpha", "haozhuma"} {
		if errSet := store.Set(name, "value-"+name); errSet != nil {
			t.Fatalf("set %s: %v", name, errSet)
		}
	}
	if errDelete := store.Delete("alpha"); errDelete != nil {
		t.Fatalf("delete: %v", errDelete)
	}

	reopened, _ := Open(path)
	if errUnlock := reopened.Unlock("pw"); errUnlock != nil {
		t.Fatalf("unlock: %v", errUnlock)
	}
	names, errNames := reopened.Names()
	if errNames != nil {
		t.Fatalf("names: %v", errNames)
	}
	if len(names) != 2 || names[0] != "haozhuma" || names[1] != "zeta" {
		t.Fatalf("names = %v, want [haozhuma zeta]", names)
	}
	if got, _ := reopened.Get("zeta"); got != "value-zeta" {
		t.Fatalf("zeta = %q", got)
	}
	if _, errGet := reopened.Get("alpha"); !errors.Is(errGet, ErrNotFound) {
		t.Fatalf("deleted secret: got %v, want ErrNotFound", errGet)
	}
}

func TestDeleteAndNotFound(t *testing.T) {
	store := initStore(t, filepath.Join(t.TempDir(), "secrets.enc"), "pw")
	if _, errGet := store.Get("missing"); !errors.Is(errGet, ErrNotFound) {
		t.Fatalf("get missing: got %v, want ErrNotFound", errGet)
	}
	if errSet := store.Set("a", "1"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	if errDelete := store.Delete("a"); errDelete != nil {
		t.Fatalf("delete: %v", errDelete)
	}
	if _, errGet := store.Get("a"); !errors.Is(errGet, ErrNotFound) {
		t.Fatalf("get after delete: got %v, want ErrNotFound", errGet)
	}
	if errDelete := store.Delete("a"); errDelete != nil {
		t.Fatalf("delete missing: %v", errDelete)
	}
}

func TestLockRequiresPassphraseToRecover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store := initStore(t, path, "pw")
	if errSet := store.Set("a", "1"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	store.Lock()
	if store.Unlocked() {
		t.Fatal("store must be locked")
	}
	if _, errGet := store.Get("a"); !errors.Is(errGet, ErrLocked) {
		t.Fatalf("get after lock: got %v, want ErrLocked", errGet)
	}
	if _, errNames := store.Names(); !errors.Is(errNames, ErrLocked) {
		t.Fatalf("names after lock: got %v, want ErrLocked", errNames)
	}
	store.mu.RLock()
	items := store.items
	store.mu.RUnlock()
	if items != nil {
		t.Fatal("plaintext items must not survive Lock")
	}
	if errUnlock := store.Unlock("pw"); errUnlock != nil {
		t.Fatalf("re-unlock: %v", errUnlock)
	}
	if got, _ := store.Get("a"); got != "1" {
		t.Fatalf("get after re-unlock = %q", got)
	}
}

func TestStoreFileDisclosesNeitherNamesNorValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store := initStore(t, path, "pw")
	const secret = "super-secret-token-value"
	if errSet := store.Set("haozhuma", secret); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read: %v", errRead)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("secret value leaked into the store file")
	}
	if strings.Contains(string(raw), "haozhuma") {
		t.Fatal("secret name leaked into the store file")
	}
	var decoded map[string]any
	if errUnmarshal := json.Unmarshal(raw, &decoded); errUnmarshal != nil {
		t.Fatalf("store file is not JSON: %v", errUnmarshal)
	}
	if decoded["v"] != float64(FormatVersion) {
		t.Fatalf("version = %v", decoded["v"])
	}
	if decoded["unlock"] != string(UnlockPassphrase) {
		t.Fatalf("unlock mode = %v, want %q", decoded["unlock"], UnlockPassphrase)
	}
	if _, ok := decoded["items"]; !ok {
		t.Fatal("store file has no items payload")
	}
}

func TestMachineUnlockRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable machine unlock: %v", errEnable)
	}
	if store.Mode() != UnlockMachine {
		t.Fatalf("mode = %q, want %q", store.Mode(), UnlockMachine)
	}
	if store.HasPassphrase() {
		t.Fatal("a pure machine store must not report a passphrase")
	}
	if errSet := store.Set("haozhuma", "secret"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}

	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen: %v", errReopen)
	}
	if !reopened.Unlocked() {
		t.Fatal("a machine store must auto-unlock from its key file")
	}
	got, errGet := reopened.Get("haozhuma")
	if errGet != nil || got != "secret" {
		t.Fatalf("reopened get = %q, err = %v", got, errGet)
	}
	keyRaw, errKey := os.ReadFile(path + ".key")
	if errKey != nil {
		t.Fatalf("read key file: %v", errKey)
	}
	if len(keyRaw) != storageKeyLen {
		t.Fatalf("key length = %d, want %d", len(keyRaw), storageKeyLen)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), string(keyRaw)) {
		t.Fatal("storage key leaked into the store file")
	}
}

func TestMachineUnlockFailsWhenKeyFileIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable: %v", errEnable)
	}
	if errSet := store.Set("a", "1"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	if errRemove := os.Remove(path + ".key"); errRemove != nil {
		t.Fatalf("remove key: %v", errRemove)
	}
	if _, errOpen := Open(path); errOpen == nil {
		t.Fatal("expected open to fail when a pure machine store lost its key")
	}
}

func TestMachineUnlockRejectsMismatchedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable: %v", errEnable)
	}
	if errSet := store.Set("a", "1"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	if errWrite := os.WriteFile(path+".key", randomBytes(storageKeyLen), 0o600); errWrite != nil {
		t.Fatalf("overwrite key: %v", errWrite)
	}
	if _, errOpen := Open(path); errOpen == nil {
		t.Fatal("expected a mismatched machine key to be rejected")
	}
}

func TestPassphrasePlusMachineRememberOptIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store := initStore(t, path, "pw")
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable: %v", errEnable)
	}
	if store.Mode() != UnlockPassphraseMachine {
		t.Fatalf("mode = %q, want %q", store.Mode(), UnlockPassphraseMachine)
	}
	if !store.HasPassphrase() {
		t.Fatal("passphrase must be retained when remembering on the machine")
	}
	if errSet := store.Set("haozhuma", "secret"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}

	// A restart needs no passphrase because the key is cached.
	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen: %v", errReopen)
	}
	if !reopened.Unlocked() {
		t.Fatal("a passphrase+machine store must auto-unlock on the same host")
	}
	if got, _ := reopened.Get("haozhuma"); got != "secret" {
		t.Fatalf("get after reopen = %q", got)
	}

	// Disabling the opt-in must drop the key file and require the passphrase.
	if errDisable := reopened.DisableMachineUnlock(); errDisable != nil {
		t.Fatalf("disable: %v", errDisable)
	}
	if _, errKey := os.Stat(path + ".key"); !errors.Is(errKey, os.ErrNotExist) {
		t.Fatal("disabling machine unlock must remove the key file")
	}
	locked, _ := Open(path)
	if locked.Unlocked() {
		t.Fatal("after disabling, a reopen must be locked")
	}
	if errUnlock := locked.Unlock("pw"); errUnlock != nil {
		t.Fatalf("unlock with passphrase after disable: %v", errUnlock)
	}
	if got, _ := locked.Get("haozhuma"); got != "secret" {
		t.Fatalf("get after passphrase unlock = %q", got)
	}
}

func TestDisableMachineUnlockRefusesWithoutPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable: %v", errEnable)
	}
	if errDisable := store.DisableMachineUnlock(); !errors.Is(errDisable, ErrModeConflict) {
		t.Fatalf("disable without a passphrase: got %v, want ErrModeConflict", errDisable)
	}
}

func TestInitializeTwiceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store := initStore(t, path, "pw")
	if errInit := store.Initialize("other"); !errors.Is(errInit, ErrModeConflict) {
		t.Fatalf("re-initialize: got %v, want ErrModeConflict", errInit)
	}
}

func TestSetPassphraseRequiresCurrentToReplace(t *testing.T) {
	store := initStore(t, filepath.Join(t.TempDir(), "secrets.enc"), "first")
	if errSet := store.SetPassphrase("", "second"); !errors.Is(errSet, ErrEmptyPassphrase) {
		t.Fatalf("replace without current: got %v, want ErrEmptyPassphrase", errSet)
	}
	if errSet := store.SetPassphrase("nope", "second"); !errors.Is(errSet, ErrInvalidPassphrase) {
		t.Fatalf("replace with wrong current: got %v, want ErrInvalidPassphrase", errSet)
	}
	if errSet := store.SetPassphrase("first", "second"); errSet != nil {
		t.Fatalf("replace with current: %v", errSet)
	}
	if errVerify := store.VerifyPassphrase("second"); errVerify != nil {
		t.Fatalf("verify new passphrase: %v", errVerify)
	}
	if errVerify := store.VerifyPassphrase("first"); !errors.Is(errVerify, ErrInvalidPassphrase) {
		t.Fatalf("old passphrase must stop matching: got %v", errVerify)
	}
}

func TestPassphraseAndSecretsSurviveReopenWithoutLeaking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	const passphrase = "PassphraseThatMustNotAppearInTheFile"
	store := initStore(t, path, passphrase)
	if errSet := store.Set("haozhuma", "secret"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}

	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen: %v", errReopen)
	}
	if !reopened.HasPassphrase() {
		t.Fatal("passphrase must survive a reopen")
	}
	if errVerify := reopened.VerifyPassphrase(passphrase); errVerify != nil {
		t.Fatalf("verify after reopen: %v", errVerify)
	}
	if errUnlock := reopened.Unlock(passphrase); errUnlock != nil {
		t.Fatalf("unlock after reopen: %v", errUnlock)
	}
	if got, _ := reopened.Get("haozhuma"); got != "secret" {
		t.Fatalf("secrets must survive alongside the passphrase, got %q", got)
	}

	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read: %v", errRead)
	}
	if strings.Contains(string(raw), passphrase) {
		t.Fatal("passphrase leaked into the store file")
	}
}

func TestEmptyInputs(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errInit := store.Initialize(""); !errors.Is(errInit, ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase on initialize: got %v", errInit)
	}
	if errSet := store.Set("", "v"); !errors.Is(errSet, ErrEmptyName) {
		t.Fatalf("empty name: got %v", errSet)
	}
}

func TestSlotsAreBoundByAAD(t *testing.T) {
	key := randomBytes(storageKeyLen)
	canary, errSeal := sealRaw(key, aadFor(canarySlot), []byte(canaryPlaintext))
	if errSeal != nil {
		t.Fatalf("seal: %v", errSeal)
	}
	if _, errOpen := openRaw(key, aadFor(itemsSlot), canary); errOpen == nil {
		t.Fatal("canary ciphertext opened under the items AAD")
	}
	if _, errOpen := openRaw(key, aadFor(canarySlot), canary); errOpen != nil {
		t.Fatalf("canary ciphertext did not open under its own AAD: %v", errOpen)
	}
}

func TestOpenRejectsUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	if errWrite := os.WriteFile(path, []byte(`{"v":99,"aead":"aes-256-gcm","items":{}}`), 0o600); errWrite != nil {
		t.Fatalf("write: %v", errWrite)
	}
	if _, errOpen := Open(path); errOpen == nil {
		t.Fatal("expected unsupported version to be rejected")
	}
}

func TestOpenRejectsPassphraseModeWithoutWrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	raw := `{"v":3,"aead":"aes-256-gcm","unlock":"passphrase"}`
	if errWrite := os.WriteFile(path, []byte(raw), 0o600); errWrite != nil {
		t.Fatalf("write: %v", errWrite)
	}
	if _, errOpen := Open(path); errOpen == nil {
		t.Fatal("expected passphrase mode without a wrapped key to be rejected")
	}
}

func TestDefaultStoreLifecycle(t *testing.T) {
	Configure(nil)
	if Default() != nil {
		t.Fatal("expected nil default store")
	}
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	Configure(store)
	if Default() != store {
		t.Fatal("default store not installed")
	}
	Configure(nil)
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("CPA_SECRET_STORE_PATH", "")
	got := DefaultPath(filepath.Join("some", "dir", "config.yaml"))
	if want := filepath.Join("some", "dir", "cpa-secrets.enc"); got != want {
		t.Fatalf("DefaultPath = %q, want %q", got, want)
	}

	t.Setenv("CPA_SECRET_STORE_PATH", filepath.Join("custom", "secrets.enc"))
	if got := DefaultPath("config.yaml"); got != filepath.Join("custom", "secrets.enc") {
		t.Fatalf("DefaultPath with env = %q", got)
	}

	t.Setenv("CPA_SECRET_STORE_PATH", "")
	if got := DefaultPath("config.yaml"); !filepath.IsAbs(got) {
		t.Fatalf("DefaultPath without a directory must be absolute, got %q", got)
	}
}
