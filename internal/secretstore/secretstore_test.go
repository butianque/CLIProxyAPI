package secretstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenStartsUsable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, errOpen := Open(path)
	if errOpen != nil {
		t.Fatalf("open: %v", errOpen)
	}
	if !store.Unlocked() {
		t.Fatal("a store with no key file must open usable")
	}
	if _, errGet := store.Get("missing"); !errors.Is(errGet, ErrNotFound) {
		t.Fatalf("get missing: got %v, want ErrNotFound", errGet)
	}
	if errSet := store.Set("haozhuma", "user=abc&key=def"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	got, errGet := store.Get("haozhuma")
	if errGet != nil {
		t.Fatalf("get: %v", errGet)
	}
	if got != "user=abc&key=def" {
		t.Fatalf("get = %q", got)
	}
}

func TestReopenDecryptsWithoutOperatorInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	if errSet := store.Set("haozhuma", "secret"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}

	// A fresh Open must decrypt by itself: no passphrase is needed.
	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen: %v", errReopen)
	}
	if !reopened.Unlocked() {
		t.Fatal("reopened store must be usable")
	}
	got, errGet := reopened.Get("haozhuma")
	if errGet != nil || got != "secret" {
		t.Fatalf("reopened get = %q, err = %v", got, errGet)
	}
}

func TestMultipleSecretsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	for _, name := range []string{"zeta", "alpha", "haozhuma"} {
		if errSet := store.Set(name, "value-"+name); errSet != nil {
			t.Fatalf("set %s: %v", name, errSet)
		}
	}
	if errDelete := store.Delete("alpha"); errDelete != nil {
		t.Fatalf("delete: %v", errDelete)
	}

	reopened, _ := Open(path)
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
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
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

func TestLockRequiresKeyFileToRecover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
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
	if errUnlock := store.Unlock(); errUnlock != nil {
		t.Fatalf("re-unlock: %v", errUnlock)
	}
	if got, _ := store.Get("a"); got != "1" {
		t.Fatalf("get after re-unlock = %q", got)
	}
}

func TestStoreFileDisclosesNeitherNamesNorValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.enc")
	store, _ := Open(path)
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
	if _, ok := decoded["items"]; !ok {
		t.Fatal("store file has no items payload")
	}

	// The machine key must live in a separate file with restrictive permissions,
	// never inside the store file.
	keyRaw, errKey := os.ReadFile(path + ".key")
	if errKey != nil {
		t.Fatalf("read key file: %v", errKey)
	}
	if len(keyRaw) != machineKeyLen {
		t.Fatalf("key length = %d, want %d", len(keyRaw), machineKeyLen)
	}
	if strings.Contains(string(raw), string(keyRaw)) {
		t.Fatal("machine key leaked into the store file")
	}
}

func TestOpenFailsWhenKeyFileIsMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.enc")
	store, _ := Open(path)
	if errSet := store.Set("a", "1"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	if errRemove := os.Remove(path + ".key"); errRemove != nil {
		t.Fatalf("remove key: %v", errRemove)
	}
	if _, errOpen := Open(path); errOpen == nil {
		t.Fatal("expected open to fail when the machine key is gone")
	}
}

func TestOpenRejectsMismatchedKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.enc")
	store, _ := Open(path)
	if errSet := store.Set("a", "1"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	if errWrite := os.WriteFile(path+".key", randomBytes(machineKeyLen), 0o600); errWrite != nil {
		t.Fatalf("overwrite key: %v", errWrite)
	}
	if _, errOpen := Open(path); errOpen == nil {
		t.Fatal("expected a mismatched machine key to be rejected")
	}
}

func TestPassphraseLifecycle(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if store.HasPassphrase() {
		t.Fatal("a fresh store has no passphrase")
	}
	if errVerify := store.VerifyPassphrase("anything"); !errors.Is(errVerify, ErrNoPassphrase) {
		t.Fatalf("verify before install: got %v, want ErrNoPassphrase", errVerify)
	}
	if errSet := store.SetPassphrase("", "master"); errSet != nil {
		t.Fatalf("install: %v", errSet)
	}
	if !store.HasPassphrase() {
		t.Fatal("passphrase must be recorded")
	}
	if errVerify := store.VerifyPassphrase("master"); errVerify != nil {
		t.Fatalf("verify correct: %v", errVerify)
	}
	if errVerify := store.VerifyPassphrase("wrong"); !errors.Is(errVerify, ErrInvalidPassphrase) {
		t.Fatalf("verify wrong: got %v, want ErrInvalidPassphrase", errVerify)
	}
	if errVerify := store.VerifyPassphrase(""); !errors.Is(errVerify, ErrEmptyPassphrase) {
		t.Fatalf("verify empty: got %v, want ErrEmptyPassphrase", errVerify)
	}
}

func TestSetPassphraseRequiresCurrentToReplace(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errSet := store.SetPassphrase("", "first"); errSet != nil {
		t.Fatalf("install: %v", errSet)
	}
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

func TestPassphraseSurvivesReopenAndDoesNotLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	const passphrase = "PassphraseThatMustNotAppearInTheFile"
	if errSet := store.SetPassphrase("", passphrase); errSet != nil {
		t.Fatalf("install: %v", errSet)
	}
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

func TestSlotsAreBoundByAAD(t *testing.T) {
	key := randomBytes(32)
	canary, errSeal := seal(key, aadFor(canarySlot), []byte(canaryPlaintext))
	if errSeal != nil {
		t.Fatalf("seal: %v", errSeal)
	}
	if _, errOpen := open(key, aadFor(itemsSlot), canary); errOpen == nil {
		t.Fatal("canary ciphertext opened under the items AAD")
	}
	if _, errOpen := open(key, aadFor(canarySlot), canary); errOpen != nil {
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

func TestEmptyInputs(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errSet := store.SetPassphrase("", ""); !errors.Is(errSet, ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase: got %v", errSet)
	}
	if errSet := store.Set("", "v"); !errors.Is(errSet, ErrEmptyName) {
		t.Fatalf("empty name: got %v", errSet)
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
