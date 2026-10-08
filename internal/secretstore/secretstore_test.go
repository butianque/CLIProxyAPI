package secretstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetGetRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, errOpen := Open(path)
	if errOpen != nil {
		t.Fatalf("open: %v", errOpen)
	}
	if store.Unlocked() {
		t.Fatal("store must start locked")
	}
	if errSet := store.Set("haozhuma", "value"); !errors.Is(errSet, ErrLocked) {
		t.Fatalf("set while locked: got %v, want ErrLocked", errSet)
	}
	if errUnlock := store.Unlock("correct horse"); errUnlock != nil {
		t.Fatalf("unlock: %v", errUnlock)
	}
	if !store.Unlocked() {
		t.Fatal("store must be unlocked")
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
	names, errNames := store.Names()
	if errNames != nil {
		t.Fatalf("names: %v", errNames)
	}
	if len(names) != 1 || names[0] != "haozhuma" {
		t.Fatalf("names = %v", names)
	}

	// Reopen with the same passphrase.
	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen: %v", errReopen)
	}
	if _, errGet := reopened.Get("haozhuma"); !errors.Is(errGet, ErrLocked) {
		t.Fatalf("get before unlock: got %v, want ErrLocked", errGet)
	}
	if errUnlock := reopened.Unlock("correct horse"); errUnlock != nil {
		t.Fatalf("reopen unlock: %v", errUnlock)
	}
	got, errGet = reopened.Get("haozhuma")
	if errGet != nil || got != "user=abc&key=def" {
		t.Fatalf("reopened get = %q, err = %v", got, errGet)
	}
}

func TestMultipleSecretsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	if errUnlock := store.Unlock("pw"); errUnlock != nil {
		t.Fatalf("unlock: %v", errUnlock)
	}
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
		t.Fatalf("reopen unlock: %v", errUnlock)
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

func TestUnlockRejectsWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	if errUnlock := store.Unlock("right"); errUnlock != nil {
		t.Fatalf("unlock: %v", errUnlock)
	}
	if errSet := store.Set("k", "v"); errSet != nil {
		t.Fatalf("set: %v", errSet)
	}
	reopened, _ := Open(path)
	if errUnlock := reopened.Unlock("wrong"); !errors.Is(errUnlock, ErrInvalidPassphrase) {
		t.Fatalf("unlock with wrong passphrase: got %v, want ErrInvalidPassphrase", errUnlock)
	}
	if reopened.Unlocked() {
		t.Fatal("store must stay locked after a failed unlock")
	}
}

func TestDeleteAndNotFound(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errUnlock := store.Unlock("pw"); errUnlock != nil {
		t.Fatalf("unlock: %v", errUnlock)
	}
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

func TestLockClearsKeyAndItems(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	_ = store.Unlock("pw")
	_ = store.Set("a", "1")
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

func TestFileDisclosesNeitherNamesNorValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, _ := Open(path)
	const passphrase = "PassphraseThatMustNotAppearInTheFile"
	_ = store.Unlock(passphrase)
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
	if strings.Contains(string(raw), passphrase) {
		t.Fatal("passphrase leaked into the store file")
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
	if errWrite := os.WriteFile(path, []byte(`{"v":99,"kdf":{"name":"argon2id","salt":"AAAAAAAAAAAAAAAAAAAAAA==","time":3,"memory":65536,"parallelism":4,"keylen":32},"aead":"aes-256-gcm","items":{}}`), 0o600); errWrite != nil {
		t.Fatalf("write: %v", errWrite)
	}
	if _, errOpen := Open(path); errOpen == nil {
		t.Fatal("expected unsupported version to be rejected")
	}
}

func TestEmptyInputs(t *testing.T) {
	store, _ := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errUnlock := store.Unlock(""); !errors.Is(errUnlock, ErrEmptyPassphrase) {
		t.Fatalf("empty passphrase: got %v", errUnlock)
	}
	_ = store.Unlock("pw")
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
