package secretstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// grantStore creates an unlocked passphrase store holding one secret.
func grantStore(t *testing.T) *Store {
	t.Helper()
	store := initStore(t, filepath.Join(t.TempDir(), "secrets.enc"), "master-pass")
	if errSet := store.Set("phone", "api-secret"); errSet != nil {
		t.Fatalf("seed secret: %v", errSet)
	}
	return store
}

func TestSessionGrantIsRequiredToReadSecrets(t *testing.T) {
	store := grantStore(t)

	// The store is open, but no session has proved the passphrase yet.
	if _, errGet := store.SessionVault("session-a").Get("phone"); !errors.Is(errGet, ErrUnauthorized) {
		t.Fatalf("unbound session read: got %v, want ErrUnauthorized", errGet)
	}

	if _, errGrant := store.GrantSession("session-a", time.Minute); errGrant != nil {
		t.Fatalf("grant: %v", errGrant)
	}
	if got, errGet := store.SessionVault("session-a").Get("phone"); errGet != nil || got != "api-secret" {
		t.Fatalf("granted read = %q, %v", got, errGet)
	}

	// A second session is a different subject: it must not inherit session-a.
	if _, errGet := store.SessionVault("session-b").Get("phone"); !errors.Is(errGet, ErrUnauthorized) {
		t.Fatalf("second session read: got %v, want ErrUnauthorized", errGet)
	}
	if store.SessionUnlocked("session-b") {
		t.Fatal("session-b must not be unlocked")
	}
}

func TestSessionGrantCoversWritesAndListing(t *testing.T) {
	store := grantStore(t)
	if _, errGrant := store.GrantSession("session-a", time.Minute); errGrant != nil {
		t.Fatalf("grant: %v", errGrant)
	}
	vault := store.SessionVault("session-a")

	if errSet := vault.Set("mailbox", "user=u&pass=p"); errSet != nil {
		t.Fatalf("granted set: %v", errSet)
	}
	names, errNames := vault.Names()
	if errNames != nil {
		t.Fatalf("granted names: %v", errNames)
	}
	if len(names) != 2 {
		t.Fatalf("names = %v, want two entries", names)
	}
	if errDelete := vault.Delete("mailbox"); errDelete != nil {
		t.Fatalf("granted delete: %v", errDelete)
	}

	// The same operations from an unbound session stay refused.
	other := store.SessionVault("session-b")
	if errSet := other.Set("x", "y"); !errors.Is(errSet, ErrUnauthorized) {
		t.Fatalf("unbound set: got %v, want ErrUnauthorized", errSet)
	}
	if _, errNames := other.Names(); !errors.Is(errNames, ErrUnauthorized) {
		t.Fatalf("unbound names: got %v, want ErrUnauthorized", errNames)
	}
	if errDelete := other.Delete("phone"); !errors.Is(errDelete, ErrUnauthorized) {
		t.Fatalf("unbound delete: got %v, want ErrUnauthorized", errDelete)
	}
}

func TestExpiredGrantIsRefusedAndTouchRenews(t *testing.T) {
	store := grantStore(t)
	if _, errGrant := store.GrantSession("session-a", time.Minute); errGrant != nil {
		t.Fatalf("grant: %v", errGrant)
	}

	// Force the idle deadline into the past instead of sleeping, so the test is
	// independent of timer granularity.
	store.mu.Lock()
	store.sessions["session-a"].expires = time.Now().Add(-time.Second)
	store.mu.Unlock()

	if _, errGet := store.SessionVault("session-a").Get("phone"); !errors.Is(errGet, ErrUnauthorized) {
		t.Fatalf("expired read: got %v, want ErrUnauthorized", errGet)
	}
	if store.TouchSession("session-a", time.Minute) {
		t.Fatal("touching an expired grant must report false")
	}

	// A fresh grant is renewable, and the renewal extends the deadline.
	if _, errGrant := store.GrantSession("session-a", time.Minute); errGrant != nil {
		t.Fatalf("regrant: %v", errGrant)
	}
	store.mu.Lock()
	store.sessions["session-a"].expires = time.Now().Add(time.Minute)
	store.mu.Unlock()
	if !store.TouchSession("session-a", time.Hour) {
		t.Fatal("touch on a live grant must report true")
	}
	if _, errGet := store.SessionVault("session-a").Get("phone"); errGet != nil {
		t.Fatalf("read after touch: %v", errGet)
	}
}

func TestRevokingLastSessionDropsKeyOnPassphraseStore(t *testing.T) {
	store := grantStore(t)
	if _, errGrant := store.GrantSession("session-a", time.Minute); errGrant != nil {
		t.Fatalf("grant: %v", errGrant)
	}
	if !store.RevokeSession("session-a") {
		t.Fatal("revoke must report the grant existed")
	}
	if store.Unlocked() {
		t.Fatal("revoking the last grant on a passphrase store must drop the storage key")
	}
	if _, errGet := store.SessionVault("session-a").Get("phone"); !errors.Is(errGet, ErrLocked) {
		t.Fatalf("read after revoke: got %v, want ErrLocked", errGet)
	}
}

func TestRevokingOneSessionKeepsAnother(t *testing.T) {
	store := grantStore(t)
	for _, id := range []string{"session-a", "session-b"} {
		if _, errGrant := store.GrantSession(id, time.Minute); errGrant != nil {
			t.Fatalf("grant %s: %v", id, errGrant)
		}
	}
	if !store.RevokeSession("session-a") {
		t.Fatal("revoke session-a must report the grant existed")
	}
	if store.RevokeSession("session-a") {
		t.Fatal("revoking twice must report no grant")
	}
	if !store.Unlocked() {
		t.Fatal("session-b still holds the store open")
	}
	if _, errGet := store.SessionVault("session-b").Get("phone"); errGet != nil {
		t.Fatalf("session-b read: %v", errGet)
	}
	if _, errGet := store.SessionVault("session-a").Get("phone"); !errors.Is(errGet, ErrUnauthorized) {
		t.Fatalf("session-a read: got %v, want ErrUnauthorized", errGet)
	}
}

func TestMachineStoreKeepsBackendAccessAfterRevoke(t *testing.T) {
	store, errOpen := Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open: %v", errOpen)
	}
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable machine unlock: %v", errEnable)
	}
	if errSet := store.Set("phone", "api-secret"); errSet != nil {
		t.Fatalf("seed secret: %v", errSet)
	}
	if got := store.SystemAccess(); got != "machine" {
		t.Fatalf("SystemAccess = %q, want machine", got)
	}

	if _, errGrant := store.GrantSession("session-a", time.Minute); errGrant != nil {
		t.Fatalf("grant: %v", errGrant)
	}
	store.RevokeAllSessions()

	// The backend is a holder in its own right on a machine store: dropping the
	// session must not take credentials away from plugins and the supply service.
	if !store.Unlocked() {
		t.Fatal("a machine store must stay open after the last session is revoked")
	}
	if got, errGet := store.Get("phone"); errGet != nil || got != "api-secret" {
		t.Fatalf("backend read after revoke = %q, %v", got, errGet)
	}
	if _, errGet := store.SessionVault("session-a").Get("phone"); !errors.Is(errGet, ErrUnauthorized) {
		t.Fatalf("revoked session read: got %v, want ErrUnauthorized", errGet)
	}
}

func TestSweepExpiredDropsOnlyStaleGrants(t *testing.T) {
	store := grantStore(t)
	for _, id := range []string{"stale", "live"} {
		if _, errGrant := store.GrantSession(id, time.Minute); errGrant != nil {
			t.Fatalf("grant %s: %v", id, errGrant)
		}
	}
	store.mu.Lock()
	store.sessions["stale"].expires = time.Now().Add(-time.Second)
	store.mu.Unlock()

	if dropped := store.SweepExpired(time.Now()); dropped != 1 {
		t.Fatalf("swept %d grants, want 1", dropped)
	}
	if store.LiveSessions() != 1 {
		t.Fatalf("live sessions = %d, want 1", store.LiveSessions())
	}
	if _, errGet := store.SessionVault("live").Get("phone"); errGet != nil {
		t.Fatalf("live session read: %v", errGet)
	}
}

func TestSystemAccessTracksMode(t *testing.T) {
	store := grantStore(t)
	if got := store.SystemAccess(); got != "session" {
		t.Fatalf("SystemAccess on an open passphrase store = %q, want session", got)
	}
	store.Lock()
	if got := store.SystemAccess(); got != "none" {
		t.Fatalf("SystemAccess on a locked passphrase store = %q, want none", got)
	}
	if _, errGrant := store.GrantSession("session-a", time.Minute); !errors.Is(errGrant, ErrLocked) {
		t.Fatalf("grant on a locked store: got %v, want ErrLocked", errGrant)
	}
}

// A store configured for unattended access is not the same as a store the
// backend can actually reach: when the seal cannot be opened (host moved, DPAPI
// profile reset, seal deleted) the process is waiting for the passphrase. The
// status must say so, otherwise the panel promises plugins a capability they do
// not have and nobody looks at the warning in the log.
func TestMachineStoreWithoutSealReportsNoBackendAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, errOpen := Open(path)
	if errOpen != nil {
		t.Fatalf("open: %v", errOpen)
	}
	if errInit := store.Initialize("correct horse battery"); errInit != nil {
		t.Fatalf("initialize: %v", errInit)
	}
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable machine unlock: %v", errEnable)
	}
	if got := store.SystemAccess(); got != "machine" {
		t.Fatalf("SystemAccess = %q, want machine", got)
	}

	if errRemove := os.Remove(path + ".seal"); errRemove != nil {
		t.Fatalf("drop seal: %v", errRemove)
	}
	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen without seal: %v", errReopen)
	}
	if reopened.Unlocked() {
		t.Fatal("a store whose seal is gone must wait for the passphrase")
	}
	if got := reopened.SystemAccess(); got != "none" {
		t.Fatalf("SystemAccess without a usable seal = %q, want none", got)
	}

	// The passphrase still opens it, and then the backend borrows the key.
	if errUnlock := reopened.Unlock("correct horse battery"); errUnlock != nil {
		t.Fatalf("unlock with passphrase: %v", errUnlock)
	}
	if got := reopened.SystemAccess(); got != "machine" {
		t.Fatalf("SystemAccess after passphrase unlock = %q, want machine", got)
	}
}

func TestGrantRequiresSessionIdentity(t *testing.T) {
	store := grantStore(t)
	if _, errGrant := store.GrantSession("", time.Minute); !errors.Is(errGrant, ErrUnauthorized) {
		t.Fatalf("empty session grant: got %v, want ErrUnauthorized", errGrant)
	}
	var disabled *Store
	if _, errGrant := disabled.GrantSession("session-a", time.Minute); !errors.Is(errGrant, ErrLocked) {
		t.Fatalf("grant on a nil store: got %v, want ErrLocked", errGrant)
	}
	if _, errGet := disabled.SessionVault("session-a").Get("phone"); !errors.Is(errGet, ErrLocked) {
		t.Fatalf("read from a nil store: got %v, want ErrLocked", errGet)
	}
}
