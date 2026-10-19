package secretstore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// machineStore returns an open machine-unlock store holding one secret.
func machineStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, errOpen := Open(path)
	if errOpen != nil {
		t.Fatalf("open: %v", errOpen)
	}
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		t.Fatalf("enable machine unlock: %v", errEnable)
	}
	if errSet := store.Set("phone", "api-secret"); errSet != nil {
		t.Fatalf("seed secret: %v", errSet)
	}
	return store, path
}

func readSeal(t *testing.T, path string) sealFile {
	t.Helper()
	raw, errRead := os.ReadFile(path + ".seal")
	if errRead != nil {
		t.Fatalf("read seal: %v", errRead)
	}
	var seal sealFile
	if errUnmarshal := json.Unmarshal(raw, &seal); errUnmarshal != nil {
		t.Fatalf("parse seal: %v", errUnmarshal)
	}
	return seal
}

// TestSealProtectsTheKeyOnDisk covers the point of the seal: the file on disk is
// not the key.
func TestSealProtectsTheKeyOnDisk(t *testing.T) {
	store, path := machineStore(t)
	seal := readSeal(t, path)

	protector, errProtector := platformProtector()
	if errProtector != nil {
		t.Fatalf("protector: %v", errProtector)
	}
	if seal.Medium != protector.medium() {
		t.Fatalf("seal medium = %q, want %q", seal.Medium, protector.medium())
	}
	if store.SealMedium() != seal.Medium {
		t.Fatalf("reported medium = %q, want %q", store.SealMedium(), seal.Medium)
	}
	if len(seal.Keys) != 1 {
		t.Fatalf("seal holds %d keys, want 1", len(seal.Keys))
	}
	if seal.Medium == SealMediumPlain {
		// Nothing to hide on a platform with no OS protection, but the file must
		// still be honest about it.
		if !bytes.Equal(seal.Keys[0].Payload, store.key) {
			t.Fatal("a plain seal must carry the key itself")
		}
		return
	}
	if bytes.Equal(seal.Keys[0].Payload, store.key) {
		t.Fatal("the sealed payload must not be the raw storage key")
	}
}

// TestRotateSealRewrapsWithoutLosingTheStore covers rotation: the artifact changes,
// the rotation is counted, and the store still opens.
func TestRotateSealRewrapsWithoutLosingTheStore(t *testing.T) {
	store, path := machineStore(t)
	before := readSeal(t, path)

	if errRotate := store.RotateSeal(); errRotate != nil {
		t.Fatalf("rotate: %v", errRotate)
	}
	after := readSeal(t, path)
	if after.Rotated != before.Rotated+1 {
		t.Fatalf("rotated = %d, want %d", after.Rotated, before.Rotated+1)
	}
	if len(after.Keys) != 1 || after.Keys[0].ID != before.Keys[0].ID {
		t.Fatal("rotation must keep the same key version, only re-wrapped")
	}
	if bytes.Equal(after.Keys[0].Payload, before.Keys[0].Payload) {
		t.Fatal("rotation must produce a different protected payload")
	}

	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("reopen after rotation: %v", errReopen)
	}
	if got, errGet := reopened.Get("phone"); errGet != nil || got != "api-secret" {
		t.Fatalf("read after rotation = %q, %v", got, errGet)
	}
}

// TestLegacyKeyFileIsMigrated covers an existing deployment: the plaintext key file
// is replaced by a seal and then removed.
func TestLegacyKeyFileIsMigrated(t *testing.T) {
	store, path := machineStore(t)
	rawKey := append([]byte(nil), store.key...)

	// Rewind to the pre-seal layout.
	if errRemove := os.Remove(path + ".seal"); errRemove != nil {
		t.Fatalf("remove seal: %v", errRemove)
	}
	if errWrite := os.WriteFile(path+".key", rawKey, 0o600); errWrite != nil {
		t.Fatalf("write legacy key: %v", errWrite)
	}
	// The store file must not name a key version, or the legacy single-key case
	// would not be exercised.
	store.mu.Lock()
	store.env.KeyID = ""
	store.mu.Unlock()
	if errSave := store.saveLocked(); errSave != nil {
		t.Fatalf("rewrite store: %v", errSave)
	}

	reopened, errReopen := Open(path)
	if errReopen != nil {
		t.Fatalf("open legacy store: %v", errReopen)
	}
	if got, errGet := reopened.Get("phone"); errGet != nil || got != "api-secret" {
		t.Fatalf("legacy read = %q, %v", got, errGet)
	}

	// Any write migrates the layout.
	if errSet := reopened.Set("other", "x"); errSet != nil {
		t.Fatalf("set after migration: %v", errSet)
	}
	if _, errSeal := os.Stat(path + ".seal"); errSeal != nil {
		t.Fatalf("the seal was not written: %v", errSeal)
	}
	if _, errLegacy := os.Stat(path + ".key"); !os.IsNotExist(errLegacy) {
		t.Fatal("the plaintext key file must be removed once the seal exists")
	}

	again, errAgain := Open(path)
	if errAgain != nil {
		t.Fatalf("reopen after migration: %v", errAgain)
	}
	if got, errGet := again.Get("phone"); errGet != nil || got != "api-secret" {
		t.Fatalf("read after migration = %q, %v", got, errGet)
	}
}

// TestSealRotationRefusesPassphraseOnlyStore keeps rotation from inventing a
// machine key on a store that deliberately has none.
func TestSealRotationRefusesPassphraseOnlyStore(t *testing.T) {
	store := initStore(t, filepath.Join(t.TempDir(), "secrets.enc"), "master")
	if errRotate := store.RotateSeal(); errRotate != nil {
		t.Fatalf("rotate on a passphrase store must be a no-op, got %v", errRotate)
	}
	if medium := store.SealMedium(); medium != "" {
		t.Fatalf("SealMedium = %q, want empty for a passphrase store", medium)
	}
}

// TestSealMediumIsHonestAboutThePlatform pins the one case where the fallback is
// visible: a platform without OS protection must not claim it has any.
func TestSealMediumIsHonestAboutThePlatform(t *testing.T) {
	store, path := machineStore(t)
	seal := readSeal(t, path)
	if runtime.GOOS == "windows" && seal.Medium != SealMediumDPAPI {
		t.Fatalf("seal medium on Windows = %q, want %q", seal.Medium, SealMediumDPAPI)
	}
	if runtime.GOOS != "windows" && seal.Medium != SealMediumPlain {
		t.Fatalf("seal medium on %s = %q, want %q", runtime.GOOS, seal.Medium, SealMediumPlain)
	}
	if store.SealMedium() != seal.Medium {
		t.Fatalf("reported medium = %q, want %q", store.SealMedium(), seal.Medium)
	}
}
