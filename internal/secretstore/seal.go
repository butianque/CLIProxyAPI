package secretstore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The seal file holds the storage key at rest for machine-unlock stores.
//
// It replaces the older plaintext `<store>.key` file, which was 32 raw bytes on
// disk: anything that could read the file could read every credential. The seal
// file instead asks the operating system to protect the key, so reading it is not
// enough — the reader must also be the account (or on the machine, for machine
// scope) that sealed it.
//
// The medium is recorded in the file rather than configured, so a store keeps
// working when it is moved between hosts: an unreadable seal reports that plainly
// instead of silently falling back to a weaker one.
//
// Rotation keeps two keys in the file for the length of one operation. That is
// what makes rotation crash-safe: at every instant the store file and the seal
// file agree on at least one readable key.
const (
	// SealMediumPlain means the key is stored unencrypted. It is the only medium
	// available where the operating system offers nothing better, and it is
	// reported as such so the operator is never misled about the protection.
	SealMediumPlain = "plain"
	// SealMediumDPAPI means the key is protected by Windows DPAPI.
	SealMediumDPAPI = "dpapi"
)

// sealedKey is one protected copy of the storage key.
type sealedKey struct {
	// ID names the key so the store file can say which one encrypted it.
	ID string `json:"id"`
	// Payload is the medium's output for the raw 32-byte key.
	Payload []byte `json:"payload"`
}

// sealFile is the on-disk seal.
type sealFile struct {
	Version int         `json:"v"`
	Medium  string      `json:"medium"`
	Created time.Time   `json:"created"`
	Rotated int         `json:"rotated"`
	Keys    []sealedKey `json:"keys"`
}

// keyProtector turns a raw storage key into bytes that are safe to leave on disk
// and back. It is the only platform-dependent part of the store.
type keyProtector interface {
	medium() string
	protect(plain []byte) ([]byte, error)
	unprotect(blob []byte) ([]byte, error)
}

// protectorFor returns the protector for a medium. An unknown medium is an error
// rather than a fallback: silently downgrading protection is worse than refusing
// to open the store.
func protectorFor(medium string) (keyProtector, error) {
	switch medium {
	case SealMediumPlain:
		return plainProtector{}, nil
	case SealMediumDPAPI:
		return platformProtector()
	default:
		return nil, fmt.Errorf("unknown seal medium %q", medium)
	}
}

// plainProtector stores the key as-is.
type plainProtector struct{}

func (plainProtector) medium() string { return SealMediumPlain }

func (plainProtector) protect(plain []byte) ([]byte, error) {
	return append([]byte(nil), plain...), nil
}

func (plainProtector) unprotect(blob []byte) ([]byte, error) {
	return append([]byte(nil), blob...), nil
}

// newSealKeyID returns a short identifier for one key version.
func newSealKeyID() (string, error) {
	buf := make([]byte, 4)
	if _, errRead := rand.Read(buf); errRead != nil {
		return "", errRead
	}
	return hex.EncodeToString(buf), nil
}

// readSealFile loads the seal, migrating a legacy plaintext key file when it is
// the only thing present. The second result reports that legacy fallback, because
// a caller that is about to write must then write a real seal instead of treating
// the legacy file as one.
func readSealFile(sealPath, legacyKeyPath string) (*sealFile, bool, error) {
	raw, errRead := os.ReadFile(sealPath)
	if errRead == nil && len(raw) > 0 {
		var seal sealFile
		if errUnmarshal := json.Unmarshal(raw, &seal); errUnmarshal != nil {
			return nil, false, fmt.Errorf("parse seal file %s: %w", sealPath, errUnmarshal)
		}
		if seal.Version != 1 {
			return nil, false, fmt.Errorf("seal file %s has unsupported version %d", sealPath, seal.Version)
		}
		if len(seal.Keys) == 0 {
			return nil, false, fmt.Errorf("seal file %s holds no key", sealPath)
		}
		return &seal, false, nil
	}
	if errRead != nil && !os.IsNotExist(errRead) {
		return nil, false, fmt.Errorf("read seal file %s: %w", sealPath, errRead)
	}

	// Legacy: a bare 32-byte key file from before the seal existed.
	legacy, errLegacy := os.ReadFile(legacyKeyPath)
	if errLegacy != nil {
		if os.IsNotExist(errLegacy) {
			return nil, false, os.ErrNotExist
		}
		return nil, false, fmt.Errorf("read machine key %s: %w", legacyKeyPath, errLegacy)
	}
	if len(legacy) != storageKeyLen {
		return nil, false, fmt.Errorf("machine key %s is %d bytes, want %d", legacyKeyPath, len(legacy), storageKeyLen)
	}
	return &sealFile{
		Version: 1,
		Medium:  SealMediumPlain,
		Created: time.Now().UTC(),
		Keys:    []sealedKey{{ID: "", Payload: legacy}},
	}, true, nil
}

// writeSealFile persists the seal atomically.
func writeSealFile(sealPath string, seal *sealFile) error {
	raw, errMarshal := json.MarshalIndent(seal, "", "  ")
	if errMarshal != nil {
		return fmt.Errorf("encode seal file: %w", errMarshal)
	}
	if errMkdir := os.MkdirAll(filepath.Dir(sealPath), 0o700); errMkdir != nil {
		return fmt.Errorf("create seal directory: %w", errMkdir)
	}
	return writeFileAtomic(sealPath, raw)
}

// keyFor returns the raw storage key the store file was encrypted with.
//
// A store file without a key id predates rotation and used whichever key the seal
// held, so the single-key case is accepted.
func (f *sealFile) keyFor(keyID string) ([]byte, string, error) {
	protector, errProtector := protectorFor(f.Medium)
	if errProtector != nil {
		return nil, f.Medium, errProtector
	}
	if keyID == "" && len(f.Keys) == 1 {
		raw, errUnprotect := protector.unprotect(f.Keys[0].Payload)
		if errUnprotect != nil {
			return nil, f.Medium, errUnprotect
		}
		return raw, f.Medium, nil
	}
	for _, key := range f.Keys {
		if key.ID != keyID {
			continue
		}
		raw, errUnprotect := protector.unprotect(key.Payload)
		if errUnprotect != nil {
			return nil, f.Medium, errUnprotect
		}
		return raw, f.Medium, nil
	}
	return nil, f.Medium, fmt.Errorf("the seal holds no key %q; the store cannot be opened on this host", keyID)
}

// addSealedKey appends a protected key and returns the updated seal.
func (f *sealFile) addSealedKey(protector keyProtector, keyID string, key []byte) (*sealFile, error) {
	payload, errProtect := protector.protect(key)
	if errProtect != nil {
		return nil, errProtect
	}
	next := &sealFile{
		Version: f.Version,
		Medium:  protector.medium(),
		Created: f.Created,
		Rotated: f.Rotated,
		Keys:    append(append([]sealedKey(nil), f.Keys...), sealedKey{ID: keyID, Payload: payload}),
	}
	return next, nil
}

// onlyKey returns a seal holding just one key version.
func (f *sealFile) onlyKey(keyID string) *sealFile {
	next := &sealFile{Version: f.Version, Medium: f.Medium, Created: f.Created, Rotated: f.Rotated}
	for _, key := range f.Keys {
		if key.ID == keyID {
			next.Keys = []sealedKey{key}
			break
		}
	}
	return next
}

// reseal replaces one key version's protected payload with a fresh one and counts
// the rotation.
func (f *sealFile) reseal(protector keyProtector, keyID string, key []byte) (*sealFile, error) {
	payload, errProtect := protector.protect(key)
	if errProtect != nil {
		return nil, errProtect
	}
	next := &sealFile{
		Version: f.Version,
		Medium:  protector.medium(),
		Created: f.Created,
		Rotated: f.Rotated + 1,
		Keys:    make([]sealedKey, 0, len(f.Keys)),
	}
	for _, entry := range f.Keys {
		if entry.ID == keyID {
			entry.Payload = payload
		}
		next.Keys = append(next.Keys, entry)
	}
	if len(next.Keys) == 0 {
		next.Keys = []sealedKey{{ID: keyID, Payload: payload}}
	}
	return next, nil
}

// SealMedium reports how the storage key is protected at rest:
//
//	"dpapi" — the OS protects it; reading the file is not enough to read it;
//	"plain" — the file is the key, so its permissions are the only protection;
//	""      — no machine key exists (a passphrase-only store).
//
// It describes the file that is actually on disk, so the panel never has to
// guess and never overstates the protection.
func (s *Store) SealMedium() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.mode != UnlockMachine && s.mode != UnlockPassphraseMachine {
		return ""
	}
	return s.sealMedium
}

// RotateSeal re-wraps the storage key with a fresh seal and counts the rotation.
//
// It is what "refresh the machine key periodically" means here, and it is worth
// being precise about what it does: the same 32-byte storage key is wrapped again
// with new OS-supplied randomness. A copy of the old seal file still decrypts, so
// this does not revoke a leaked copy — revoking one means replacing the storage
// key itself, which requires re-encrypting the store. What rotation does buy is a
// bounded, observable window for the artifact that is current, and a clean hook
// for a medium that can rotate real credentials later.
func (s *Store) RotateSeal() error {
	if s == nil {
		return ErrLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return ErrLocked
	}
	if s.mode != UnlockMachine && s.mode != UnlockPassphraseMachine {
		return nil
	}
	existing, legacy, errSeal := readSealFile(s.sealPath, s.keyPath)
	if errSeal != nil || legacy {
		// Nothing sealed yet: writing the seal is the rotation's job here.
		return s.sealKeyLocked()
	}
	protector, errProtector := platformProtector()
	if errProtector != nil {
		return errProtector
	}
	keyID := s.env.KeyID
	if _, _, errKey := existing.keyFor(keyID); errKey != nil {
		// The seal does not know this key yet; write it rather than rotate.
		return s.sealKeyLocked()
	}
	next, errReseal := existing.reseal(protector, keyID, s.key)
	if errReseal != nil {
		return errReseal
	}
	// Prove the new blob reads back before it replaces the working one.
	roundTrip, _, errUnprotect := next.keyFor(keyID)
	if errUnprotect != nil {
		return errUnprotect
	}
	if !bytes.Equal(roundTrip, s.key) {
		zero(roundTrip)
		return errors.New("seal rotation produced a key that does not match the store")
	}
	zero(roundTrip)
	if errWrite := writeSealFile(s.sealPath, next); errWrite != nil {
		return errWrite
	}
	s.sealMedium = next.Medium
	return nil
}
