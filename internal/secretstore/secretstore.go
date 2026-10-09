// Package secretstore implements a host-owned secret store whose unlock policy
// is explicit.
//
// The store keeps named secrets in a single versioned file: the whole secret map
// (names and values) is serialized to JSON and encrypted with AES-256-GCM under a
// random 32-byte storage key. The store file therefore discloses neither secret
// names nor secret values.
//
// How that storage key is unlocked is recorded in the file and chosen by the
// operator, never inferred:
//
//   - "passphrase" (the default): the storage key is wrapped under a key derived
//     from the master passphrase with Argon2id. No key file exists, so a copied
//     store file is useless without the passphrase.
//   - "machine": the storage key lives in a 0600 key file beside the store, so a
//     headless deployment serves secrets without an operator. This protects a
//     copied store file from being read elsewhere, but it is not a defence
//     against someone who already has the host's filesystem.
//   - "passphrase+machine": the key is wrapped under the passphrase *and* cached
//     in the key file, so the operator unlocks once and restarts in between need
//     no passphrase. This is the explicit "remember on this machine" opt-in and
//     is exactly as strong as "machine" at rest.
//
// The default is "passphrase": the store starts locked and stays locked until the
// operator supplies the passphrase. Locking drops the storage key and plaintext
// items from memory.
package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// FormatVersion is the on-disk envelope version. It is part of the frozen
// storage contract: readers must reject versions they do not understand instead
// of guessing.
const FormatVersion = 3

// UnlockMode records how a store's storage key is obtained.
type UnlockMode string

const (
	// UnlockPassphrase derives the key from the master passphrase alone.
	UnlockPassphrase UnlockMode = "passphrase"
	// UnlockMachine reads the key from the 0600 key file beside the store.
	UnlockMachine UnlockMode = "machine"
	// UnlockPassphraseMachine wraps the key under the passphrase and also caches
	// it in the key file, so restarts need no passphrase.
	UnlockPassphraseMachine UnlockMode = "passphrase+machine"
)

const (
	aeadName = "aes-256-gcm"

	// aadPrefix binds a ciphertext to its slot so the wrapped key cannot be
	// replayed as the canary ciphertext, or vice versa.
	aadPrefix = "cpa-secretstore:v3:"

	canarySlot      = "canary"
	itemsSlot       = "items"
	keySlot         = "storage-key"
	canaryPlaintext = "cpa-secretstore:v3"

	storageKeyLen = 32

	// masterKeySaltLen is the salt length for the Argon2id master-key derivation.
	masterKeySaltLen = 16

	// Passphrase KDF parameters. They protect an offline guess of the master
	// passphrase, so the cost is deliberately far above a single hash.
	kdfTime        uint32 = 3
	kdfMemory      uint32 = 64 * 1024 // KiB (64 MiB)
	kdfParallelism uint8  = 4
	kdfKeyLen      uint32 = 32

	// Bounds protect against a hostile or corrupted file requesting an
	// unreasonable amount of work.
	maxTime        = 32
	maxMemory      = 4 * 1024 * 1024 // KiB (4 GiB)
	maxParallelism = 64
)

var (
	// ErrLocked is returned when the storage key is not available, so secrets
	// cannot be read or written. It is the only state in which the store is
	// unusable.
	ErrLocked = errors.New("secret store is locked")
	// ErrNotFound is returned when the named secret does not exist.
	ErrNotFound = errors.New("secret not found")
	// ErrNoPassphrase is returned when a passphrase operation is attempted on a
	// store that has no passphrase installed.
	ErrNoPassphrase = errors.New("no master passphrase is configured")
	// ErrInvalidPassphrase is returned when the passphrase does not unlock the
	// store.
	ErrInvalidPassphrase = errors.New("invalid passphrase")
	// ErrEmptyPassphrase is returned when an empty passphrase is supplied.
	ErrEmptyPassphrase = errors.New("passphrase must not be empty")
	// ErrEmptyName is returned when a blank secret name is supplied.
	ErrEmptyName = errors.New("secret name must not be empty")
	// ErrModeConflict is returned when a mode change is impossible, for example
	// enabling a passphrase on a machine-only store that cannot be re-wrapped
	// while locked.
	ErrModeConflict = errors.New("secret store unlock mode conflict")
)

// kdfParams records the Argon2id parameters used to derive the master key.
type kdfParams struct {
	Name        string `json:"name"`
	Salt        []byte `json:"salt"`
	Time        uint32 `json:"time"`
	Memory      uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"keylen"`
}

// envelope is the on-disk representation.
//
// StorageKey is the random storage key sealed under whichever keys are enabled
// (the master key, the machine key, or both); Items holds the sealed JSON map of
// secret name to value. Both names and values are therefore opaque at rest.
type envelope struct {
	Version    int        `json:"v"`
	AEAD       string     `json:"aead"`
	Unlock     UnlockMode `json:"unlock"`
	KDF        *kdfParams `json:"kdf,omitempty"`
	StorageKey []byte     `json:"storage_key,omitempty"`
	Canary     []byte     `json:"canary,omitempty"`
	Items      []byte     `json:"items,omitempty"`
}

// Store is a host-owned secret store backed by a single file.
//
// A Store is safe for concurrent use. The zero value is not usable; call Open.
type Store struct {
	path    string
	keyPath string

	mu    sync.RWMutex
	env   envelope
	key   []byte
	mode  UnlockMode
	items map[string]string
}

// Open loads the store at path. A missing store is an empty store awaiting
// Initialize; nothing is written until it is initialized (or machine unlock is
// enabled on an empty store).
//
// The store's unlock mode comes from the file. A brand-new store has no mode yet
// and stays locked: secrets cannot be read or written until the operator installs
// a passphrase (Initialize) or explicitly opts into machine unlock
// (EnableMachineUnlock on an empty store).
func Open(path string) (*Store, error) {
	clean := filepath.Clean(path)
	store := &Store{path: clean, keyPath: clean + ".key"}

	rawStore, errStore := os.ReadFile(clean)
	switch {
	case errStore == nil && len(rawStore) > 0:
		if errUnmarshal := json.Unmarshal(rawStore, &store.env); errUnmarshal != nil {
			return nil, fmt.Errorf("parse secret store %s: %w", clean, errUnmarshal)
		}
		if errValidate := store.env.validate(); errValidate != nil {
			return nil, fmt.Errorf("secret store %s: %w", clean, errValidate)
		}
		store.mode = store.env.Unlock
	case errStore == nil, errors.Is(errStore, os.ErrNotExist):
		// Brand new: remember the store needs initialization, but keep it locked
		// so no secret can be written before an unlock policy exists.
		store.mode = ""
	default:
		return nil, fmt.Errorf("read secret store %s: %w", clean, errStore)
	}

	// A machine-enabled store tries to auto-unlock from its key file; a
	// passphrase-only store stays locked until the operator supplies it.
	if store.mode == UnlockMachine || store.mode == UnlockPassphraseMachine {
		if errUnlock := store.unlockFromMachineKey(); errUnlock != nil {
			if store.mode == UnlockMachine {
				return nil, errUnlock
			}
			// passphrase+machine: a missing or stale key file is not fatal; the
			// store simply waits for the passphrase.
			store.lockLocked()
		}
	}
	return store, nil
}

// Initialized reports whether the store has an unlock policy yet. A store that is
// not initialized is brand new and must be set up with Initialize before use (an
// empty machine store may instead call EnableMachineUnlock).
func (s *Store) Initialized() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode != ""
}

// Initialize sets up a brand-new store with a master passphrase. It generates a
// fresh storage key, wraps it under the passphrase, and leaves the store
// unlocked. Calling it on an already-initialized store fails so an existing
// policy is never silently replaced.
func (s *Store) Initialize(passphrase string) error {
	if s == nil {
		return ErrLocked
	}
	if passphrase == "" {
		return ErrEmptyPassphrase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode != "" && s.env.Unlock != "" {
		return fmt.Errorf("%w: store is already initialized", ErrModeConflict)
	}
	params := newKDFParams()
	masterKey := deriveKDFKey(passphrase, params)
	defer zero(masterKey)

	storageKey := randomBytes(storageKeyLen)
	wrapped, errWrap := sealKey(masterKey, storageKey)
	if errWrap != nil {
		return errWrap
	}
	s.env = newEnvelope(UnlockPassphrase)
	s.env.KDF = &params
	s.env.StorageKey = wrapped
	s.mode = UnlockPassphrase
	if errDecrypt := s.adoptStorageKeyLocked(storageKey); errDecrypt != nil {
		return errDecrypt
	}
	return s.saveLocked()
}

// Path reports the backing file path.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Mode reports the store's unlock mode.
func (s *Store) Mode() UnlockMode {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// DefaultPath resolves the on-disk location of the store. The
// CPA_SECRET_STORE_PATH environment variable wins; otherwise the store lives
// next to the configuration file so it travels with the deployment.
func DefaultPath(configPath string) string {
	if env := strings.TrimSpace(os.Getenv("CPA_SECRET_STORE_PATH")); env != "" {
		return env
	}
	name := "cpa-secrets.enc"
	dir := strings.TrimSpace(filepath.Dir(configPath))
	if dir == "" || dir == "." {
		if abs, errAbs := filepath.Abs(name); errAbs == nil {
			return abs
		}
		return name
	}
	return filepath.Join(dir, name)
}

// Unlocked reports whether the storage key is held, i.e. whether secrets can be
// read and written.
func (s *Store) Unlocked() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key != nil
}

// HasPassphrase reports whether a master passphrase protects this store.
func (s *Store) HasPassphrase() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.env.KDF != nil
}

// Lock drops the in-memory storage key and decrypted secrets.
func (s *Store) Lock() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked()
}

// Unlock derives the storage key from the master passphrase. It is the way into a
// passphrase mode store, and it also works for a "passphrase+machine" store
// whether or not its key file is present.
//
// A store in pure machine mode has no passphrase; use Open or UnlockMachine.
func (s *Store) Unlock(passphrase string) error {
	if s == nil {
		return ErrLocked
	}
	if passphrase == "" {
		return ErrEmptyPassphrase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return nil
	}
	if s.env.KDF == nil {
		return ErrNoPassphrase
	}
	masterKey := deriveKDFKey(passphrase, *s.env.KDF)
	defer zero(masterKey)
	storageKey, errUnwrap := s.unwrapStorageKey(masterKey)
	if errUnwrap != nil {
		return ErrInvalidPassphrase
	}
	if errDecrypt := s.adoptStorageKeyLocked(storageKey); errDecrypt != nil {
		return errDecrypt
	}
	// A passphrase+machine store refreshes its key-file cache so a restart stays
	// password-free.
	if s.mode == UnlockPassphraseMachine {
		if errCache := s.cacheStorageKeyFile(); errCache != nil {
			return errCache
		}
	}
	return nil
}

// UnlockMachine loads the storage key from the key file. It is the way into a
// machine mode store and the fast path for a passphrase+machine store.
func (s *Store) UnlockMachine() error {
	if s == nil {
		return ErrLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return nil
	}
	if s.mode != UnlockMachine && s.mode != UnlockPassphraseMachine {
		return fmt.Errorf("%w: store unlock mode is %q", ErrModeConflict, s.mode)
	}
	return s.unlockFromMachineKey()
}

// unlockFromMachineKey reads the key file and decrypts the items. Callers must
// hold s.mu.
func (s *Store) unlockFromMachineKey() error {
	rawKey, errKey := os.ReadFile(s.keyPath)
	if errKey != nil {
		return fmt.Errorf("read machine key %s: %w", s.keyPath, errKey)
	}
	if len(rawKey) != storageKeyLen {
		return fmt.Errorf("machine key %s is %d bytes, want %d", s.keyPath, len(rawKey), storageKeyLen)
	}
	clone := append([]byte(nil), rawKey...)
	return s.adoptStorageKeyLocked(clone)
}

// adoptStorageKeyLocked installs key, decrypts the items, and discards the key on
// failure. Callers must hold s.mu for writing.
func (s *Store) adoptStorageKeyLocked(key []byte) error {
	if len(key) != storageKeyLen {
		return fmt.Errorf("storage key is %d bytes, want %d", len(key), storageKeyLen)
	}
	previous := s.key
	s.key = key
	if errDecrypt := s.decryptLocked(); errDecrypt != nil {
		zero(s.key)
		s.key = previous
		return errDecrypt
	}
	zero(previous)
	return nil
}

// lockLocked drops the key and plaintext items. Callers must hold s.mu.
func (s *Store) lockLocked() {
	zero(s.key)
	s.key = nil
	s.items = nil
}

// SetPassphrase replaces the master passphrase. The current passphrase is
// required, so a caller cannot silently take over a store. It is not used to
// create the first passphrase: a brand-new store is set up with Initialize.
//
// The mode stays passphrase (or passphrase+machine); the machine key file is
// removed unless machine unlock is kept.
func (s *Store) SetPassphrase(current, next string) error {
	if s == nil {
		return ErrLocked
	}
	if next == "" {
		return ErrEmptyPassphrase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return ErrLocked
	}
	if s.env.KDF == nil {
		return ErrNoPassphrase
	}
	if current == "" {
		return ErrEmptyPassphrase
	}
	// Validate the current passphrase by unwrapping the storage key.
	currentMasterKey := deriveKDFKey(current, *s.env.KDF)
	_, errCheck := s.unwrapStorageKey(currentMasterKey)
	zero(currentMasterKey)
	if errCheck != nil {
		return ErrInvalidPassphrase
	}

	params := newKDFParams()
	nextMasterKey := deriveKDFKey(next, params)
	defer zero(nextMasterKey)

	previousEnv := s.env
	previousMode := s.mode
	wrapped, errWrap := sealKey(nextMasterKey, s.key)
	if errWrap != nil {
		return errWrap
	}
	previousEnvKDF := *s.env.KDF
	s.env.KDF = &params
	s.env.StorageKey = wrapped
	keepMachine := s.mode == UnlockPassphraseMachine
	if keepMachine {
		s.mode = UnlockPassphraseMachine
	} else {
		s.mode = UnlockPassphrase
	}
	s.env.Unlock = s.mode

	if errSave := s.saveLocked(); errSave != nil {
		s.env.KDF = &previousEnvKDF
		s.env.StorageKey = previousEnv.StorageKey
		s.env.Unlock = previousEnv.Unlock
		s.mode = previousMode
		return errSave
	}
	if !keepMachine {
		if errRemove := removeIfExists(s.keyPath); errRemove != nil {
			return errRemove
		}
	} else if errCache := s.cacheStorageKeyFile(); errCache != nil {
		return errCache
	}
	return nil
}

// VerifyPassphrase reports whether passphrase matches the installed master
// passphrase. An unset passphrase yields ErrNoPassphrase so a caller can decide
// whether that is acceptable rather than treating it as a wrong passphrase.
func (s *Store) VerifyPassphrase(passphrase string) error {
	if s == nil {
		return ErrLocked
	}
	if passphrase == "" {
		return ErrEmptyPassphrase
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.env.KDF == nil {
		return ErrNoPassphrase
	}
	masterKey := deriveKDFKey(passphrase, *s.env.KDF)
	defer zero(masterKey)
	if _, errUnwrap := s.unwrapStorageKey(masterKey); errUnwrap != nil {
		return ErrInvalidPassphrase
	}
	return nil
}

// EnableMachineUnlock switches the store to a machine-unlockable mode so a
// headless deployment does not need the passphrase after each restart.
//
// On an initialized passphrase-protected store the mode becomes
// "passphrase+machine": the passphrase still unlocks it, and the key is
// additionally cached in the key file. On an uninitialized (brand-new) store the
// mode becomes pure "machine" with a fresh storage key.
//
// Enabling this writes the storage key to the key file, which weakens protection
// to "anyone with the host filesystem" — the caller is expected to have warned
// the operator.
func (s *Store) EnableMachineUnlock() error {
	if s == nil {
		return ErrLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mode == UnlockMachine || s.mode == UnlockPassphraseMachine {
		return s.cacheStorageKeyFile()
	}

	if s.mode == "" {
		// Brand-new store: create it in pure machine mode.
		s.env = newEnvelope(UnlockMachine)
		s.mode = UnlockMachine
		s.key = randomBytes(storageKeyLen)
		s.items = make(map[string]string)
		if errDecrypt := s.decryptLocked(); errDecrypt != nil {
			return errDecrypt
		}
		return s.saveLocked()
	}

	if s.key == nil {
		return ErrLocked
	}
	if s.env.KDF != nil {
		s.mode = UnlockPassphraseMachine
	} else {
		s.mode = UnlockMachine
	}
	s.env.Unlock = s.mode
	if errSave := s.saveLocked(); errSave != nil {
		return errSave
	}
	return s.cacheStorageKeyFile()
}

// DisableMachineUnlock removes the machine key file. A passphrase-protected store
// stays unlockable by passphrase; a store with no passphrase cannot be left
// without a key file, so it becomes locked until a passphrase is installed.
func (s *Store) DisableMachineUnlock() error {
	if s == nil {
		return ErrLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mode != UnlockMachine && s.mode != UnlockPassphraseMachine {
		return nil
	}
	if s.env.KDF != nil {
		s.mode = UnlockPassphrase
	} else {
		// No passphrase: dropping the key file would make the store
		// unrecoverable, so refuse instead of destroying data.
		return fmt.Errorf("%w: install a master passphrase before disabling machine unlock", ErrModeConflict)
	}
	s.env.Unlock = s.mode
	if errSave := s.saveLocked(); errSave != nil {
		return errSave
	}
	return removeIfExists(s.keyPath)
}

// Names lists the stored secret names in sorted order.
func (s *Store) Names() ([]string, error) {
	if s == nil {
		return nil, ErrLocked
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return nil, ErrLocked
	}
	names := make([]string, 0, len(s.items))
	for name := range s.items {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

// Get returns the plaintext value for name.
func (s *Store) Get(name string) (string, error) {
	if s == nil {
		return "", ErrLocked
	}
	if name == "" {
		return "", ErrEmptyName
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.key == nil {
		return "", ErrLocked
	}
	value, ok := s.items[name]
	if !ok {
		return "", ErrNotFound
	}
	return value, nil
}

// Set stores value under name, creating or replacing it.
func (s *Store) Set(name, value string) error {
	if s == nil {
		return ErrLocked
	}
	if name == "" {
		return ErrEmptyName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return ErrLocked
	}
	if s.items == nil {
		s.items = make(map[string]string)
	}
	previous, had := s.items[name]
	s.items[name] = value
	if errSave := s.saveLocked(); errSave != nil {
		if had {
			s.items[name] = previous
		} else {
			delete(s.items, name)
		}
		return errSave
	}
	return nil
}

// Delete removes name. Deleting a missing name is not an error.
func (s *Store) Delete(name string) error {
	if s == nil {
		return ErrLocked
	}
	if name == "" {
		return ErrEmptyName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return ErrLocked
	}
	previous, had := s.items[name]
	if !had {
		return nil
	}
	delete(s.items, name)
	if errSave := s.saveLocked(); errSave != nil {
		s.items[name] = previous
		return errSave
	}
	return nil
}

// cacheStorageKeyFile writes the storage key to the key file. Callers must hold
// s.mu.
func (s *Store) cacheStorageKeyFile() error {
	if s.key == nil {
		return ErrLocked
	}
	return writeFileAtomic(s.keyPath, s.key)
}

// saveLocked reseals the secret map and persists the envelope. Callers must hold
// s.mu for writing.
func (s *Store) saveLocked() error {
	plain, errMarshal := json.Marshal(s.items)
	if errMarshal != nil {
		return fmt.Errorf("encode secret store: %w", errMarshal)
	}
	sealed, errSeal := sealRaw(s.key, aadFor(itemsSlot), plain)
	zero(plain)
	if errSeal != nil {
		return errSeal
	}
	previous := s.env.Items
	s.env.Items = sealed

	raw, errEncode := json.MarshalIndent(s.env, "", "  ")
	if errEncode != nil {
		s.env.Items = previous
		return fmt.Errorf("encode secret store: %w", errEncode)
	}
	// The key file is written first: a store file without its key is
	// unrecoverable, while a key without a store file is harmless.
	if s.mode == UnlockMachine || s.mode == UnlockPassphraseMachine {
		if errKey := writeFileAtomic(s.keyPath, s.key); errKey != nil {
			s.env.Items = previous
			return errKey
		}
	}
	if errWrite := writeFileAtomic(s.path, raw); errWrite != nil {
		s.env.Items = previous
		return errWrite
	}
	return nil
}

// decryptLocked unfolds the sealed items into the in-memory map. Callers must
// hold s.mu for writing. An empty envelope is materialised into a sealed empty
// map so a later write has somewhere to put it.
func (s *Store) decryptLocked() error {
	if len(s.env.Canary) == 0 {
		canary, errCanary := sealRaw(s.key, aadFor(canarySlot), []byte(canaryPlaintext))
		if errCanary != nil {
			return errCanary
		}
		items, errItems := sealRaw(s.key, aadFor(itemsSlot), []byte("{}"))
		if errItems != nil {
			return errItems
		}
		s.env.Canary = canary
		s.env.Items = items
		s.items = make(map[string]string)
		return nil
	}

	if _, errOpen := openRaw(s.key, aadFor(canarySlot), s.env.Canary); errOpen != nil {
		// The canary fails only when the storage key does not match the store.
		return errors.New("storage key does not match the secret store")
	}
	plain, errItems := openRaw(s.key, aadFor(itemsSlot), s.env.Items)
	if errItems != nil {
		return fmt.Errorf("decrypt secret store: %w", errItems)
	}
	items := make(map[string]string)
	if len(plain) > 0 {
		if errDecode := json.Unmarshal(plain, &items); errDecode != nil {
			zero(plain)
			return fmt.Errorf("decode secret store: %w", errDecode)
		}
	}
	zero(plain)
	s.items = items
	return nil
}

// unwrapStorageKey recovers the storage key from the envelope with masterKey.
// Callers must hold s.mu (read is enough). It returns ErrNoPassphrase when the
// envelope carries no passphrase wrap.
func (s *Store) unwrapStorageKey(masterKey []byte) ([]byte, error) {
	if s.env.KDF == nil || len(s.env.StorageKey) == 0 {
		return nil, ErrNoPassphrase
	}
	if !s.keyMatchesKDF(masterKey) {
		return nil, ErrInvalidPassphrase
	}
	return openRaw(masterKey, aadFor(keySlot), s.env.StorageKey)
}

// keyMatchesKDF reports whether masterKey decrypts the stored key wrap, which is
// how a candidate passphrase is validated.
func (s *Store) keyMatchesKDF(masterKey []byte) bool {
	if len(s.env.StorageKey) == 0 {
		return false
	}
	_, errOpen := openRaw(masterKey, aadFor(keySlot), s.env.StorageKey)
	return errOpen == nil
}

func (e *envelope) validate() error {
	if e.Version != FormatVersion {
		return fmt.Errorf("unsupported format version %d (want %d)", e.Version, FormatVersion)
	}
	if e.AEAD != aeadName {
		return fmt.Errorf("unsupported aead %q", e.AEAD)
	}
	switch e.Unlock {
	case UnlockPassphrase, UnlockMachine, UnlockPassphraseMachine:
	default:
		return fmt.Errorf("unsupported unlock mode %q", e.Unlock)
	}
	if e.KDF != nil {
		if e.KDF.Name != "argon2id" {
			return fmt.Errorf("unsupported kdf %q", e.KDF.Name)
		}
		if len(e.KDF.Salt) < masterKeySaltLen {
			return errors.New("kdf salt is too short")
		}
		if e.KDF.Time == 0 || e.KDF.Time > maxTime {
			return fmt.Errorf("kdf time out of range: %d", e.KDF.Time)
		}
		if e.KDF.Memory == 0 || e.KDF.Memory > maxMemory {
			return fmt.Errorf("kdf memory out of range: %d", e.KDF.Memory)
		}
		if e.KDF.Parallelism == 0 || e.KDF.Parallelism > maxParallelism {
			return fmt.Errorf("kdf parallelism out of range: %d", e.KDF.Parallelism)
		}
		if e.KDF.KeyLen == 0 || e.KDF.KeyLen > 64 {
			return fmt.Errorf("kdf key length out of range: %d", e.KDF.KeyLen)
		}
	}
	if e.Unlock == UnlockPassphrase || e.Unlock == UnlockPassphraseMachine {
		if e.KDF == nil {
			return errors.New("passphrase unlock mode requires kdf parameters")
		}
		if len(e.StorageKey) == 0 {
			return errors.New("passphrase unlock mode requires a wrapped storage key")
		}
	}
	if e.Unlock == UnlockMachine && e.KDF != nil {
		return errors.New("machine unlock mode must not carry kdf parameters")
	}
	return nil
}

func newEnvelope(mode UnlockMode) envelope {
	return envelope{Version: FormatVersion, AEAD: aeadName, Unlock: mode}
}

// newKDFParams returns fresh Argon2id parameters with a random salt. The
// parameters do not depend on the passphrase; only deriveKDFKey does.
func newKDFParams() kdfParams {
	return kdfParams{
		Name:        "argon2id",
		Salt:        randomBytes(masterKeySaltLen),
		Time:        kdfTime,
		Memory:      kdfMemory,
		Parallelism: kdfParallelism,
		KeyLen:      kdfKeyLen,
	}
}

func deriveKDFKey(passphrase string, p kdfParams) []byte {
	return argon2.IDKey([]byte(passphrase), p.Salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)
}

// sealKey wraps a storage key under masterKey.
func sealKey(masterKey, storageKey []byte) ([]byte, error) {
	return sealRaw(masterKey, aadFor(keySlot), storageKey)
}

func aadFor(slot string) []byte {
	return []byte(aadPrefix + slot)
}

func sealRaw(key, aad, plaintext []byte) ([]byte, error) {
	gcm, errAEAD := newAEAD(key)
	if errAEAD != nil {
		return nil, errAEAD
	}
	nonce := randomBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func openRaw(key, aad, blob []byte) ([]byte, error) {
	gcm, errAEAD := newAEAD(key)
	if errAEAD != nil {
		return nil, errAEAD
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, errors.New("ciphertext is truncated")
	}
	nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, errCipher := aes.NewCipher(key)
	if errCipher != nil {
		return nil, fmt.Errorf("create cipher: %w", errCipher)
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return nil, fmt.Errorf("create gcm: %w", errGCM)
	}
	return gcm, nil
}

// writeFileAtomic replaces path with data so a crash mid-write cannot leave a
// truncated file behind. The file is created 0600 and the parent directory 0700.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return fmt.Errorf("create secret store directory: %w", errMkdir)
	}
	tmp, errCreate := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if errCreate != nil {
		return fmt.Errorf("create temporary secret store: %w", errCreate)
	}
	tmpName := tmp.Name()
	if errChmod := tmp.Chmod(0o600); errChmod != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("secure temporary secret store: %w", errChmod)
	}
	if _, errWrite := tmp.Write(data); errWrite != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write secret store: %w", errWrite)
	}
	if errSync := tmp.Sync(); errSync != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("sync secret store: %w", errSync)
	}
	if errClose := tmp.Close(); errClose != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close secret store: %w", errClose)
	}
	if errRename := os.Rename(tmpName, path); errRename != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace secret store: %w", errRename)
	}
	return nil
}

// removeIfExists deletes path, treating a missing file as success.
func removeIfExists(path string) error {
	if errRemove := os.Remove(path); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, errRemove)
	}
	return nil
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, errRead := rand.Read(buf); errRead != nil {
		// crypto/rand.Read never returns an error on supported platforms; a
		// failure here means the platform RNG is unusable and we must not
		// silently continue with predictable bytes.
		panic(fmt.Sprintf("secretstore: crypto/rand failed: %v", errRead))
	}
	return buf
}

func zero(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

var (
	defaultMu    sync.RWMutex
	defaultStore *Store
)

// Configure installs the process-wide store. A nil store disables the feature.
func Configure(store *Store) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultStore = store
}

// Default returns the process-wide store, or nil when the feature is disabled.
func Default() *Store {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultStore
}
