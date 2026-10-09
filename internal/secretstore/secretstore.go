// Package secretstore implements a machine-self-protected, host-owned secret
// store.
//
// The store keeps named secrets in a single versioned file. The whole secret map
// (names and values) is serialized to JSON and encrypted with AES-256-GCM under a
// random 32-byte machine key. Neither the machine key nor the plaintext items are
// ever written into the store file: the key lives in a separate 0600 key file
// beside it, so the store file alone discloses neither secret names nor secret
// values.
//
// The store opens itself: Open decrypts the items as soon as the machine key is
// present, so a headless deployment serves secrets without an operator. Because
// the machine key sits on the same host, this stops a copied store file from
// being readable elsewhere, but it is not a defence against someone who already
// has the host's filesystem.
//
// A master passphrase is a separate, stronger gate. It is never used to derive a
// storage key; instead the store keeps an Argon2id verifier so callers can ask
// "does this passphrase match?" before performing a sensitive action. The
// passphrase can be installed lazily, which keeps an empty store usable while the
// operator has not created one yet.
package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
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
const FormatVersion = 2

const (
	aeadName = "aes-256-gcm"

	// aadPrefix binds a ciphertext to its slot so the canary ciphertext cannot be
	// replayed as the items ciphertext, or vice versa.
	aadPrefix = "cpa-secretstore:v2:"

	canarySlot      = "canary"
	itemsSlot       = "items"
	canaryPlaintext = "cpa-secretstore:v2"

	machineKeyLen = 32

	// Passphrase verifier parameters. They only protect a guess-checking oracle,
	// so the cost can stay modest while remaining far above a single hash.
	verifierTime        uint32 = 3
	verifierMemory      uint32 = 64 * 1024 // KiB (64 MiB)
	verifierParallelism uint8  = 4
	verifierKeyLen      uint32 = 32
	verifierSaltLen            = 16

	// Bounds protect against a hostile or corrupted file requesting an
	// unreasonable amount of work.
	maxTime        = 32
	maxMemory      = 4 * 1024 * 1024 // KiB (4 GiB)
	maxParallelism = 64
)

var (
	// ErrLocked is returned when no machine key is available, so secrets cannot
	// be read or written. It is the only state in which the store is unusable.
	ErrLocked = errors.New("secret store is locked")
	// ErrNotFound is returned when the named secret does not exist.
	ErrNotFound = errors.New("secret not found")
	// ErrNoPassphrase is returned when a passphrase check is attempted before one
	// has been installed.
	ErrNoPassphrase = errors.New("no master passphrase is configured")
	// ErrInvalidPassphrase is returned when the verifier does not match.
	ErrInvalidPassphrase = errors.New("invalid passphrase")
	// ErrEmptyPassphrase is returned when an empty passphrase is supplied.
	ErrEmptyPassphrase = errors.New("passphrase must not be empty")
	// ErrEmptyName is returned when a blank secret name is supplied.
	ErrEmptyName = errors.New("secret name must not be empty")
)

// verifier is the stored Argon2id commitment used to check a master passphrase
// without keeping the passphrase itself.
type verifier struct {
	Name        string `json:"name"`
	Salt        []byte `json:"salt"`
	Time        uint32 `json:"time"`
	Memory      uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"keylen"`
	Hash        []byte `json:"hash"`
}

// envelope is the on-disk representation. Items holds the sealed JSON map of
// secret name to secret value; both names and values are therefore opaque at
// rest. Verifier is present once a master passphrase has been installed.
type envelope struct {
	Version  int       `json:"v"`
	AEAD     string    `json:"aead"`
	Canary   []byte    `json:"canary,omitempty"`
	Items    []byte    `json:"items,omitempty"`
	Verifier *verifier `json:"verifier,omitempty"`
}

// Store is a machine-self-protected secret store backed by a single file.
//
// A Store is safe for concurrent use. The zero value is not usable; call Open.
type Store struct {
	path    string
	keyPath string

	mu    sync.RWMutex
	env   envelope
	key   []byte
	items map[string]string
}

// Open loads the store at path, decrypting it with the machine key stored beside
// it. A missing store is an empty but usable store; the files are only created
// when something is written.
//
// When the machine key file is missing but the store file exists, the store
// cannot be decrypted: it opens locked so the caller can report the problem
// instead of silently discarding data.
func Open(path string) (*Store, error) {
	clean := filepath.Clean(path)
	store := &Store{path: clean, keyPath: clean + ".key"}

	rawKey, errKey := os.ReadFile(store.keyPath)
	rawStore, errStore := os.ReadFile(clean)

	switch {
	case errKey == nil && len(rawKey) > 0:
		if len(rawKey) != machineKeyLen {
			return nil, fmt.Errorf("machine key %s is %d bytes, want %d", store.keyPath, len(rawKey), machineKeyLen)
		}
		store.key = append([]byte(nil), rawKey...)
	case errors.Is(errKey, os.ErrNotExist):
		// No machine key yet. Only an empty (or absent) store may start fresh;
		// an existing store without its key would be unreadable, so refuse to
		// pretend it is empty and fail loudly instead.
		if errStore == nil && len(rawStore) > 0 {
			return nil, fmt.Errorf("machine key %s is missing but %s exists", store.keyPath, clean)
		}
		store.key = randomBytes(machineKeyLen)
	default:
		return nil, fmt.Errorf("read machine key %s: %w", store.keyPath, errKey)
	}

	if errStore != nil {
		if errors.Is(errStore, os.ErrNotExist) {
			store.env = newEnvelope()
		} else {
			return nil, fmt.Errorf("read secret store %s: %w", clean, errStore)
		}
	} else if len(rawStore) == 0 {
		store.env = newEnvelope()
	} else {
		if errUnmarshal := json.Unmarshal(rawStore, &store.env); errUnmarshal != nil {
			return nil, fmt.Errorf("parse secret store %s: %w", clean, errUnmarshal)
		}
		if errValidate := store.env.validate(); errValidate != nil {
			return nil, fmt.Errorf("secret store %s: %w", clean, errValidate)
		}
	}
	// Seal or unseal exactly once, so a fresh store already carries a canary and
	// a reopen decrypts the items instead of mistaking the file for empty.
	if errDecrypt := store.decryptLocked(); errDecrypt != nil {
		store.lockLocked()
		return nil, errDecrypt
	}
	return store, nil
}

// Path reports the backing file path.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
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

// Unlocked reports whether the machine key is held, i.e. whether secrets can be
// read and written. A store that opened successfully is normally unlocked.
func (s *Store) Unlocked() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key != nil
}

// Lock drops the in-memory machine key and decrypted secrets. Unlocking again
// requires the machine key file, which Open re-reads.
func (s *Store) Lock() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked()
}

// Unlock re-reads the machine key file and decrypts the store. It exists so a
// store that opened locked (for example its key file appeared later) can recover
// without a restart.
func (s *Store) Unlock() error {
	if s == nil {
		return ErrLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return nil
	}
	rawKey, errKey := os.ReadFile(s.keyPath)
	if errKey != nil {
		return fmt.Errorf("read machine key %s: %w", s.keyPath, errKey)
	}
	if len(rawKey) != machineKeyLen {
		return fmt.Errorf("machine key %s is %d bytes, want %d", s.keyPath, len(rawKey), machineKeyLen)
	}
	s.key = append([]byte(nil), rawKey...)
	if errDecrypt := s.decryptLocked(); errDecrypt != nil {
		s.lockLocked()
		return errDecrypt
	}
	return nil
}

// lockLocked drops the key and plaintext items. Callers must hold s.mu.
func (s *Store) lockLocked() {
	zero(s.key)
	s.key = nil
	s.items = nil
}

// decryptLocked unfolds the sealed items into the in-memory map. Callers must
// hold s.mu for writing. An empty envelope is materialised into a sealed empty
// map so a later write has somewhere to put it.
func (s *Store) decryptLocked() error {
	if len(s.env.Canary) == 0 {
		canary, errCanary := seal(s.key, aadFor(canarySlot), []byte(canaryPlaintext))
		if errCanary != nil {
			return errCanary
		}
		items, errItems := seal(s.key, aadFor(itemsSlot), []byte("{}"))
		if errItems != nil {
			return errItems
		}
		s.env.Canary = canary
		s.env.Items = items
		s.items = make(map[string]string)
		return nil
	}

	if _, errOpen := open(s.key, aadFor(canarySlot), s.env.Canary); errOpen != nil {
		// The canary fails only when the machine key does not match the store,
		// which means the two files do not belong together.
		return errors.New("machine key does not match the secret store")
	}
	plain, errItems := open(s.key, aadFor(itemsSlot), s.env.Items)
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

// HasPassphrase reports whether a master passphrase has been installed.
func (s *Store) HasPassphrase() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.env.Verifier != nil
}

// SetPassphrase installs or replaces the master passphrase. Replacing an
// existing passphrase requires the current one, so a caller cannot silently
// take over a store.
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
	if s.env.Verifier != nil {
		if current == "" {
			return ErrEmptyPassphrase
		}
		if !s.verifyLocked(current) {
			return ErrInvalidPassphrase
		}
	}
	v := newVerifier(next)
	previous := s.env.Verifier
	s.env.Verifier = &v
	if errSave := s.saveLocked(); errSave != nil {
		s.env.Verifier = previous
		return errSave
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
	if s.env.Verifier == nil {
		return ErrNoPassphrase
	}
	if !s.verifyLocked(passphrase) {
		return ErrInvalidPassphrase
	}
	return nil
}

// verifyLocked checks passphrase against the stored commitment. Callers must
// hold s.mu.
func (s *Store) verifyLocked(passphrase string) bool {
	v := s.env.Verifier
	if v == nil {
		return false
	}
	got := argon2.IDKey([]byte(passphrase), v.Salt, v.Time, v.Memory, v.Parallelism, v.KeyLen)
	ok := subtle.ConstantTimeCompare(got, v.Hash) == 1
	zero(got)
	return ok
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

// saveLocked reseals the secret map and persists the envelope together with the
// machine key. Callers must hold s.mu for writing.
func (s *Store) saveLocked() error {
	plain, errMarshal := json.Marshal(s.items)
	if errMarshal != nil {
		return fmt.Errorf("encode secret store: %w", errMarshal)
	}
	sealed, errSeal := seal(s.key, aadFor(itemsSlot), plain)
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
	// The key is written first: a store file without its key is unrecoverable,
	// while a key without a store file is harmless.
	if errKey := writeFileAtomic(s.keyPath, s.key); errKey != nil {
		s.env.Items = previous
		return errKey
	}
	if errWrite := writeFileAtomic(s.path, raw); errWrite != nil {
		s.env.Items = previous
		return errWrite
	}
	return nil
}

// writeFileAtomic replaces path with data so a crash mid-write cannot leave a
// truncated file behind.
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

func (e *envelope) validate() error {
	if e.Version != FormatVersion {
		return fmt.Errorf("unsupported format version %d (want %d)", e.Version, FormatVersion)
	}
	if e.AEAD != aeadName {
		return fmt.Errorf("unsupported aead %q", e.AEAD)
	}
	if v := e.Verifier; v != nil {
		if v.Name != "argon2id" {
			return fmt.Errorf("unsupported verifier kdf %q", v.Name)
		}
		if len(v.Salt) < verifierSaltLen {
			return errors.New("verifier salt is too short")
		}
		if v.Time == 0 || v.Time > maxTime {
			return fmt.Errorf("verifier time out of range: %d", v.Time)
		}
		if v.Memory == 0 || v.Memory > maxMemory {
			return fmt.Errorf("verifier memory out of range: %d", v.Memory)
		}
		if v.Parallelism == 0 || v.Parallelism > maxParallelism {
			return fmt.Errorf("verifier parallelism out of range: %d", v.Parallelism)
		}
		if v.KeyLen == 0 || v.KeyLen > 64 {
			return fmt.Errorf("verifier key length out of range: %d", v.KeyLen)
		}
		if len(v.Hash) != int(v.KeyLen) {
			return fmt.Errorf("verifier hash is %d bytes, want %d", len(v.Hash), v.KeyLen)
		}
	}
	return nil
}

func newEnvelope() envelope {
	return envelope{Version: FormatVersion, AEAD: aeadName}
}

func newVerifier(passphrase string) verifier {
	v := verifier{
		Name:        "argon2id",
		Salt:        randomBytes(verifierSaltLen),
		Time:        verifierTime,
		Memory:      verifierMemory,
		Parallelism: verifierParallelism,
		KeyLen:      verifierKeyLen,
	}
	v.Hash = argon2.IDKey([]byte(passphrase), v.Salt, v.Time, v.Memory, v.Parallelism, v.KeyLen)
	return v
}

func aadFor(slot string) []byte {
	return []byte(aadPrefix + slot)
}

func seal(key, aad, plaintext []byte) ([]byte, error) {
	gcm, errAEAD := newAEAD(key)
	if errAEAD != nil {
		return nil, errAEAD
	}
	nonce := randomBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func open(key, aad, blob []byte) ([]byte, error) {
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
