// Package secretstore implements a passphrase-encrypted, host-owned secret store.
//
// The store keeps named secrets in a single versioned file. The whole secret map
// (names and values) is serialized to JSON and encrypted with AES-256-GCM under a
// key derived from an operator passphrase using Argon2id. Neither the passphrase
// nor the derived key is ever written to disk, and the file discloses neither
// secret names nor secret values.
//
// The store starts locked and is unlocked on demand, so a headless deployment
// keeps serving without an operator present until a secret is actually needed.
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
const FormatVersion = 1

const (
	kdfName  = "argon2id"
	aeadName = "aes-256-gcm"

	// aadPrefix binds a ciphertext to its slot so the canary ciphertext cannot be
	// replayed as the items ciphertext, or vice versa.
	aadPrefix = "cpa-secretstore:v1:"

	canarySlot      = "canary"
	itemsSlot       = "items"
	canaryPlaintext = "cpa-secretstore:v1"

	defaultTime        uint32 = 3
	defaultMemory      uint32 = 64 * 1024 // KiB (64 MiB)
	defaultParallelism uint8  = 4
	defaultKeyLen      uint32 = 32
	saltLen                   = 16

	// Bounds protect against a hostile or corrupted file requesting an
	// unreasonable amount of work at unlock time.
	maxTime        = 32
	maxMemory      = 4 * 1024 * 1024 // KiB (4 GiB)
	maxParallelism = 64
)

var (
	// ErrLocked is returned when a secret is read or written while locked.
	ErrLocked = errors.New("secret store is locked")
	// ErrNotFound is returned when the named secret does not exist.
	ErrNotFound = errors.New("secret not found")
	// ErrInvalidPassphrase is returned when the canary does not decrypt.
	ErrInvalidPassphrase = errors.New("invalid passphrase")
	// ErrEmptyPassphrase is returned when an empty passphrase is supplied.
	ErrEmptyPassphrase = errors.New("passphrase must not be empty")
	// ErrEmptyName is returned when a blank secret name is supplied.
	ErrEmptyName = errors.New("secret name must not be empty")
)

type kdfParams struct {
	Name        string `json:"name"`
	Salt        []byte `json:"salt"`
	Time        uint32 `json:"time"`
	Memory      uint32 `json:"memory"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"keylen"`
}

// envelope is the on-disk representation. Items holds the sealed JSON map of
// secret name to secret value; both names and values are therefore opaque at
// rest.
type envelope struct {
	Version int       `json:"v"`
	KDF     kdfParams `json:"kdf"`
	AEAD    string    `json:"aead"`
	Canary  []byte    `json:"canary,omitempty"`
	Items   []byte    `json:"items,omitempty"`
}

// Store is a passphrase-encrypted secret store backed by a single file.
//
// A Store is safe for concurrent use. The zero value is not usable; call Open.
type Store struct {
	path string

	mu    sync.RWMutex
	env   envelope
	key   []byte
	items map[string]string
}

// Open loads the store at path. A missing file yields an empty, locked store
// that materialises on the first successful Unlock. The file itself is only
// created when the first secret is written.
func Open(path string) (*Store, error) {
	clean := filepath.Clean(path)
	store := &Store{path: clean, env: newEnvelope()}

	raw, errRead := os.ReadFile(clean)
	if errRead != nil {
		if errors.Is(errRead, os.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("read secret store %s: %w", clean, errRead)
	}
	if len(raw) == 0 {
		return store, nil
	}
	if errUnmarshal := json.Unmarshal(raw, &store.env); errUnmarshal != nil {
		return nil, fmt.Errorf("parse secret store %s: %w", clean, errUnmarshal)
	}
	if errValidate := store.env.validate(); errValidate != nil {
		return nil, fmt.Errorf("secret store %s: %w", clean, errValidate)
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

// Unlocked reports whether a key is currently held in memory.
func (s *Store) Unlocked() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.key != nil
}

// Unlock derives the key from passphrase and verifies it against the canary.
// The first successful unlock on an empty store establishes the passphrase.
// Unlock is idempotent while already unlocked.
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
	key := deriveKey(passphrase, s.env.KDF)

	if len(s.env.Canary) == 0 {
		// First use on an empty store: establish the passphrase and start with
		// no secrets.
		canary, errCanary := seal(key, aadFor(canarySlot), []byte(canaryPlaintext))
		if errCanary != nil {
			zero(key)
			return errCanary
		}
		items, errItems := seal(key, aadFor(itemsSlot), []byte("{}"))
		if errItems != nil {
			zero(key)
			return errItems
		}
		s.env.Canary = canary
		s.env.Items = items
		s.key = key
		s.items = make(map[string]string)
		return s.saveLocked()
	}

	if _, errOpen := open(key, aadFor(canarySlot), s.env.Canary); errOpen != nil {
		zero(key)
		return ErrInvalidPassphrase
	}
	plain, errItems := open(key, aadFor(itemsSlot), s.env.Items)
	if errItems != nil {
		zero(key)
		return fmt.Errorf("decrypt secret store: %w", errItems)
	}
	items := make(map[string]string)
	if len(plain) > 0 {
		if errDecode := json.Unmarshal(plain, &items); errDecode != nil {
			zero(key)
			zero(plain)
			return fmt.Errorf("decode secret store: %w", errDecode)
		}
	}
	zero(plain)
	s.key = key
	s.items = items
	return nil
}

// Lock discards the in-memory key and decrypted secrets.
func (s *Store) Lock() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockLocked()
}

// lockLocked drops the key and plaintext items. Callers must hold s.mu.
func (s *Store) lockLocked() {
	zero(s.key)
	s.key = nil
	s.items = nil
}

// Names lists the stored secret names in sorted order. It requires an unlocked
// store because names are part of the encrypted payload.
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

// saveLocked reseals the secret map and persists the envelope. Callers must
// hold s.mu for writing.
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
	if errWrite := writeFileAtomic(s.path, raw); errWrite != nil {
		s.env.Items = previous
		return errWrite
	}
	return nil
}

// writeFileAtomic replaces path with data so a crash mid-write cannot leave a
// truncated store behind.
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
	if e.KDF.Name != kdfName {
		return fmt.Errorf("unsupported kdf %q", e.KDF.Name)
	}
	if e.AEAD != aeadName {
		return fmt.Errorf("unsupported aead %q", e.AEAD)
	}
	if len(e.KDF.Salt) < saltLen {
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
	return nil
}

func newEnvelope() envelope {
	return envelope{
		Version: FormatVersion,
		KDF: kdfParams{
			Name:        kdfName,
			Salt:        randomBytes(saltLen),
			Time:        defaultTime,
			Memory:      defaultMemory,
			Parallelism: defaultParallelism,
			KeyLen:      defaultKeyLen,
		},
		AEAD: aeadName,
	}
}

func deriveKey(passphrase string, params kdfParams) []byte {
	return argon2.IDKey([]byte(passphrase), params.Salt, params.Time, params.Memory, params.Parallelism, params.KeyLen)
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
