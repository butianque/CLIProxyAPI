package secretstore

import (
	"errors"
	"time"
)

// ErrUnauthorized reports that the caller holds no grant for this store.
//
// It is deliberately distinct from ErrLocked: ErrLocked means nobody has the
// storage key, ErrUnauthorized means the store is open but not for this caller.
// The two are different situations for the operator, so the API maps them to
// different statuses.
var ErrUnauthorized = errors.New("secret store: no grant for this session")

// SessionGrantTTL is how long a session grant survives without being refreshed.
// The management session owns the authoritative idle clock; this is the store's
// own backstop so a forgotten grant cannot outlive the session that created it.
const SessionGrantTTL = 10 * time.Minute

// sessionGrant records that one management session proved the master
// passphrase.
//
// A grant holds no key material: it only says "this session may use the storage
// key while it is in memory". Revoking the last grant on a store without machine
// unlock drops the key itself (see refreshAfterRevokeLocked).
type sessionGrant struct {
	issued  time.Time
	expires time.Time
}

// expired reports whether the grant's idle deadline has passed. A zero deadline
// never expires.
func (g *sessionGrant) expired(now time.Time) bool {
	if g == nil {
		return true
	}
	if g.expires.IsZero() {
		return false
	}
	return !now.Before(g.expires)
}

// Vault is the store as seen by one management session.
//
// Every method authorizes against that session's grant before touching data, so
// a session that never proved the master passphrase cannot read, write, list or
// delete secrets even while another session has the store open. This is the
// boundary that stops "one session unlocked" from meaning "every client holding
// the management key can read credentials".
type Vault struct {
	store   *Store
	session string
}

// Session identifies the session this vault speaks for.
func (v Vault) Session() string { return v.session }

// Available reports whether the host has a secret store at all. A vault for a
// disabled store is inert: every method fails.
func (v Vault) Available() bool { return v.store != nil }

// Get returns the plaintext value for name.
func (v Vault) Get(name string) (string, error) {
	if v.store == nil {
		return "", ErrLocked
	}
	v.store.mu.RLock()
	defer v.store.mu.RUnlock()
	if errAuth := v.store.authorizeLocked(v.session, time.Now()); errAuth != nil {
		return "", errAuth
	}
	return v.store.getLocked(name)
}

// Set stores value under name, creating or replacing it.
func (v Vault) Set(name, value string) error {
	if v.store == nil {
		return ErrLocked
	}
	v.store.mu.Lock()
	defer v.store.mu.Unlock()
	if errAuth := v.store.authorizeLocked(v.session, time.Now()); errAuth != nil {
		return errAuth
	}
	return v.store.setLocked(name, value)
}

// Delete removes name. Deleting a missing name is not an error.
func (v Vault) Delete(name string) error {
	if v.store == nil {
		return ErrLocked
	}
	v.store.mu.Lock()
	defer v.store.mu.Unlock()
	if errAuth := v.store.authorizeLocked(v.session, time.Now()); errAuth != nil {
		return errAuth
	}
	return v.store.deleteLocked(name)
}

// Names lists the stored secret names in sorted order.
func (v Vault) Names() ([]string, error) {
	if v.store == nil {
		return nil, ErrLocked
	}
	v.store.mu.RLock()
	defer v.store.mu.RUnlock()
	if errAuth := v.store.authorizeLocked(v.session, time.Now()); errAuth != nil {
		return nil, errAuth
	}
	return v.store.namesLocked()
}

// SessionVault returns the vault for one session. The vault stays valid as a
// handle whether or not the session currently holds a grant; each call checks.
func (s *Store) SessionVault(sessionID string) Vault {
	if s == nil {
		return Vault{}
	}
	return Vault{store: s, session: sessionID}
}

// GrantSession authorizes sessionID to read and write secrets and returns its
// vault. The store must already be open: a grant records a successful passphrase
// check, it does not perform one.
func (s *Store) GrantSession(sessionID string, ttl time.Duration) (Vault, error) {
	if s == nil {
		return Vault{}, ErrLocked
	}
	if sessionID == "" {
		return Vault{}, ErrUnauthorized
	}
	if ttl <= 0 {
		ttl = SessionGrantTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return Vault{}, ErrLocked
	}
	now := time.Now()
	if s.sessions == nil {
		s.sessions = make(map[string]*sessionGrant)
	}
	s.sessions[sessionID] = &sessionGrant{issued: now, expires: now.Add(ttl)}
	return Vault{store: s, session: sessionID}, nil
}

// TouchSession extends a live grant's idle deadline. It reports false when the
// session has no live grant, so the caller can ask for the passphrase again.
func (s *Store) TouchSession(sessionID string, ttl time.Duration) bool {
	if s == nil || sessionID == "" {
		return false
	}
	if ttl <= 0 {
		ttl = SessionGrantTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if errAuth := s.authorizeLocked(sessionID, now); errAuth != nil {
		return false
	}
	s.sessions[sessionID].expires = now.Add(ttl)
	return true
}

// SessionUnlocked reports whether this session holds a live grant.
func (s *Store) SessionUnlocked(sessionID string) bool {
	if s == nil || sessionID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authorizeLocked(sessionID, time.Now()) == nil
}

// RevokeSession drops one session's grant and reports whether it had one.
func (s *Store) RevokeSession(sessionID string) bool {
	if s == nil || sessionID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sessionID]; !ok {
		return false
	}
	delete(s.sessions, sessionID)
	s.refreshAfterRevokeLocked()
	return true
}

// RevokeAllSessions drops every session grant and reports how many were live.
// The backend's own access (machine unlock) is not affected.
func (s *Store) RevokeAllSessions() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.sessions)
	s.sessions = nil
	s.refreshAfterRevokeLocked()
	return count
}

// RevokeOtherSessions drops every grant except keep, and reports how many were
// dropped. Keeping one is what lets a passphrase change sign the other sessions
// out without locking the store out from under the caller who made the change.
func (s *Store) RevokeOtherSessions(keep string) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := 0
	for id := range s.sessions {
		if id == keep {
			continue
		}
		delete(s.sessions, id)
		dropped++
	}
	if dropped > 0 {
		s.refreshAfterRevokeLocked()
	}
	return dropped
}

// SweepExpired drops grants whose idle deadline has passed and reports how many
// were dropped. Expiry is also enforced lazily on every authorized call, so this
// only matters for reclaiming memory and for dropping the key promptly.
func (s *Store) SweepExpired(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dropped := 0
	for id, grant := range s.sessions {
		if grant.expired(now) {
			delete(s.sessions, id)
			dropped++
		}
	}
	if dropped > 0 {
		s.refreshAfterRevokeLocked()
	}
	return dropped
}

// LiveSessions reports how many session grants are currently valid. It exists
// for status reporting and tests, never for authorization.
func (s *Store) LiveSessions() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	live := 0
	for _, grant := range s.sessions {
		if !grant.expired(now) {
			live++
		}
	}
	return live
}

// SystemAccess describes how the backend itself reaches the store — what
// plugins, the supply service and startup code rely on:
//
//	"machine" — a machine key opens the store without an operator, so the
//	            backend reads credentials regardless of who is signed in;
//	"session" — no machine key: the backend reads only while some session has
//	            the store open;
//	"none"    — the store is not initialized, so there is nothing to reach.
//
// It describes the backend's own reach, never the caller's, so it cannot be used
// to skip the per-session check.
func (s *Store) SystemAccess() string {
	if s == nil {
		return "none"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Every answer here describes what the process can reach *now*, so it keys
	// off the loaded storage key, not off the configured mode. A machine store
	// whose seal cannot be opened (moved host, reset profile, deleted seal) is
	// configured for unattended access but is waiting for the passphrase; saying
	// "machine" there would promise plugins a capability the process lacks.
	if s.key == nil {
		return "none"
	}
	if s.mode == UnlockMachine || s.mode == UnlockPassphraseMachine {
		return "machine"
	}
	if s.mode == UnlockPassphrase {
		return "session"
	}
	return "none"
}

// authorizeLocked reports whether sessionID may read or write right now.
// Callers must hold s.mu.
func (s *Store) authorizeLocked(sessionID string, now time.Time) error {
	if s.key == nil {
		return ErrLocked
	}
	if sessionID == "" {
		return ErrUnauthorized
	}
	grant, ok := s.sessions[sessionID]
	if !ok || grant.expired(now) {
		return ErrUnauthorized
	}
	return nil
}

// refreshAfterRevokeLocked drops the storage key once nothing holds the store
// open any more.
//
// A machine-unlockable store keeps its key: the backend is a holder in its own
// right, and dropping it would break plugins and the supply service for no
// security gain, since the machine key on disk reopens it anyway.
// Callers must hold s.mu for writing.
func (s *Store) refreshAfterRevokeLocked() {
	if len(s.sessions) > 0 {
		return
	}
	if s.mode == UnlockMachine || s.mode == UnlockPassphraseMachine {
		return
	}
	s.lockLocked()
}
