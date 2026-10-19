package management

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// secretStatusPayload describes the secret store to one management session.
//
// Two different questions are answered here and they are deliberately separate:
//
//   - "unlocked" is about the caller — has this session proved the master
//     passphrase? Secrets are readable only when it is true.
//   - "system_access" is about the backend — can the process reach credentials on
//     its own, without an operator? Plugins and the supply service depend on it.
//
// Secret values are never included. Names are disclosed only while the calling
// session is unlocked, so a locked session does not learn which credentials exist.
type secretStatusPayload struct {
	Enabled      bool     `json:"enabled"`
	Path         string   `json:"path,omitempty"`
	Initialized  bool     `json:"initialized"`
	Unlocked     bool     `json:"unlocked"`
	SystemAccess string   `json:"system_access"`
	Seal         string   `json:"seal,omitempty"`
	Passphrase   bool     `json:"passphrase"`
	Mode         string   `json:"mode,omitempty"`
	Names        []string `json:"names"`
}

func secretStatus(c *gin.Context) secretStatusPayload {
	store := secretstore.Default()
	if store == nil {
		return secretStatusPayload{SystemAccess: "none", Names: []string{}}
	}
	session := sessionID(c)
	payload := secretStatusPayload{
		Enabled:      true,
		Path:         store.Path(),
		Initialized:  store.Initialized(),
		Unlocked:     store.SessionUnlocked(session),
		SystemAccess: store.SystemAccess(),
		Seal:         store.SealMedium(),
		Passphrase:   store.HasPassphrase(),
		Mode:         string(store.Mode()),
		Names:        []string{},
	}
	if payload.Unlocked {
		if names, errNames := store.SessionVault(session).Names(); errNames == nil {
			payload.Names = names
		}
	}
	return payload
}

// GetSecretStatus reports the store to the calling session.
func (h *Handler) GetSecretStatus(c *gin.Context) {
	c.JSON(http.StatusOK, secretStatus(c))
}

// PostSecretInitialize sets up a brand-new store with a master passphrase and
// authorizes the calling session. Calling it on an initialized store is refused,
// so an existing policy is never silently replaced.
func (h *Handler) PostSecretInitialize(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	session, okSession := requireSession(c)
	if !okSession {
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if errInit := store.Initialize(req.Passphrase); errInit != nil {
		c.JSON(errStatus(errInit), gin.H{"error": errInit.Error()})
		return
	}
	if _, errGrant := store.GrantSession(session.id, sessionIdleTTL()); errGrant != nil {
		c.JSON(errStatus(errGrant), gin.H{"error": errGrant.Error()})
		return
	}
	reloadSupply()
	c.JSON(http.StatusOK, secretStatus(c))
}

// PostSecretUnlock verifies the master passphrase and authorizes the calling
// session. Other sessions are not affected: each one has to prove the passphrase
// for itself.
func (h *Handler) PostSecretUnlock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	session, okSession := requireSession(c)
	if !okSession {
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if errUnlock := store.Unlock(req.Passphrase); errUnlock != nil {
		c.JSON(errStatus(errUnlock), gin.H{"error": errUnlock.Error()})
		return
	}
	if _, errGrant := store.GrantSession(session.id, sessionIdleTTL()); errGrant != nil {
		c.JSON(errStatus(errGrant), gin.H{"error": errGrant.Error()})
		return
	}
	// The supply service is built from credentials that only become readable now
	// that the store is open, so rebuild it before reporting.
	reloadSupply()
	c.JSON(http.StatusOK, secretStatus(c))
}

// PostSecretMachineUnlock opts the store into machine unlock ("the backend can
// reach credentials without an operator"). The response carries the resulting
// status, whose mode field states the weakened protection explicitly.
//
// It is a credential operation, not a setting: turning it on makes every stored
// secret readable without a master passphrase. So it needs the calling session to
// have already proved the passphrase, exactly like a credential write — otherwise a
// client holding only the management key could switch it on while an operator has
// the panel open, and keep that access afterwards.
func (h *Handler) PostSecretMachineUnlock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	if errGate := gateWrite(c, store, ""); errGate != nil {
		c.JSON(errStatus(errGate), gin.H{"error": errGate.Error()})
		return
	}
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		c.JSON(errStatus(errEnable), gin.H{"error": errEnable.Error()})
		return
	}
	reloadSupply()
	c.JSON(http.StatusOK, secretStatus(c))
}

// DeleteSecretMachineUnlock removes the machine key, so the backend can no longer
// reach credentials on its own. A store with no passphrase refuses, because
// dropping its key would make it unrecoverable.
func (h *Handler) DeleteSecretMachineUnlock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	if errGate := gateWrite(c, store, ""); errGate != nil {
		c.JSON(errStatus(errGate), gin.H{"error": errGate.Error()})
		return
	}
	if errDisable := store.DisableMachineUnlock(); errDisable != nil {
		c.JSON(errStatus(errDisable), gin.H{"error": errDisable.Error()})
		return
	}
	reloadSupply()
	c.JSON(http.StatusOK, secretStatus(c))
}

// PostSecretLock ends the calling session's access to credentials. Other sessions
// keep theirs — locking is a per-session action now, not a global one. On a
// passphrase-only store, losing the last session drops the storage key itself.
func (h *Handler) PostSecretLock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	revokeSessionGrant(sessionID(c))
	c.JSON(http.StatusOK, secretStatus(c))
}

// PostSecretPassphrase installs or replaces the master passphrase.
//
// Replacing one requires the current passphrase, so a request cannot take over a
// store it does not already control. Every other session is signed out of the
// credentials: their grant was obtained with the old passphrase, and a credential
// change must not be inherited. The calling session stays unlocked.
func (h *Handler) PostSecretPassphrase(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	session, okSession := requireSession(c)
	if !okSession {
		return
	}
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if errSet := store.SetPassphrase(req.Current, req.Next); errSet != nil {
		c.JSON(errStatus(errSet), gin.H{"error": errSet.Error()})
		return
	}
	// Every other session proved the old passphrase, so its grant does not
	// survive the change. This one does: the operator who just changed the
	// passphrase must not be signed out of the credentials they are looking at.
	store.RevokeOtherSessions(session.id)
	c.JSON(http.StatusOK, secretStatus(c))
}

// PostSecretVerify checks a candidate master passphrase without authorizing the
// session.
func (h *Handler) PostSecretVerify(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if errVerify := store.VerifyPassphrase(req.Passphrase); errVerify != nil {
		c.JSON(errStatus(errVerify), gin.H{"error": errVerify.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": true})
}

// PutSecret creates or replaces one named secret for the calling session.
//
// The session must be unlocked. A passphrase supplied per request is still
// honoured, because older callers send one; it must be correct when present. New
// callers can rely on the session grant alone.
func (h *Handler) PutSecret(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "secret name is required"})
		return
	}
	var req struct {
		Value      string `json:"value"`
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if errGate := gateWrite(c, store, req.Passphrase); errGate != nil {
		c.JSON(errStatus(errGate), gin.H{"error": errGate.Error()})
		return
	}
	if errSet := store.SessionVault(sessionID(c)).Set(name, req.Value); errSet != nil {
		c.JSON(errStatus(errSet), gin.H{"error": errSet.Error()})
		return
	}
	// A written credential may be the one the supply service needs, so rebuild.
	reloadSupply()
	c.JSON(http.StatusOK, secretStatus(c))
}

// DeleteSecret removes one named secret, behind the same gate.
func (h *Handler) DeleteSecret(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "secret name is required"})
		return
	}
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	_ = c.ShouldBindJSON(&req)
	if errGate := gateWrite(c, store, req.Passphrase); errGate != nil {
		c.JSON(errStatus(errGate), gin.H{"error": errGate.Error()})
		return
	}
	if errDelete := store.SessionVault(sessionID(c)).Delete(name); errDelete != nil {
		c.JSON(errStatus(errDelete), gin.H{"error": errDelete.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus(c))
}

// gateWrite refuses a secret write unless the calling session is unlocked. A
// passphrase supplied per request must also be correct, except on a store that has
// none at all.
func gateWrite(c *gin.Context, store *secretstore.Store, passphrase string) error {
	session := sessionID(c)
	if !store.SessionUnlocked(session) {
		if store.Unlocked() {
			// The store is open for someone else: this session simply has not
			// proved the passphrase.
			return secretstore.ErrUnauthorized
		}
		return secretstore.ErrLocked
	}
	if passphrase == "" || !store.HasPassphrase() {
		return nil
	}
	return store.VerifyPassphrase(passphrase)
}

// errStatus maps a secret store error to an HTTP status.
func errStatus(err error) int {
	switch {
	case errors.Is(err, secretstore.ErrInvalidPassphrase), errors.Is(err, secretstore.ErrNoPassphrase):
		return http.StatusUnauthorized
	case errors.Is(err, secretstore.ErrEmptyPassphrase), errors.Is(err, secretstore.ErrEmptyName):
		return http.StatusBadRequest
	case errors.Is(err, secretstore.ErrLocked), errors.Is(err, secretstore.ErrModeConflict),
		errors.Is(err, secretstore.ErrUnauthorized):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
