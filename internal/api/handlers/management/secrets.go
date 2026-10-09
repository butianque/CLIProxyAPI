package management

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// secretStatusPayload describes the secret store to management clients. Secret
// values are never included; names are only disclosed while the store is
// unlocked, so a locked passphrase store does not leak the set of stored names.
type secretStatusPayload struct {
	Enabled     bool     `json:"enabled"`
	Path        string   `json:"path,omitempty"`
	Initialized bool     `json:"initialized"`
	Unlocked    bool     `json:"unlocked"`
	Passphrase  bool     `json:"passphrase"`
	Mode        string   `json:"mode,omitempty"`
	Names       []string `json:"names"`
}

func secretStatus() secretStatusPayload {
	store := secretstore.Default()
	if store == nil {
		return secretStatusPayload{Names: []string{}}
	}
	payload := secretStatusPayload{
		Enabled:     true,
		Path:        store.Path(),
		Initialized: store.Initialized(),
		Unlocked:    store.Unlocked(),
		Passphrase:  store.HasPassphrase(),
		Mode:        string(store.Mode()),
		Names:       []string{},
	}
	if payload.Unlocked {
		if names, errNames := store.Names(); errNames == nil {
			payload.Names = names
		}
	}
	return payload
}

// GetSecretStatus reports whether the store is enabled, its path, its unlock
// mode and state, whether a master passphrase is installed, and which names
// exist while unlocked.
func (h *Handler) GetSecretStatus(c *gin.Context) {
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretInitialize sets up a brand-new store with a master passphrase. It
// exists so the first setup can be done over HTTP; calling it on an initialized
// store is refused, so an existing policy is never silently replaced.
func (h *Handler) PostSecretInitialize(c *gin.Context) {
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
	if errInit := store.Initialize(req.Passphrase); errInit != nil {
		c.JSON(errStatus(errInit), gin.H{"error": errInit.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretUnlock unlocks the store with the master passphrase.
func (h *Handler) PostSecretUnlock(c *gin.Context) {
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
	if errUnlock := store.Unlock(req.Passphrase); errUnlock != nil {
		c.JSON(errStatus(errUnlock), gin.H{"error": errUnlock.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretMachineUnlock opts the store into machine unlock ("remember on this
// machine"), so a headless deployment does not need the passphrase after each
// restart. The response carries the resulting status, whose mode field states the
// weakened protection explicitly.
func (h *Handler) PostSecretMachineUnlock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	if errEnable := store.EnableMachineUnlock(); errEnable != nil {
		c.JSON(errStatus(errEnable), gin.H{"error": errEnable.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// DeleteSecretMachineUnlock removes the machine key file, restoring passphrase-
// only protection. A store with no passphrase refuses, because dropping its key
// file would make it unrecoverable.
func (h *Handler) DeleteSecretMachineUnlock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	if errDisable := store.DisableMachineUnlock(); errDisable != nil {
		c.JSON(errStatus(errDisable), gin.H{"error": errDisable.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretLock drops the in-memory machine key.
func (h *Handler) PostSecretLock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	store.Lock()
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretPassphrase installs or replaces the master passphrase. Replacing an
// existing one requires the current passphrase, so a request cannot take over a
// store it does not already control.
func (h *Handler) PostSecretPassphrase(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
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
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretVerify checks a candidate master passphrase without changing it.
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

// PutSecret creates or replaces one named secret.
//
// Once a master passphrase is installed, it must be presented here: writing a
// secret is the operator-facing action the passphrase exists to protect. The
// internal host.secret.set callback a plugin uses is deliberately not gated,
// because that is the system acting on its own behalf.
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
	if errGate := gateWrite(store, req.Passphrase); errGate != nil {
		c.JSON(errStatus(errGate), gin.H{"error": errGate.Error()})
		return
	}
	if errSet := store.Set(name, req.Value); errSet != nil {
		c.JSON(errStatus(errSet), gin.H{"error": errSet.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// DeleteSecret removes one named secret, behind the same passphrase gate.
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
	if errGate := gateWrite(store, req.Passphrase); errGate != nil {
		c.JSON(errStatus(errGate), gin.H{"error": errGate.Error()})
		return
	}
	if errDelete := store.Delete(name); errDelete != nil {
		c.JSON(errStatus(errDelete), gin.H{"error": errDelete.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// gateWrite refuses a secret write while the store is locked. Unlocking happens
// once through PostSecretUnlock (with the master passphrase) or on open for a
// machine-unlockable store; the store then stays unlocked until locked again, so
// every subsequent write is not required to carry the passphrase.
func gateWrite(store *secretstore.Store, passphrase string) error {
	if !store.Unlocked() {
		return secretstore.ErrLocked
	}
	// A passphrase may still be supplied per request; when it is, it must be the
	// right one. Omitting it relies on the store already being unlocked.
	if passphrase != "" {
		return store.VerifyPassphrase(passphrase)
	}
	return nil
}

// errStatus maps a secret store error to an HTTP status.
func errStatus(err error) int {
	switch {
	case errors.Is(err, secretstore.ErrInvalidPassphrase), errors.Is(err, secretstore.ErrNoPassphrase):
		return http.StatusUnauthorized
	case errors.Is(err, secretstore.ErrEmptyPassphrase), errors.Is(err, secretstore.ErrEmptyName):
		return http.StatusBadRequest
	case errors.Is(err, secretstore.ErrLocked), errors.Is(err, secretstore.ErrModeConflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
