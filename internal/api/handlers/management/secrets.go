package management

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// secretStatusPayload describes the secret store to management clients. Secret
// values are never included; names are disclosed plainly because the store is
// machine-protected.
type secretStatusPayload struct {
	Enabled    bool     `json:"enabled"`
	Path       string   `json:"path,omitempty"`
	Unlocked   bool     `json:"unlocked"`
	Passphrase bool     `json:"passphrase"`
	Names      []string `json:"names"`
}

func secretStatus() secretStatusPayload {
	store := secretstore.Default()
	if store == nil {
		return secretStatusPayload{Names: []string{}}
	}
	payload := secretStatusPayload{
		Enabled:    true,
		Path:       store.Path(),
		Unlocked:   store.Unlocked(),
		Passphrase: store.HasPassphrase(),
		Names:      []string{},
	}
	if names, errNames := store.Names(); errNames == nil {
		payload.Names = names
	}
	return payload
}

// GetSecretStatus reports whether the store is enabled, its path, whether it is
// usable, whether a master passphrase is installed, and which names exist.
func (h *Handler) GetSecretStatus(c *gin.Context) {
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretUnlock re-reads the machine key file so a store that opened without
// it can recover. It takes no passphrase: unlocking is a machine operation.
func (h *Handler) PostSecretUnlock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	if errUnlock := store.Unlock(); errUnlock != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": errUnlock.Error()})
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

// gateWrite enforces the master passphrase once one is installed. Before that
// the store has nothing to protect, so the first write is allowed: that is how
// an operator stores the initial credential and then creates the passphrase.
func gateWrite(store *secretstore.Store, passphrase string) error {
	if !store.HasPassphrase() {
		return nil
	}
	return store.VerifyPassphrase(passphrase)
}

// errStatus maps a secret store error to an HTTP status.
func errStatus(err error) int {
	switch {
	case errors.Is(err, secretstore.ErrInvalidPassphrase), errors.Is(err, secretstore.ErrNoPassphrase):
		return http.StatusUnauthorized
	case errors.Is(err, secretstore.ErrEmptyPassphrase):
		return http.StatusBadRequest
	case errors.Is(err, secretstore.ErrLocked):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
