package management

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// secretStatusPayload describes the secret store to management clients. Secret
// values are never included; names are disclosed only while unlocked.
type secretStatusPayload struct {
	Enabled  bool     `json:"enabled"`
	Path     string   `json:"path,omitempty"`
	Unlocked bool     `json:"unlocked"`
	Names    []string `json:"names"`
}

func secretStatus() secretStatusPayload {
	store := secretstore.Default()
	if store == nil {
		return secretStatusPayload{Names: []string{}}
	}
	payload := secretStatusPayload{Enabled: true, Path: store.Path(), Unlocked: store.Unlocked(), Names: []string{}}
	if names, errNames := store.Names(); errNames == nil {
		payload.Names = names
	}
	return payload
}

// GetSecretStatus reports whether the store is enabled, its path, and which
// secret names exist (only while unlocked).
func (h *Handler) GetSecretStatus(c *gin.Context) {
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretUnlock derives the key from the supplied passphrase and holds it in
// memory. The passphrase is never persisted.
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
		status := http.StatusInternalServerError
		switch {
		case errors.Is(errUnlock, secretstore.ErrInvalidPassphrase):
			status = http.StatusUnauthorized
		case errors.Is(errUnlock, secretstore.ErrEmptyPassphrase):
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error": errUnlock.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// PostSecretLock discards the in-memory key.
func (h *Handler) PostSecretLock(c *gin.Context) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "secret store is disabled"})
		return
	}
	store.Lock()
	c.JSON(http.StatusOK, secretStatus())
}

// PutSecret creates or replaces one named secret.
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
		Value string `json:"value"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if errSet := store.Set(name, req.Value); errSet != nil {
		status := http.StatusInternalServerError
		if errors.Is(errSet, secretstore.ErrLocked) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": errSet.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}

// DeleteSecret removes one named secret.
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
	if errDelete := store.Delete(name); errDelete != nil {
		status := http.StatusInternalServerError
		if errors.Is(errDelete, secretstore.ErrLocked) {
			status = http.StatusConflict
		}
		c.JSON(status, gin.H{"error": errDelete.Error()})
		return
	}
	c.JSON(http.StatusOK, secretStatus())
}
