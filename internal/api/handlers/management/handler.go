// Package management provides the management API handlers and middleware
// for configuring the server and managing auth files.
package management

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginstore"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type attemptInfo struct {
	count        int
	blockedUntil time.Time
	lastActivity time.Time // track last activity for cleanup
}

// attemptCleanupInterval controls how often stale IP entries are purged
const attemptCleanupInterval = 1 * time.Hour

// attemptMaxIdleTime controls how long an IP can be idle before cleanup
const attemptMaxIdleTime = 2 * time.Hour

// Handler aggregates config reference, persistence path and helpers.
type Handler struct {
	cfg                     *config.Config
	configFilePath          string
	mu                      sync.Mutex
	authStatusMu            sync.Mutex
	reloadMu                sync.Mutex
	reloadGeneration        uint64
	appliedReloadGeneration uint64
	attemptsMu              sync.Mutex
	failedAttempts          map[string]*attemptInfo // keyed by client IP
	sessionsOnce            sync.Once
	sessions                *sessionRegistry
	authManager             *coreauth.Manager
	tokenStore              coreauth.Store
	localPassword           string
	allowRemoteOverride     bool
	envSecret               string
	logDir                  string
	postAuthHook            coreauth.PostAuthHook
	postAuthPersistHook     coreauth.PostAuthHook
	pluginHost              *pluginhost.Host
	configReloadHook        func(context.Context, *config.Config)
	pluginStoreRegistryURL  string
	pluginStoreHTTPClient   pluginstore.HTTPDoer
	pluginStoreRateLimiter  *pluginstore.GitHubRateLimiter
	pluginReleases          pluginReleaseCache
}

type configReloadSnapshot struct {
	cfg        *config.Config
	generation uint64
}

// NewHandler creates a new management handler instance.
func NewHandler(cfg *config.Config, configFilePath string, manager *coreauth.Manager) *Handler {
	envSecret, _ := os.LookupEnv("MANAGEMENT_PASSWORD")
	envSecret = strings.TrimSpace(envSecret)

	h := &Handler{
		cfg:                 cfg,
		configFilePath:      configFilePath,
		failedAttempts:      make(map[string]*attemptInfo),
		authManager:         manager,
		tokenStore:          sdkAuth.GetTokenStore(),
		allowRemoteOverride: envSecret != "",
		envSecret:           envSecret,
	}
	h.startAttemptCleanup()
	return h
}

// startAttemptCleanup launches a background goroutine that periodically
// removes stale IP entries from failedAttempts to prevent memory leaks.
func (h *Handler) startAttemptCleanup() {
	go func() {
		ticker := time.NewTicker(attemptCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			h.purgeStaleAttempts()
		}
	}()
}

// purgeStaleAttempts removes IP entries that have been idle beyond attemptMaxIdleTime
// and whose ban (if any) has expired.
func (h *Handler) purgeStaleAttempts() {
	now := time.Now()
	h.attemptsMu.Lock()
	defer h.attemptsMu.Unlock()
	for ip, ai := range h.failedAttempts {
		// Skip if still banned
		if !ai.blockedUntil.IsZero() && now.Before(ai.blockedUntil) {
			continue
		}
		// Remove if idle too long
		if now.Sub(ai.lastActivity) > attemptMaxIdleTime {
			delete(h.failedAttempts, ip)
		}
	}
}

// NewHandler creates a new management handler instance.
func NewHandlerWithoutConfigFilePath(cfg *config.Config, manager *coreauth.Manager) *Handler {
	return NewHandler(cfg, "", manager)
}

// SetConfig updates the in-memory config reference when the server hot-reloads.
func (h *Handler) SetConfig(cfg *config.Config) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.cfg = cfg
	h.mu.Unlock()
}

// SetAuthManager updates the auth manager reference used by management endpoints.
func (h *Handler) SetAuthManager(manager *coreauth.Manager) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.authManager = manager
	h.mu.Unlock()
}

// SetPluginHost updates the plugin host used by plugin-backed management endpoints.
func (h *Handler) SetPluginHost(host *pluginhost.Host) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.pluginHost = host
	h.mu.Unlock()
}

// SetConfigReloadHook updates the callback used after management saves config changes.
func (h *Handler) SetConfigReloadHook(hook func(context.Context, *config.Config)) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.configReloadHook = hook
	h.mu.Unlock()
}

// reloadSnapshotConfigLocked clones the runtime config and assigns a reload generation.
// Callers must hold h.mu.
func (h *Handler) reloadSnapshotConfigLocked() configReloadSnapshot {
	if h == nil || h.cfg == nil {
		return configReloadSnapshot{}
	}
	h.reloadGeneration++
	return configReloadSnapshot{
		cfg:        h.cfg.CloneForRuntime(),
		generation: h.reloadGeneration,
	}
}

// saveConfigAndSnapshotLocked saves h.cfg and returns a full runtime config snapshot.
// Callers must hold h.mu.
func (h *Handler) saveConfigAndSnapshotLocked(c *gin.Context) (configReloadSnapshot, bool) {
	if errSave := config.SaveConfigPreserveComments(h.configFilePath, h.cfg, c.GetBool(ConfigV8ContextKey)); errSave != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save config: %v", errSave)})
		return configReloadSnapshot{}, false
	}
	return h.reloadSnapshotConfigLocked(), true
}

// reloadConfigAfterManagementSave reloads from an independent config snapshot.
// Callers must pass a full Config clone captured immediately after a successful save.
func (h *Handler) reloadConfigAfterManagementSave(ctx context.Context, snapshot configReloadSnapshot) {
	if h == nil || snapshot.cfg == nil || snapshot.generation == 0 {
		return
	}
	h.reloadMu.Lock()
	defer h.reloadMu.Unlock()

	h.mu.Lock()
	if snapshot.generation < h.appliedReloadGeneration {
		h.mu.Unlock()
		return
	}
	hook := h.configReloadHook
	host := h.pluginHost
	h.mu.Unlock()
	if hook != nil {
		hook(ctx, snapshot.cfg)
	} else if host != nil {
		host.ApplyConfig(ctx, snapshot.cfg)
	}

	h.mu.Lock()
	if snapshot.generation > h.appliedReloadGeneration {
		h.appliedReloadGeneration = snapshot.generation
	}
	h.mu.Unlock()
}

// reloadConfigAfterManagementSaveAsync reloads from an independent config snapshot.
// Callers must pass a full Config clone captured immediately after a successful save.
func (h *Handler) reloadConfigAfterManagementSaveAsync(ctx context.Context, snapshot configReloadSnapshot) {
	if h == nil || snapshot.cfg == nil || snapshot.generation == 0 {
		return
	}
	reloadCtx := context.Background()
	if ctx != nil {
		reloadCtx = context.WithoutCancel(ctx)
	}
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.WithField("panic", recovered).Error("management: async config reload panicked")
			}
		}()
		h.reloadConfigAfterManagementSave(reloadCtx, snapshot)
	}()
}

// SetLocalPassword configures the runtime-local password accepted for localhost requests.
func (h *Handler) SetLocalPassword(password string) { h.localPassword = password }

// SetLogDirectory updates the directory where main.log should be looked up.
func (h *Handler) SetLogDirectory(dir string) {
	if dir == "" {
		return
	}
	if !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	h.logDir = dir
}

// SetPostAuthHook registers a hook to be called after auth record creation but before persistence.
func (h *Handler) SetPostAuthHook(hook coreauth.PostAuthHook) {
	h.postAuthHook = hook
}

// SetPostAuthPersistHook registers a hook to be called after auth persistence.
func (h *Handler) SetPostAuthPersistHook(hook coreauth.PostAuthHook) {
	h.postAuthPersistHook = hook
}

// Middleware enforces access control for management endpoints.
//
// A request authenticates either with the management key (Authorization: Bearer
// or X-Management-Key) or with the session cookie the key issued earlier. Remote
// access requires allow-remote-management=true on both paths.
func (h *Handler) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-CPA-VERSION", buildinfo.Version)
		c.Header("X-CPA-COMMIT", buildinfo.Commit)
		c.Header("X-CPA-BUILD-DATE", buildinfo.BuildDate)
		c.Header("X-CPA-SUPPORT-PLUGIN", pluginhost.SupportPluginHeaderValue())

		clientIP := c.ClientIP()
		localClient := clientIP == "127.0.0.1" || clientIP == "::1"

		// Accept either Authorization: Bearer <key> or X-Management-Key
		var provided string
		if ah := c.GetHeader("Authorization"); ah != "" {
			parts := strings.SplitN(ah, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				provided = parts[1]
			} else {
				provided = ah
			}
		}
		if provided == "" {
			provided = c.GetHeader("X-Management-Key")
		}

		// A browser does not have to present the key on every request: after the
		// first sign-in it holds a session cookie instead. The cookie is only ever
		// issued by a key-authenticated request, it is HttpOnly, SameSite=Strict,
		// scoped to the management API, and bound to the address that created it.
		//
		// This is checked before the key path so that a browser which simply has no
		// key (every reload) is not counted as a failed attempt: absence of a
		// credential is not a guess, and counting it would let any unauthenticated
		// visitor lock the operator's IP out of the panel.
		if provided == "" {
			if token := sessionCookieToken(c); token != "" {
				if !cookieRequestAllowed(c) {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "missing " + sessionCSRFHeader + " header"})
					return
				}
				if !localClient && !h.remoteManagementAllowed() {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "remote management disabled"})
					return
				}
				session, errLookup := h.ensureSessions().lookup(token, clientIP)
				if errLookup != nil {
					clearSessionCookie(c)
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "management session expired"})
					return
				}
				c.Set(sessionContextKey, session)
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing management key"})
			return
		}

		// An automation key is a second, narrower credential: it authenticates
		// exactly like the management key but only reaches the routes the
		// operator listed. It is checked first so a script's request costs one
		// bcrypt comparison rather than two.
		if h.automationKeyMatch(clientIP, localClient, provided) {
			route := c.FullPath()
			if !automationRouteAllowed(c.Request.Method, route, h.automationAllow()) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "this automation key may not call " + c.Request.Method + " " + route})
				return
			}
			c.Next()
			return
		}

		allowed, statusCode, errMsg := h.AuthenticateManagementKey(clientIP, localClient, provided)
		if !allowed {
			c.AbortWithStatusJSON(statusCode, gin.H{"error": errMsg})
			return
		}
		c.Next()
	}
}

// automationKeyMatch reports whether provided is the configured automation key.
//
// It applies the same remote gate as AuthenticateManagementKey, so a narrow key
// cannot be used from an address the operator has closed, and it clears the
// failure counter on a match for the same reason the full key does. A request
// that fails here falls through to the full-key path, which owns the ban and the
// failure counting.
func (h *Handler) automationKeyMatch(clientIP string, localClient bool, provided string) bool {
	if h == nil || h.cfg == nil || provided == "" {
		return false
	}
	hash := h.cfg.RemoteManagement.AutomationKey
	if hash == "" {
		return false
	}
	if !localClient && !h.remoteManagementAllowed() {
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(provided)) != nil {
		return false
	}
	h.attemptsMu.Lock()
	if ai := h.failedAttempts[clientIP]; ai != nil {
		ai.count = 0
		ai.blockedUntil = time.Time{}
	}
	h.attemptsMu.Unlock()
	return true
}

// automationAllow returns the routes an automation key may call.
func (h *Handler) automationAllow() []string {
	if h == nil || h.cfg == nil {
		return nil
	}
	if len(h.cfg.RemoteManagement.AutomationAllow) == 0 {
		return config.DefaultAutomationAllow
	}
	return h.cfg.RemoteManagement.AutomationAllow
}

// automationRouteAllowed reports whether one call is covered by an allow list.
//
// An entry is "METHOD /route" matched exactly, or "METHOD /route/prefix*" matched
// as a prefix. The route is the registered pattern rather than the raw URL, so a
// doubled slash or an encoded segment cannot walk past a prefix entry. Both
// halves must match: a route is never opened to a method the entry did not name.
func automationRouteAllowed(method, route string, allow []string) bool {
	call := method + " " + route
	for _, entry := range allow {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, isPrefix := strings.CutSuffix(entry, "*"); isPrefix {
			if strings.HasPrefix(call, prefix) {
				return true
			}
			continue
		}
		if call == entry {
			return true
		}
	}
	return false
}

// remoteManagementAllowed reports whether clients outside the loopback interface
// may use the management API at all. The session cookie path has to ask this
// separately: a cookie outlives the config change that turned remote access off.
func (h *Handler) remoteManagementAllowed() bool {
	if h == nil {
		return false
	}
	if h.allowRemoteOverride {
		return true
	}
	return h.cfg != nil && h.cfg.RemoteManagement.AllowRemote
}

// AuthenticateManagementKey verifies the provided management key for the given client.
// It mirrors the behaviour of Middleware() so non-HTTP callers can reuse the same logic.
func (h *Handler) AuthenticateManagementKey(clientIP string, localClient bool, provided string) (bool, int, string) {
	const maxFailures = 5
	const banDuration = 30 * time.Minute

	if h == nil {
		return false, http.StatusForbidden, "remote management disabled"
	}

	cfg := h.cfg
	var (
		allowRemote bool
		secretHash  string
	)
	if cfg != nil {
		allowRemote = cfg.RemoteManagement.AllowRemote
		secretHash = cfg.RemoteManagement.SecretKey
	}
	if h.allowRemoteOverride {
		allowRemote = true
	}
	envSecret := h.envSecret

	now := time.Now()
	h.attemptsMu.Lock()
	ai := h.failedAttempts[clientIP]
	if ai != nil && !ai.blockedUntil.IsZero() {
		if now.Before(ai.blockedUntil) {
			remaining := ai.blockedUntil.Sub(now).Round(time.Second)
			h.attemptsMu.Unlock()
			return false, http.StatusForbidden, fmt.Sprintf("IP banned due to too many failed attempts. Try again in %s", remaining)
		}
		// Ban expired, reset state
		ai.blockedUntil = time.Time{}
		ai.count = 0
	}
	h.attemptsMu.Unlock()

	if !localClient && !allowRemote {
		return false, http.StatusForbidden, "remote management disabled"
	}

	fail := func() {
		h.attemptsMu.Lock()
		aip := h.failedAttempts[clientIP]
		if aip == nil {
			aip = &attemptInfo{}
			h.failedAttempts[clientIP] = aip
		}
		aip.count++
		aip.lastActivity = time.Now()
		if aip.count >= maxFailures {
			aip.blockedUntil = time.Now().Add(banDuration)
			aip.count = 0
		}
		h.attemptsMu.Unlock()
	}

	reset := func() {
		h.attemptsMu.Lock()
		if ai := h.failedAttempts[clientIP]; ai != nil {
			ai.count = 0
			ai.blockedUntil = time.Time{}
		}
		h.attemptsMu.Unlock()
	}

	if secretHash == "" && envSecret == "" {
		return false, http.StatusForbidden, "remote management key not set"
	}

	if provided == "" {
		fail()
		return false, http.StatusUnauthorized, "missing management key"
	}

	if localClient {
		if lp := h.localPassword; lp != "" {
			if subtle.ConstantTimeCompare([]byte(provided), []byte(lp)) == 1 {
				reset()
				return true, 0, ""
			}
		}
	}

	if envSecret != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(envSecret)) == 1 {
		reset()
		return true, 0, ""
	}

	if secretHash == "" || bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(provided)) != nil {
		fail()
		return false, http.StatusUnauthorized, "invalid management key"
	}

	reset()

	return true, 0, ""
}

// persist saves the current in-memory config to disk.
func (h *Handler) persist(c *gin.Context) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.persistLocked(c)
}

// persistLocked saves the current in-memory config to disk.
// It expects the caller to hold h.mu.
func (h *Handler) persistLocked(c *gin.Context) bool {
	// Preserve comments when writing
	if err := config.SaveConfigPreserveComments(h.configFilePath, h.cfg, c.GetBool(ConfigV8ContextKey)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save config: %v", err)})
		return false
	}
	snapshot := h.reloadSnapshotConfigLocked()
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
	var reqCtx context.Context
	if c != nil && c.Request != nil {
		reqCtx = c.Request.Context()
	}
	h.reloadConfigAfterManagementSaveAsync(reqCtx, snapshot)
	return true
}

// Helper methods for simple types
func (h *Handler) updateBoolField(c *gin.Context, set func(bool)) {
	var body struct {
		Value *bool `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	set(*body.Value)
	h.persist(c)
}

func (h *Handler) updateIntField(c *gin.Context, set func(int)) {
	var body struct {
		Value *int `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	set(*body.Value)
	h.persist(c)
}

func (h *Handler) updateStringField(c *gin.Context, set func(string)) {
	var body struct {
		Value *string `json:"value"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	set(*body.Value)
	h.persist(c)
}
