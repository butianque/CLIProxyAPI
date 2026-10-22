package management

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// Management sessions.
//
// The management key proves who the operator is; it is a static secret that never
// expires and cannot be revoked, so it is not a session. A session is the
// short-lived thing an operator actually holds: it starts when the panel signs in,
// it slides on real user activity, and it dies on its own.
//
// Two clocks bound it:
//
//   - an idle limit (10 minutes by default) that only a real user action resets —
//     background polling must not keep a session alive, or the timeout would never
//     fire;
//   - an absolute limit (12 hours) that nothing resets, so a session cannot be
//     kept alive indefinitely by a script that keeps touching it.
//
// Ending a session revokes that session's secret-store grant. It does not affect
// any other session, and it does not affect the backend's own access.
const (
	// sessionHeaderName is the header the panel presents on every request. It is
	// deliberately not the management key: the key authenticates the operator, the
	// token identifies which session is asking.
	sessionHeaderName = "X-CPA-Session"
	// sessionContextKey is where the resolved session is stored on the gin context.
	sessionContextKey = "cpa.management.session"

	// sessionCookieName is the browser's credential. It is HttpOnly and scoped to
	// the management API, so a page reload, a second tab, or a reopened window
	// reaches the same session without asking for the management key again — which
	// is what a browser is supposed to do, and what the key alone could never do
	// (the key is not persisted by default, and storing it in JavaScript-reachable
	// storage is worse than an HttpOnly cookie).
	sessionCookieName = "cpa_management_session"
	// sessionCookiePath is the only path prefix that ever sees this cookie. Every
	// management route lives under it.
	sessionCookiePath = "/v8/management"

	// sessionCSRFHeader must accompany a request that authenticates with the
	// cookie. SameSite=Strict already stops cross-site requests from carrying the
	// cookie, but "site" is the registrable domain: a sibling host such as
	// api.example.com could still post to cpa.example.com. A plain HTML form
	// cannot set a custom header, so requiring one closes that gap.
	sessionCSRFHeader      = "X-CPA-Panel"
	sessionCSRFHeaderValue = "1"

	// defaultSessionIdleTTL is the credential-unlock window: how long an unlocked
	// secret store stays unlocked without a real user action. It is short because it
	// bounds standing access to upstream credentials.
	defaultSessionIdleTTL     = 10 * time.Minute
	defaultSessionAbsoluteTTL = 12 * time.Hour
	// defaultPanelIdleTTL is the browser-session window: how long a signed-in
	// browser may go without a request and still be recognised. It is deliberately
	// much longer than the unlock window — being signed in to the panel and having
	// the credential store open are different privileges, and conflating them is
	// what made a page reload look like a fresh login.
	defaultPanelIdleTTL = 12 * time.Hour
	// sessionSweepInterval bounds how late an expired session is noticed. Liveness
	// is enforced on every request anyway; the sweeper exists so an abandoned
	// session's grant (and, on a passphrase store, the storage key) is dropped
	// promptly rather than at the next request.
	sessionSweepInterval = 30 * time.Second
)

var (
	errSessionMissing = errors.New("a management session is required for this operation")
	errSessionExpired = errors.New("management session expired")
)

// managementSession is one signed-in browser.
type managementSession struct {
	id       string
	clientIP string
	created  time.Time
	lastSeen time.Time
	// lastAuth is the last request that authenticated with this session, which is
	// what keeps the browser signed in. lastSeen is the last real user action,
	// which is what keeps the credential store unlocked.
	lastAuth time.Time
	// persistent mirrors the cookie the browser asked for, so a re-issue does not
	// turn "remember this device" into "until the browser closes".
	persistent bool
}

// expiredForPanel reports whether the browser is no longer recognised. Only the
// panel clock and the absolute cap apply: polling must not extend a session, but
// neither should a quiet afternoon end it.
func (s *managementSession) expiredForPanel(now time.Time, idle, absolute time.Duration) bool {
	if idle > 0 && now.Sub(s.lastAuth) > idle {
		return true
	}
	return absolute > 0 && now.Sub(s.created) > absolute
}

// sessionRegistry holds the live sessions, keyed by their opaque token.
type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*managementSession
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{sessions: make(map[string]*managementSession)}
}

// sessionIdleTTL resolves the idle limit. CPA_SESSION_IDLE_MINUTES overrides it;
// zero or a negative value disables the idle clock.
func sessionIdleTTL() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("CPA_SESSION_IDLE_MINUTES")); raw != "" {
		if minutes, errAtoi := strconv.Atoi(raw); errAtoi == nil {
			return time.Duration(minutes) * time.Minute
		}
	}
	return defaultSessionIdleTTL
}

// panelIdleTTL resolves the browser-session window. CPA_PANEL_IDLE_MINUTES
// overrides it; zero or a negative value falls back to the default.
func panelIdleTTL() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("CPA_PANEL_IDLE_MINUTES")); raw != "" {
		if minutes, errAtoi := strconv.Atoi(raw); errAtoi == nil {
			if minutes <= 0 {
				return 0
			}
			return time.Duration(minutes) * time.Minute
		}
	}
	return defaultPanelIdleTTL
}

// sessionAbsoluteTTL resolves the absolute limit. CPA_SESSION_ABSOLUTE_HOURS
// overrides it; zero or a negative value disables the cap.
func sessionAbsoluteTTL() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("CPA_SESSION_ABSOLUTE_HOURS")); raw != "" {
		if hours, errAtoi := strconv.Atoi(raw); errAtoi == nil {
			return time.Duration(hours) * time.Hour
		}
	}
	return defaultSessionAbsoluteTTL
}

// sessionBindsIP reports whether a session is pinned to the address that created
// it. On by default: a token copied to another host is useless. CPA_SESSION_BIND_IP=0
// turns it off for deployments behind a rotating proxy.
func sessionBindsIP() bool {
	raw := strings.TrimSpace(os.Getenv("CPA_SESSION_BIND_IP"))
	if raw == "" {
		return true
	}
	switch strings.ToLower(raw) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// sessionToken returns the caller's session token. The header wins: it is what
// non-browser clients and older panels send. The cookie is what a browser sends
// on its own after the first sign-in.
func sessionToken(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if token := strings.TrimSpace(c.GetHeader(sessionHeaderName)); token != "" {
		return token
	}
	return sessionCookieToken(c)
}

// sessionCookieToken returns only the cookie's token.
//
// Management authentication uses this and not sessionToken: the cookie is
// HttpOnly, so a script running in the panel's own origin cannot read it and
// replay it elsewhere. The header token stays available for session resolution
// (secret operations), where it is already the panel's own credential.
func sessionCookieToken(c *gin.Context) string {
	if c == nil {
		return ""
	}
	cookie, errCookie := c.Cookie(sessionCookieName)
	if errCookie != nil {
		return ""
	}
	return strings.TrimSpace(cookie)
}

// sessionCookieSecure reports whether the cookie must carry the Secure flag. The
// panel is reached over TLS at the edge, so behind the proxy the scheme arrives in
// X-Forwarded-Proto rather than on the request itself.
func sessionCookieSecure(c *gin.Context) bool {
	if c == nil {
		return true
	}
	if c.Request != nil && c.Request.TLS != nil {
		// A non-nil TLS state does not mean TLS. net/http fills Request.TLS from
		// any connection that reports a ConnectionState, and this server's
		// buffered connection wrapper reports a zero one for plain TCP. Only a
		// completed handshake counts, otherwise every plain-HTTP deployment would
		// get a Secure cookie the browser then drops.
		if state := c.Request.TLS; state.HandshakeComplete || state.Version != 0 {
			return true
		}
	}
	return strings.EqualFold(strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")), "https")
}

// writeSessionCookie hands the browser its session token.
//
// persistent decides whether the cookie outlives the browser process. The default
// is a session cookie: the panel keeps working across reloads, tabs and windows,
// and a fresh browser start signs in again.
func writeSessionCookie(c *gin.Context, token string, persistent bool) {
	if c == nil || token == "" || c.Writer == nil {
		return
	}
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     sessionCookiePath,
		HttpOnly: true,
		Secure:   sessionCookieSecure(c),
		SameSite: http.SameSiteStrictMode,
	}
	if persistent {
		if lifetime := sessionAbsoluteTTL(); lifetime > 0 {
			cookie.MaxAge = int(lifetime / time.Second)
			cookie.Expires = time.Now().Add(lifetime)
		}
	}
	http.SetCookie(c.Writer, cookie)
}

// clearSessionCookie drops the browser's session token.
func clearSessionCookie(c *gin.Context) {
	if c == nil || c.Writer == nil {
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     sessionCookiePath,
		HttpOnly: true,
		Secure:   sessionCookieSecure(c),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

// cookieRequestAllowed reports whether a request that authenticates with the
// session cookie carries the CSRF header. A token sent in the session header is
// already immune to form-based cross-site requests, so it does not need this.
func cookieRequestAllowed(c *gin.Context) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.GetHeader(sessionCSRFHeader)) == sessionCSRFHeaderValue
}

// newSessionToken returns a 32-byte URL-safe token.
func newSessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, errRead := rand.Read(buf); errRead != nil {
		return "", errRead
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// create registers a new session and returns it with its token.
//
// persistent only records how the browser should keep the cookie, so a later
// re-issue (the browser lost it, the panel came back with just its token) does not
// silently downgrade a "remember this device" session to a browser-lifetime one.
func (r *sessionRegistry) create(clientIP string, persistent bool) (*managementSession, string, error) {
	token, errToken := newSessionToken()
	if errToken != nil {
		return nil, "", errToken
	}
	now := time.Now()
	session := &managementSession{
		id:         token[:16],
		clientIP:   clientIP,
		created:    now,
		lastSeen:   now,
		lastAuth:   now,
		persistent: persistent,
	}
	r.mu.Lock()
	r.sessions[token] = session
	r.mu.Unlock()
	return session, token, nil
}

// lookup resolves a token without touching its clocks. A request that merely polls
// must not extend the session.
func (r *sessionRegistry) lookup(token, clientIP string) (*managementSession, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errSessionMissing
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[token]
	if !ok {
		return nil, errSessionExpired
	}
	now := time.Now()
	if session.expiredForPanel(now, panelIdleTTL(), sessionAbsoluteTTL()) {
		delete(r.sessions, token)
		return nil, errSessionExpired
	}
	if sessionBindsIP() && session.clientIP != clientIP {
		return nil, errSessionExpired
	}
	return session, nil
}

// touch resolves a token and slides both clocks. It is the only path that does,
// and only real user activity is allowed to reach it: a real action is both
// "the browser is still here" and "the operator is still working".
func (r *sessionRegistry) touch(token, clientIP string) (*managementSession, error) {
	session, errLookup := r.lookup(token, clientIP)
	if errLookup != nil {
		return nil, errLookup
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	session.lastSeen = now
	session.lastAuth = now
	return session, nil
}

// revoke drops a token and returns the session it belonged to.
func (r *sessionRegistry) revoke(token string) *managementSession {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[token]
	if !ok {
		return nil
	}
	delete(r.sessions, token)
	return session
}

// sweep drops expired sessions and returns them so their grants can be revoked.
//
// It uses the browser-session clock, not the unlock clock: a session that merely
// went quiet keeps the browser signed in, while the credential grant it holds
// expires on its own (see dropStaleGrants).
func (r *sessionRegistry) sweep(now time.Time) []*managementSession {
	idle, absolute := panelIdleTTL(), sessionAbsoluteTTL()
	r.mu.Lock()
	defer r.mu.Unlock()
	var dropped []*managementSession
	for token, session := range r.sessions {
		if session.expiredForPanel(now, idle, absolute) {
			delete(r.sessions, token)
			dropped = append(dropped, session)
		}
	}
	return dropped
}

// count reports how many sessions are live, for tests and diagnostics.
func (r *sessionRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// ensureSessions lazily installs the registry so handlers built as struct
// literals (tests) still work.
func (h *Handler) ensureSessions() *sessionRegistry {
	h.sessionsOnce.Do(func() {
		h.sessions = newSessionRegistry()
		go h.runSessionSweeper()
	})
	return h.sessions
}

// runSessionSweeper drops expired sessions and their secret-store grants.
func (h *Handler) runSessionSweeper() {
	ticker := time.NewTicker(sessionSweepInterval)
	defer ticker.Stop()
	for now := range ticker.C {
		for _, session := range h.ensureSessions().sweep(now) {
			revokeSessionGrant(session.id)
		}
		dropStaleGrants(now)
	}
}

// revokeSessionGrant drops one session's grant and rebuilds the supply service
// when that took the storage key away from the backend.
//
// On a machine-unlockable store the key stays, so nothing is rebuilt: tearing
// down a provider that plugins are using would be pure disruption.
func revokeSessionGrant(sessionID string) {
	store := secretstore.Default()
	if store == nil {
		return
	}
	heldBefore := store.Unlocked()
	store.RevokeSession(sessionID)
	if heldBefore && !store.Unlocked() {
		reloadSupply()
	}
}

// dropStaleGrants reclaims grants whose store-side deadline has passed, which
// matters when the session registry and the store disagree about a session's
// lifetime.
func dropStaleGrants(now time.Time) {
	store := secretstore.Default()
	if store == nil {
		return
	}
	heldBefore := store.Unlocked()
	if store.SweepExpired(now) > 0 && heldBefore && !store.Unlocked() {
		reloadSupply()
	}
}

// SessionMiddleware resolves the session token for management routes.
//
// A request without any token is allowed through: the management key alone still
// works for everything that is not a secret operation, so existing scripts and
// tooling keep functioning. A request that does present a token must present a
// live one — a stale token is an expired session, and answering 401 is what sends
// the panel back to the login page instead of letting it show stale data.
//
// The cookie is the browser's own credential and the header is what a script
// sends, so they are tried in that order of authority: if the header names a
// session that is gone but the cookie still resolves, the cookie wins. And a live
// session always ends up with a cookie — otherwise a browser that signed in with
// the key once could lose "this browser is signed in" without noticing.
func (h *Handler) SessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		headerToken := strings.TrimSpace(c.GetHeader(sessionHeaderName))
		cookieToken := sessionCookieToken(c)
		token := headerToken
		if token == "" {
			token = cookieToken
		}
		if token == "" {
			c.Next()
			return
		}
		session, errLookup := h.ensureSessions().lookup(token, c.ClientIP())
		if errLookup != nil && cookieToken != "" && cookieToken != headerToken {
			// The header may be a leftover from another session or another tab.
			// The cookie is what this browser actually holds.
			if viaCookie, errCookie := h.ensureSessions().lookup(cookieToken, c.ClientIP()); errCookie == nil {
				session, errLookup, headerToken, token = viaCookie, nil, "", cookieToken
			}
		}
		if errLookup != nil {
			if headerToken != "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": errLookup.Error()})
				return
			}
			// A stale cookie must not block a request that still carries a valid
			// management key: drop it and let the key path decide.
			clearSessionCookie(c)
			c.Next()
			return
		}
		if cookieToken == "" {
			writeSessionCookie(c, token, session.persistent)
		}
		c.Set(sessionContextKey, session)
		c.Next()
	}
}

// sessionFromContext returns the session resolved by SessionMiddleware, or nil
// when the request carried no token.
func sessionFromContext(c *gin.Context) *managementSession {
	if c == nil {
		return nil
	}
	value, ok := c.Get(sessionContextKey)
	if !ok {
		return nil
	}
	session, ok := value.(*managementSession)
	if !ok {
		return nil
	}
	return session
}

// sessionID returns the current session id, or "" when there is none.
func sessionID(c *gin.Context) string {
	if session := sessionFromContext(c); session != nil {
		return session.id
	}
	return ""
}

// sessionVault returns the secret store as seen by the calling session. A request
// without a session gets a vault that refuses everything, so the management key
// alone never reaches credentials.
func sessionVault(c *gin.Context) secretstore.Vault {
	return secretstore.Default().SessionVault(sessionID(c))
}

// requireSession answers 409 when an operation needs a session and the request
// carried none.
func requireSession(c *gin.Context) (*managementSession, bool) {
	session := sessionFromContext(c)
	if session == nil {
		c.JSON(http.StatusConflict, gin.H{"error": errSessionMissing.Error()})
		return nil, false
	}
	return session, true
}

// sessionPayload is the session description the panel reads.
type sessionPayload struct {
	ID              string `json:"id"`
	Token           string `json:"token,omitempty"`
	ClientIP        string `json:"client_ip,omitempty"`
	IdleSeconds     int    `json:"idle_seconds"`
	AbsoluteSeconds int    `json:"absolute_seconds"`
	ExpiresAt       string `json:"expires_at"`
	Unlocked        bool   `json:"unlocked"`
	SystemAccess    string `json:"system_access"`
}

func buildSessionPayload(session *managementSession, token string) sessionPayload {
	payload := sessionPayload{
		ID:              session.id,
		Token:           token,
		ClientIP:        session.clientIP,
		IdleSeconds:     int(sessionIdleTTL() / time.Second),
		AbsoluteSeconds: int(sessionAbsoluteTTL() / time.Second),
		SystemAccess:    "none",
	}
	if idle := sessionIdleTTL(); idle > 0 {
		payload.ExpiresAt = session.lastSeen.Add(idle).UTC().Format(time.RFC3339)
	}
	if store := secretstore.Default(); store != nil {
		payload.Unlocked = store.SessionUnlocked(session.id)
		payload.SystemAccess = store.SystemAccess()
	}
	return payload
}

// PostSession starts a management session. The management key is the only
// credential it accepts; the reply carries the token the panel stores.
//
// The same token is also written to an HttpOnly cookie, which is what lets a
// reload or a new tab stay signed in without the panel holding the key. The
// optional `persistent` flag asks for a cookie that outlives the browser process.
func (h *Handler) PostSession(c *gin.Context) {
	var request struct {
		Persistent bool `json:"persistent"`
	}
	if c.Request != nil && c.Request.Body != nil {
		// A missing or malformed body is not an error: the default is a session
		// cookie, which is what a browser should get unless it asked otherwise.
		_ = c.ShouldBindJSON(&request)
	}
	session, token, errCreate := h.ensureSessions().create(c.ClientIP(), request.Persistent)
	if errCreate != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot create a session"})
		return
	}
	writeSessionCookie(c, token, request.Persistent)
	c.JSON(http.StatusOK, buildSessionPayload(session, token))
}

// GetSession describes the calling session.
func (h *Handler) GetSession(c *gin.Context) {
	session, ok := requireSession(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, buildSessionPayload(session, ""))
}

// PostSessionTouch slides the idle clock. The panel calls it on real user
// activity only, so background polling never keeps a session alive.
func (h *Handler) PostSessionTouch(c *gin.Context) {
	session, errTouch := h.ensureSessions().touch(sessionToken(c), c.ClientIP())
	if errTouch != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errTouch.Error()})
		return
	}
	// Keep the store's own backstop in step with the session clock.
	if store := secretstore.Default(); store != nil {
		store.TouchSession(session.id, sessionIdleTTL())
	}
	c.JSON(http.StatusOK, buildSessionPayload(session, ""))
}

// DeleteSession ends the calling session and drops its secret-store grant. Other
// sessions are untouched.
func (h *Handler) DeleteSession(c *gin.Context) {
	session := h.ensureSessions().revoke(sessionToken(c))
	// The cookie goes away whether or not the token still resolved: a browser that
	// pressed "sign out" must not keep a credential it can no longer use.
	clearSessionCookie(c)
	if session == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ended"})
		return
	}
	revokeSessionGrant(session.id)
	c.JSON(http.StatusOK, gin.H{"status": "ended"})
}
