package management

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// passphraseStoreLocked installs a passphrase-protected store that is locked and
// holds one secret, which is the state the panel starts from after a restart.
func passphraseStoreLocked(t *testing.T) *secretstore.Store {
	t.Helper()
	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	if errInit := store.Initialize("master"); errInit != nil {
		t.Fatalf("initialize store: %v", errInit)
	}
	if errSeed := store.Set("phone", "api-secret"); errSeed != nil {
		t.Fatalf("seed secret: %v", errSeed)
	}
	store.Lock()
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })
	return store
}

// sessionRouter mounts the session and secret routes behind the session
// middleware, mirroring the v8 management group.
func sessionRouter(t *testing.T) (*Handler, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &Handler{}
	r := gin.New()
	r.Use(h.SessionMiddleware())
	r.POST("/session", h.PostSession)
	r.GET("/session", h.GetSession)
	r.DELETE("/session", h.DeleteSession)
	r.POST("/session/touch", h.PostSessionTouch)
	r.GET("/secrets", h.GetSecretStatus)
	r.POST("/secrets/unlock", h.PostSecretUnlock)
	r.POST("/secrets/lock", h.PostSecretLock)
	r.POST("/secrets/passphrase", h.PostSecretPassphrase)
	r.POST("/secrets/machine-unlock", h.PostSecretMachineUnlock)
	r.PUT("/secrets/:name", h.PutSecret)
	return h, r
}

// call issues one request, optionally carrying a session token.
func call(t *testing.T, r *gin.Engine, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, errMarshal := json.Marshal(body)
		if errMarshal != nil {
			t.Fatalf("marshal body: %v", errMarshal)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(sessionHeaderName, token)
	}
	recorder := httptest.NewRecorder()
	r.ServeHTTP(recorder, req)
	return recorder
}

// startSession creates a session through the route the panel uses.
func startSession(t *testing.T, r *gin.Engine) string {
	t.Helper()
	recorder := call(t, r, http.MethodPost, "/session", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("create session: status %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
	}
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode session: %v", errDecode)
	}
	if payload.Token == "" {
		t.Fatal("create session returned no token")
	}
	return payload.Token
}

// secretStatusOf reads the status the panel would render.
func secretStatusOf(t *testing.T, r *gin.Engine, token string) secretStatusPayload {
	t.Helper()
	recorder := call(t, r, http.MethodGet, "/secrets", token, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("secret status: %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload secretStatusPayload
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode status: %v", errDecode)
	}
	return payload
}

// unlockWith proves the passphrase for one session.
func unlockWith(t *testing.T, r *gin.Engine, token, passphrase string) *httptest.ResponseRecorder {
	t.Helper()
	return call(t, r, http.MethodPost, "/secrets/unlock", token, map[string]string{"passphrase": passphrase})
}

// TestUnlockIsBoundToTheCallingSession is the core contract: opening the store for
// one session must not open it for another, and a management key alone must never
// reach a credential.
func TestUnlockIsBoundToTheCallingSession(t *testing.T) {
	passphraseStoreLocked(t)
	_, r := sessionRouter(t)

	tokenA := startSession(t, r)
	if status := secretStatusOf(t, r, tokenA); status.Unlocked {
		t.Fatal("a new session must not be unlocked")
	}

	if recorder := unlockWith(t, r, tokenA, "master"); recorder.Code != http.StatusOK {
		t.Fatalf("unlock: %d: %s", recorder.Code, recorder.Body.String())
	}
	statusA := secretStatusOf(t, r, tokenA)
	if !statusA.Unlocked {
		t.Fatal("the unlocking session must be unlocked")
	}
	if len(statusA.Names) != 1 || statusA.Names[0] != "phone" {
		t.Fatalf("names = %v, want [phone]", statusA.Names)
	}

	// A second session is a different subject, even though the same operator
	// created it with the same management key.
	tokenB := startSession(t, r)
	statusB := secretStatusOf(t, r, tokenB)
	if statusB.Unlocked {
		t.Fatal("a second session must not inherit the first one's unlock")
	}
	if len(statusB.Names) != 0 {
		t.Fatalf("a locked session must not learn secret names, got %v", statusB.Names)
	}
	if recorder := call(t, r, http.MethodPut, "/secrets/other", tokenB, map[string]string{"value": "x"}); recorder.Code != http.StatusConflict {
		t.Fatalf("write from an unbound session: %d, want 409", recorder.Code)
	}

	// The same write succeeds for the session that proved the passphrase.
	if recorder := call(t, r, http.MethodPut, "/secrets/other", tokenA, map[string]string{"value": "x"}); recorder.Code != http.StatusOK {
		t.Fatalf("write from the unlocked session: %d: %s", recorder.Code, recorder.Body.String())
	}
}

// TestLockingOneSessionLeavesAnotherUnlocked pins the per-session lock semantics.
func TestLockingOneSessionLeavesAnotherUnlocked(t *testing.T) {
	store := passphraseStoreLocked(t)
	_, r := sessionRouter(t)

	tokenA := startSession(t, r)
	tokenB := startSession(t, r)
	for _, token := range []string{tokenA, tokenB} {
		if recorder := unlockWith(t, r, token, "master"); recorder.Code != http.StatusOK {
			t.Fatalf("unlock: %d: %s", recorder.Code, recorder.Body.String())
		}
	}

	if recorder := call(t, r, http.MethodPost, "/secrets/lock", tokenA, nil); recorder.Code != http.StatusOK {
		t.Fatalf("lock: %d: %s", recorder.Code, recorder.Body.String())
	}
	if status := secretStatusOf(t, r, tokenA); status.Unlocked {
		t.Fatal("the locked session must be locked")
	}
	if status := secretStatusOf(t, r, tokenB); !status.Unlocked {
		t.Fatal("locking one session must not lock another")
	}
	if !store.Unlocked() {
		t.Fatal("the store stays open while another session holds it")
	}

	// The last holder leaving a passphrase-only store drops the storage key.
	if recorder := call(t, r, http.MethodPost, "/secrets/lock", tokenB, nil); recorder.Code != http.StatusOK {
		t.Fatalf("lock: %d: %s", recorder.Code, recorder.Body.String())
	}
	if store.Unlocked() {
		t.Fatal("the store must lock once the last session leaves a passphrase store")
	}
}

// TestSecretOperationsWithoutASessionAreRefused covers the management-key-only
// client: it may configure the server, but it may not reach credentials.
func TestSecretOperationsWithoutASessionAreRefused(t *testing.T) {
	passphraseStoreLocked(t)
	_, r := sessionRouter(t)

	if recorder := unlockWith(t, r, "", "master"); recorder.Code != http.StatusConflict {
		t.Fatalf("unlock without a session: %d, want 409", recorder.Code)
	}
	if recorder := call(t, r, http.MethodPut, "/secrets/phone", "", map[string]string{"value": "x"}); recorder.Code != http.StatusConflict {
		t.Fatalf("write without a session: %d, want 409", recorder.Code)
	}
	// Reading the status is allowed: it is how a client discovers that it needs a
	// session, and it discloses no names while locked.
	status := secretStatusOf(t, r, "")
	if status.Unlocked || len(status.Names) != 0 {
		t.Fatalf("status without a session = %+v, want locked and nameless", status)
	}
}

// TestExpiredSessionIsRejected makes sure expiry is enforced by the server rather
// than by the browser choosing to log out.
func TestExpiredSessionIsRejected(t *testing.T) {
	passphraseStoreLocked(t)
	h, r := sessionRouter(t)

	token := startSession(t, r)
	if recorder := unlockWith(t, r, token, "master"); recorder.Code != http.StatusOK {
		t.Fatalf("unlock: %d: %s", recorder.Code, recorder.Body.String())
	}

	registry := h.ensureSessions()
	registry.mu.Lock()
	session := registry.sessions[token]
	registry.mu.Unlock()
	if session == nil {
		t.Fatal("session was not registered")
	}
	// Both clocks: the browser clock decides whether the session resolves at all,
	// the activity clock decides whether the credential grant survives.
	session.lastSeen = time.Now().Add(-2 * sessionIdleTTL())
	session.lastAuth = time.Now().Add(-2 * panelIdleTTL())

	if recorder := call(t, r, http.MethodGet, "/secrets", token, nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("request with an expired session: %d, want 401", recorder.Code)
	}
}

// TestQuietSessionStaysSignedIn is the separation the panel needs: a browser that
// went quiet keeps its sign-in, while the credential grant it held does not.
func TestQuietSessionStaysSignedIn(t *testing.T) {
	passphraseStoreLocked(t)
	h, r := sessionRouter(t)

	token := startSession(t, r)
	registry := h.ensureSessions()
	registry.mu.Lock()
	session := registry.sessions[token]
	registry.mu.Unlock()

	session.lastSeen = time.Now().Add(-2 * sessionIdleTTL())
	if recorder := call(t, r, http.MethodGet, "/secrets", token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("a quiet session must still resolve: %d: %s", recorder.Code, recorder.Body.String())
	}
	if status := secretStatusOf(t, r, token); status.Unlocked {
		t.Fatal("a quiet session must not still hold an unlocked credential store")
	}
}

// TestTouchSlidesTheIdleClock covers the one path allowed to extend a session.
func TestTouchSlidesTheIdleClock(t *testing.T) {
	passphraseStoreLocked(t)
	h, r := sessionRouter(t)

	token := startSession(t, r)
	registry := h.ensureSessions()
	registry.mu.Lock()
	session := registry.sessions[token]
	registry.mu.Unlock()

	// Just inside the idle limit: still alive, but about to expire.
	session.lastSeen = time.Now().Add(-sessionIdleTTL() + time.Minute)
	if recorder := call(t, r, http.MethodPost, "/session/touch", token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("touch: %d: %s", recorder.Code, recorder.Body.String())
	}
	if idle := time.Since(session.lastSeen); idle > time.Minute {
		t.Fatalf("touch did not slide the idle clock (last seen %v ago)", idle)
	}
}

// TestEndingASessionDropsItsToken keeps a logout from leaving a usable token
// behind.
func TestEndingASessionDropsItsToken(t *testing.T) {
	passphraseStoreLocked(t)
	_, r := sessionRouter(t)

	token := startSession(t, r)
	if recorder := unlockWith(t, r, token, "master"); recorder.Code != http.StatusOK {
		t.Fatalf("unlock: %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := call(t, r, http.MethodDelete, "/session", token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("end session: %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := call(t, r, http.MethodGet, "/secrets", token, nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("request after ending the session: %d, want 401", recorder.Code)
	}
}

// TestMachineUnlockNeedsAnUnlockedSession closes a hole the per-session model
// would otherwise open: enabling machine unlock is what gives the backend standing
// access, so a client holding only the management key must not be able to switch it
// on while an operator has the panel open.
func TestMachineUnlockNeedsAnUnlockedSession(t *testing.T) {
	store := passphraseStoreLocked(t)
	_, r := sessionRouter(t)

	if recorder := call(t, r, http.MethodPost, "/secrets/machine-unlock", "", nil); recorder.Code != http.StatusConflict {
		t.Fatalf("enable without a session: %d, want 409", recorder.Code)
	}
	token := startSession(t, r)
	if recorder := call(t, r, http.MethodPost, "/secrets/machine-unlock", token, nil); recorder.Code != http.StatusConflict {
		t.Fatalf("enable from a locked session: %d, want 409", recorder.Code)
	}
	if store.Mode() != secretstore.UnlockPassphrase {
		t.Fatalf("mode = %q, want %q", store.Mode(), secretstore.UnlockPassphrase)
	}

	if recorder := unlockWith(t, r, token, "master"); recorder.Code != http.StatusOK {
		t.Fatalf("unlock: %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := call(t, r, http.MethodPost, "/secrets/machine-unlock", token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("enable from an unlocked session: %d: %s", recorder.Code, recorder.Body.String())
	}
	if store.Mode() != secretstore.UnlockPassphraseMachine {
		t.Fatalf("mode = %q, want %q", store.Mode(), secretstore.UnlockPassphraseMachine)
	}
}

// TestChangingPassphraseKeepsTheCallingSession covers the credential change: other
// sessions proved the old passphrase and must prove the new one, while the session
// that made the change stays unlocked.
func TestChangingPassphraseKeepsTheCallingSession(t *testing.T) {
	store := passphraseStoreLocked(t)
	_, r := sessionRouter(t)

	tokenA := startSession(t, r)
	tokenB := startSession(t, r)
	for _, token := range []string{tokenA, tokenB} {
		if recorder := unlockWith(t, r, token, "master"); recorder.Code != http.StatusOK {
			t.Fatalf("unlock: %d: %s", recorder.Code, recorder.Body.String())
		}
	}

	recorder := call(t, r, http.MethodPost, "/secrets/passphrase", tokenA,
		map[string]string{"current": "master", "next": "next-pass"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("change passphrase: %d: %s", recorder.Code, recorder.Body.String())
	}
	if status := secretStatusOf(t, r, tokenA); !status.Unlocked {
		t.Fatal("the session that changed the passphrase must stay unlocked")
	}
	if status := secretStatusOf(t, r, tokenB); status.Unlocked {
		t.Fatal("other sessions must prove the new passphrase")
	}
	if !store.Unlocked() {
		t.Fatal("the store stays open for the session that changed the passphrase")
	}

	if recorder := unlockWith(t, r, tokenB, "master"); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unlock with the old passphrase: %d, want 401", recorder.Code)
	}
	if recorder := unlockWith(t, r, tokenB, "next-pass"); recorder.Code != http.StatusOK {
		t.Fatalf("unlock with the new passphrase: %d: %s", recorder.Code, recorder.Body.String())
	}
}

// cookieRouter mounts the management group the way the server does: the key
// middleware in front, the session middleware behind it, and one protected route.
func cookieRouter(t *testing.T, allowRemote bool) *Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &Handler{
		cfg: &config.Config{
			RemoteManagement: config.RemoteManagement{AllowRemote: allowRemote, SecretKey: ""},
		},
		failedAttempts: make(map[string]*attemptInfo),
		envSecret:      "test-secret",
	}
	return h
}

// cookieCall issues one management request from a fixed address, carrying
// whichever credentials the caller supplies.
func cookieCall(t *testing.T, h *Handler, remoteAddr, key, cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	engine := gin.New()
	engine.Use(h.Middleware(), h.SessionMiddleware())
	engine.GET("/config", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	engine.POST("/session", h.PostSession)
	engine.DELETE("/session", h.DeleteSession)

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.RemoteAddr = remoteAddr
	if key != "" {
		req.Header.Set("X-Management-Key", key)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	if csrf != "" {
		req.Header.Set(sessionCSRFHeader, csrf)
	}
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)
	return recorder
}

// cookieFrom pulls the management session cookie out of a response.
func cookieFrom(t *testing.T, recorder *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	return nil
}

// startCookieSession signs in with the key and returns the issued cookie.
func startCookieSession(t *testing.T, h *Handler, remoteAddr string, persistent bool) *http.Cookie {
	t.Helper()
	engine := gin.New()
	engine.Use(h.Middleware())
	engine.POST("/session", h.PostSession)

	body := bytes.NewReader(nil)
	if persistent {
		body = bytes.NewReader([]byte(`{"persistent":true}`))
	}
	req := httptest.NewRequest(http.MethodPost, "/session", body)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Management-Key", "test-secret")
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("create session: %d: %s", recorder.Code, recorder.Body.String())
	}
	cookie := cookieFrom(t, recorder)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("signing in must hand the browser a session cookie")
	}
	return cookie
}

// TestSessionCookieAuthenticatesWithoutTheKey is the point of the cookie: a
// browser that reloads the page has no key to send, and must still be let in.
func TestSessionCookieAuthenticatesWithoutTheKey(t *testing.T) {
	h := cookieRouter(t, false)
	const loopback = "127.0.0.1:12345"
	cookie := startCookieSession(t, h, loopback, false)

	if !cookie.HttpOnly {
		t.Fatal("the session cookie must not be readable from JavaScript")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Path != sessionCookiePath {
		t.Fatalf("path = %q, want %q", cookie.Path, sessionCookiePath)
	}
	if cookie.MaxAge != 0 {
		t.Fatalf("a default sign-in must be a browser-session cookie, MaxAge = %d", cookie.MaxAge)
	}

	if recorder := cookieCall(t, h, loopback, "", cookie.Value, sessionCSRFHeaderValue); recorder.Code != http.StatusOK {
		t.Fatalf("cookie-only request: %d: %s", recorder.Code, recorder.Body.String())
	}
}

// TestSessionCookieWithoutTheCSRFHeaderIsRefused covers the sibling-host case that
// SameSite=Strict alone does not: a form post from another host under the same
// registrable domain still carries the cookie.
func TestSessionCookieWithoutTheCSRFHeaderIsRefused(t *testing.T) {
	h := cookieRouter(t, false)
	const loopback = "127.0.0.1:12345"
	cookie := startCookieSession(t, h, loopback, false)

	recorder := cookieCall(t, h, loopback, "", cookie.Value, "")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

// TestSessionCookieIsBoundToTheAddressThatCreatedIt keeps a stolen cookie useless.
func TestSessionCookieIsBoundToTheAddressThatCreatedIt(t *testing.T) {
	h := cookieRouter(t, true)
	cookie := startCookieSession(t, h, "203.0.113.7:5000", false)

	recorder := cookieCall(t, h, "203.0.113.8:5000", "", cookie.Value, sessionCSRFHeaderValue)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a cookie replayed from another address", recorder.Code)
	}
	if cleared := cookieFrom(t, recorder); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatal("a rejected cookie must be cleared in the reply")
	}
}

// TestPersistentSessionCookieOutlivesTheBrowser is what the panel's "remember this
// device" option asks for.
func TestPersistentSessionCookieOutlivesTheBrowser(t *testing.T) {
	h := cookieRouter(t, false)
	cookie := startCookieSession(t, h, "127.0.0.1:12345", true)
	if cookie.MaxAge <= 0 {
		t.Fatalf("MaxAge = %d, want a persistent lifetime", cookie.MaxAge)
	}
}

// TestEndingTheSessionClearsTheCookie makes "sign out" actually sign the browser out.
func TestEndingTheSessionClearsTheCookie(t *testing.T) {
	h := cookieRouter(t, false)
	const loopback = "127.0.0.1:12345"
	cookie := startCookieSession(t, h, loopback, false)

	engine := gin.New()
	engine.Use(h.Middleware(), h.SessionMiddleware())
	engine.DELETE("/session", h.DeleteSession)
	req := httptest.NewRequest(http.MethodDelete, "/session", nil)
	req.RemoteAddr = loopback
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie.Value})
	req.Header.Set(sessionCSRFHeader, sessionCSRFHeaderValue)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("end session: %d: %s", recorder.Code, recorder.Body.String())
	}
	if cleared := cookieFrom(t, recorder); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatal("ending a session must clear the cookie")
	}
	if recorder := cookieCall(t, h, loopback, "", cookie.Value, sessionCSRFHeaderValue); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("the revoked cookie still authenticates: %d", recorder.Code)
	}
}

// TestRequestsWithoutCredentialsAreNotCountedAsFailures guards the operator's own
// address: a browser reload sends no key, and five of those must not ban it.
func TestRequestsWithoutCredentialsAreNotCountedAsFailures(t *testing.T) {
	h := cookieRouter(t, false)
	const loopback = "127.0.0.1:12345"

	for i := range 10 {
		if recorder := cookieCall(t, h, loopback, "", "", ""); recorder.Code != http.StatusUnauthorized {
			t.Fatalf("request %d: status = %d, want 401", i+1, recorder.Code)
		}
	}
	if recorder := cookieCall(t, h, loopback, "test-secret", "", ""); recorder.Code != http.StatusOK {
		t.Fatalf("the key must still work after keyless requests: %d: %s", recorder.Code, recorder.Body.String())
	}
}

// TestWrongKeyStillBansTheAddress keeps the brute-force protection intact.
func TestWrongKeyStillBansTheAddress(t *testing.T) {
	h := cookieRouter(t, false)
	const loopback = "127.0.0.1:12345"

	for range 5 {
		cookieCall(t, h, loopback, "wrong-secret", "", "")
	}
	recorder := cookieCall(t, h, loopback, "test-secret", "", "")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 while banned", recorder.Code)
	}
}

// TestALiveSessionAlwaysEndsUpWithACookie keeps "signed in" and "has a cookie" in
// step. A key-authenticated request can still present an older session token (the
// panel reused a live session instead of creating one), and in that case nothing
// would ever have written the cookie — so the next reload would have neither a key
// nor a cookie.
func TestALiveSessionAlwaysEndsUpWithACookie(t *testing.T) {
	h := cookieRouter(t, false)
	const loopback = "127.0.0.1:12345"
	cookie := startCookieSession(t, h, loopback, false)

	engine := gin.New()
	engine.Use(h.Middleware(), h.SessionMiddleware())
	engine.GET("/config", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.RemoteAddr = loopback
	req.Header.Set("X-Management-Key", "test-secret")
	req.Header.Set(sessionHeaderName, cookie.Value)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	issued := cookieFrom(t, recorder)
	if issued == nil || issued.Value != cookie.Value {
		t.Fatal("a live session presented in the header must get its cookie back")
	}
}

// TestTheCookieOutranksAStaleHeaderToken covers the mixed state: the header names a
// session that is gone, the cookie still resolves. The cookie is what the browser
// actually holds, so it decides.
func TestTheCookieOutranksAStaleHeaderToken(t *testing.T) {
	h := cookieRouter(t, false)
	const loopback = "127.0.0.1:12345"
	cookie := startCookieSession(t, h, loopback, false)

	engine := gin.New()
	engine.Use(h.Middleware(), h.SessionMiddleware())
	engine.GET("/config", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.RemoteAddr = loopback
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie.Value})
	req.Header.Set(sessionCSRFHeader, sessionCSRFHeaderValue)
	req.Header.Set(sessionHeaderName, "session-that-no-longer-exists")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
}

// TestSecureCookieOnlyOverRealTLS guards the bug that made a plain-HTTP panel lose
// its session on every reload: net/http fills Request.TLS from any connection that
// reports a ConnectionState, and this server's buffered connection wrapper reports
// a zero one for plain TCP. A non-nil state therefore proves nothing — only a
// completed handshake (or an https hop in front) does.
func TestSecureCookieOnlyOverRealTLS(t *testing.T) {
	cases := []struct {
		name   string
		state  *tls.ConnectionState
		proto  string
		secure bool
	}{
		{name: "plain tcp reporting an empty state", state: &tls.ConnectionState{}},
		{name: "no state at all"},
		{name: "completed handshake", state: &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}, secure: true},
		{name: "handshake state without the flag", state: &tls.ConnectionState{Version: tls.VersionTLS12}, secure: true},
		{name: "https hop in front", proto: "https", secure: true},
		{name: "http hop in front", proto: "http"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/session", nil)
			c.Request.TLS = testCase.state
			if testCase.proto != "" {
				c.Request.Header.Set("X-Forwarded-Proto", testCase.proto)
			}
			if got := sessionCookieSecure(c); got != testCase.secure {
				t.Fatalf("secure = %t, want %t", got, testCase.secure)
			}
		})
	}
}
