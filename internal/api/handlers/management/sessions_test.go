package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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
	session.lastSeen = time.Now().Add(-2 * sessionIdleTTL())

	if recorder := call(t, r, http.MethodGet, "/secrets", token, nil); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("request with an expired session: %d, want 401", recorder.Code)
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
