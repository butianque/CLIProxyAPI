package management

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
)

// setupAuthorizeTest wires the sign-in routes against the same temporary supply
// directory and empty pool the paste import uses, so both imports are asserted
// against the same persisted state.
func setupAuthorizeTest(t *testing.T) (*Handler, *gin.Engine, string) {
	t.Helper()
	h, r, stateDir := setupImportTest(t)
	r.POST("/supply/email/authorize", h.PostSupplyEmailAuthorize)
	r.GET("/supply/email/authorize", h.GetSupplyEmailAuthorize)
	r.POST("/supply/email/authorize/:id/cancel", h.PostSupplyEmailAuthorizeCancel)
	r.POST("/supply/email/authorize/:id/commit", h.PostSupplyEmailAuthorizeCommit)
	emailAuthorizes.reset()
	t.Cleanup(func() {
		emailAuthorizes.reset()
		emailAuthorizes.startSignIn = nil
		emailAuthorizes.pollSignIn = nil
		emailAuthorizes.identify = nil
	})
	return h, r, stateDir
}

// stubSignIn replaces the three calls that would reach Microsoft. The interval is
// milliseconds so the state machine runs without a real wait, and the first poll
// already succeeds: what these tests cover is the decision, not the waiting.
func stubSignIn(t *testing.T, identity email.GraphIdentity, refreshToken string) {
	t.Helper()
	emailAuthorizes.startSignIn = func(ctx context.Context, egress, clientID string) (email.DeviceAuthorization, error) {
		return email.DeviceAuthorization{
			DeviceCode: "dc-1",
			UserCode:   "Z5UENLHM",
			VerifyURL:  "https://www.microsoft.com/link",
			ExpiresIn:  10 * time.Second,
			Interval:   time.Millisecond,
		}, nil
	}
	emailAuthorizes.pollSignIn = func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
		return email.DeviceToken{
			AccessToken:  "at-1",
			RefreshToken: refreshToken,
			Expires:      time.Now().Add(time.Hour),
		}, nil
	}
	emailAuthorizes.identify = func(ctx context.Context, egress, accessToken string) (email.GraphIdentity, error) {
		return identity, nil
	}
}

// startAuthorize posts a batch and returns the flows it started.
func startAuthorize(t *testing.T, r *gin.Engine, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/supply/email/authorize", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	var decoded map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &decoded)
	return rr.Code, decoded
}

// listAuthorizes reads every flow the panel would see.
func listAuthorizes(t *testing.T, r *gin.Engine) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/supply/email/authorize", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	var decoded struct {
		Flows []map[string]any `json:"flows"`
	}
	if errUnmarshal := json.Unmarshal(rr.Body.Bytes(), &decoded); errUnmarshal != nil {
		t.Fatalf("decode list: %v", errUnmarshal)
	}
	return decoded.Flows
}

// waitForStatus polls the list until one flow reaches want, and returns it. The
// batch runs in the background, so this is the only way to observe it without
// reaching into the goroutine.
func waitForStatus(t *testing.T, r *gin.Engine, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last []map[string]any
	for time.Now().Before(deadline) {
		last = listAuthorizes(t, r)
		for _, flow := range last {
			if flow["status"] == want {
				return flow
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("no flow reached %q; last state %v", want, last)
	return nil
}

// waitForIdleBatch waits until no batch is running. A test that reads the pool
// document has to wait for this: the batch saves it from its own goroutine, and
// on Windows an open read of a file being replaced is an error rather than a
// stale value.
func waitForIdleBatch(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		emailAuthorizes.mu.Lock()
		running := emailAuthorizes.running
		emailAuthorizes.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the batch never finished")
}

// The point of the whole feature: an address alone becomes a working mailbox
// identity, with the refresh token in the store and a Graph pool record pointing
// at it — the same shape the paste import writes, so the read path cannot tell
// the two apart.
func TestAuthorizeStoresASignedInMailbox(t *testing.T) {
	_, r, stateDir := setupAuthorizeTest(t)
	unlockedEmptyStore(t)
	stubSignIn(t, email.GraphIdentity{Mail: "alice@hotmail.com"}, "rt-signed-in")

	code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`)
	if code != http.StatusOK {
		t.Fatalf("start: %d %v", code, resp)
	}
	flows, _ := resp["flows"].([]any)
	if len(flows) != 1 {
		t.Fatalf("started %d flows, want 1", len(flows))
	}
	// The code has to be on screen from the first answer: the operator cannot
	// type something they were never shown.
	first := flows[0].(map[string]any)
	if first["user_code"] != "Z5UENLHM" || first["verify_url"] != "https://www.microsoft.com/link" {
		t.Fatalf("first flow = %v, want the code and the page", first)
	}

	flow := waitForStatus(t, r, authorizeDone)
	if flow["account"] != "alice@hotmail.com" {
		t.Fatalf("flow account = %v", flow["account"])
	}
	waitForIdleBatch(t)

	store := secretstore.Default()
	value, errGet := store.Get(supply.EmailOAuth2CredentialName("alice@hotmail.com"))
	if errGet != nil {
		t.Fatalf("read stored token: %v", errGet)
	}
	if value != "rt-signed-in" {
		t.Fatalf("stored token = %q, want the signed-in one", value)
	}

	records := loadPool(t, stateDir).Mailboxes()
	if len(records) != 1 {
		t.Fatalf("pool mailboxes = %d, want 1", len(records))
	}
	box := records[0].Mailbox
	if box == nil || box.Nature != supply.NatureGraph {
		t.Fatalf("mailbox = %+v, want a graph transport", box)
	}
	// Graph answers at one fixed endpoint, so nothing is stored for it.
	if box.Endpoint != "" {
		t.Fatalf("endpoint = %q, want none", box.Endpoint)
	}
	if box.ClientID != authorizeClientID {
		t.Fatalf("application id = %q, want the one the sign-in used", box.ClientID)
	}
	if box.Secret != supply.EmailOAuth2CredentialName("alice@hotmail.com") {
		t.Fatalf("credential entry = %q", box.Secret)
	}
}

// The endpoint never says which account was signed in to. Without the identity
// check, a batch that asked for one address and was signed in to another would
// store that other account's token under the requested address — and every later
// A mailbox sold under an alias signs in as the address Microsoft reports, not
// the one the operator typed. The credential must be filed under the reported
// address: filing it under the typed one would hand a later read of that address
// whatever mailbox happened to sign in, which for a wrong sign-in is someone
// else's mail.
func TestAuthorizeStoresTheAddressThatActuallySignedIn(t *testing.T) {
	_, r, stateDir := setupAuthorizeTest(t)
	unlockedEmptyStore(t)
	stubSignIn(t, email.GraphIdentity{Mail: "bob@outlook.com"}, "rt-bob")

	if code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`); code != http.StatusOK {
		t.Fatalf("start: %d %v", code, resp)
	}
	flow := waitForStatus(t, r, authorizeDone)
	if got, _ := flow["stored_as"].(string); got != "bob@outlook.com" {
		t.Fatalf("stored_as = %q, want the signed-in address", got)
	}
	detail, _ := flow["detail"].(string)
	if !strings.Contains(detail, "bob@outlook.com") {
		t.Fatalf("detail = %q, want the address the sign-in landed on", detail)
	}

	records := loadPool(t, stateDir).All()
	if len(records) != 1 || records[0].Address != "bob@outlook.com" {
		t.Fatalf("records = %+v, want the signed-in address alone", records)
	}
	store := secretstore.Default()
	if _, errGet := store.Get(supply.EmailOAuth2CredentialName("alice@hotmail.com")); errGet == nil {
		t.Fatal("the requested address must not hold a credential for another account")
	}
	if _, errGet := store.Get(supply.EmailOAuth2CredentialName("bob@outlook.com")); errGet != nil {
		t.Fatalf("the signed-in address has no credential: %v", errGet)
	}
}

// Re-authorizing a mailbox must not drop the password entry an earlier paste
// import recorded: it is what a person signing in to the mailbox's own web page
// needs, and nothing in the sign-in flow can recover it.
func TestAuthorizeKeepsThePasswordAnEarlierImportRecorded(t *testing.T) {
	_, r, stateDir := setupAuthorizeTest(t)
	unlockedEmptyStore(t)
	stubSignIn(t, email.GraphIdentity{Mail: "alice@hotmail.com"}, "rt-signed-in")

	pool := supply.DefaultPool()
	pool.AttachMailbox(supply.KindEmail, "alice@hotmail.com", supply.Mailbox{
		Nature:   supply.NatureGraph,
		ClientID: authorizeClientID,
		Secret:   supply.EmailOAuth2CredentialName("alice@hotmail.com"),
		Password: supply.EmailPasswordCredentialName("alice@hotmail.com"),
	}, time.Now().Unix())
	if errSave := pool.Save(supply.PoolPath(stateDir)); errSave != nil {
		t.Fatalf("seed pool: %v", errSave)
	}

	if code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`); code != http.StatusOK {
		t.Fatalf("start: %d %v", code, resp)
	}
	waitForStatus(t, r, authorizeDone)
	waitForIdleBatch(t)

	box := loadPool(t, stateDir).Mailboxes()[0].Mailbox
	if box.Password != supply.EmailPasswordCredentialName("alice@hotmail.com") {
		t.Fatalf("password entry = %q, want it preserved", box.Password)
	}
}

// A store that locks while a sign-in is in flight must not throw the sign-in
// away: the token is held, and one unlock finishes the batch instead of one more
// trip through Microsoft's page.
func TestAuthorizeHoldsTheTokenWhenTheStoreLocks(t *testing.T) {
	_, r, stateDir := setupAuthorizeTest(t)
	unlockedEmptyStore(t)
	store := secretstore.Default()
	stubSignIn(t, email.GraphIdentity{Mail: "alice@hotmail.com"}, "rt-signed-in")

	// The sign-in lands while the store is locked, which is what happens when an
	// operator locks the panel in the middle of a batch.
	emailAuthorizes.pollSignIn = func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
		store.Lock()
		return email.DeviceToken{AccessToken: "at-1", RefreshToken: "rt-signed-in", Expires: time.Now().Add(time.Hour)}, nil
	}

	if code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`); code != http.StatusOK {
		t.Fatalf("start: %d %v", code, resp)
	}
	flow := waitForStatus(t, r, authorizeAwaitingUnlock)
	if records := loadPool(t, stateDir).All(); len(records) != 0 {
		t.Fatalf("a held sign-in wrote %d identities", len(records))
	}

	// Unlocking and committing finishes it without a second sign-in.
	if errUnlock := store.Unlock("master"); errUnlock != nil {
		t.Fatalf("unlock store: %v", errUnlock)
	}
	id, _ := flow["id"].(string)
	req := httptest.NewRequest(http.MethodPost, "/supply/email/authorize/"+id+"/commit",
		bytes.NewBufferString(`{"passphrase":"master"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rr.Code, rr.Body.String())
	}
	if value, errGet := store.Get(supply.EmailOAuth2CredentialName("alice@hotmail.com")); errGet != nil || value != "rt-signed-in" {
		t.Fatalf("stored token = %q (err %v)", value, errGet)
	}
	if records := loadPool(t, stateDir).Mailboxes(); len(records) != 1 {
		t.Fatalf("pool mailboxes = %d, want 1", len(records))
	}
}

// A batch walks its accounts one at a time: the panel can only show one code, and
// two sign-ins in the same minute from one address is the pattern Microsoft's
// abuse scoring watches for.
func TestAuthorizeWalksTheBatchOneAccountAtATime(t *testing.T) {
	_, r, stateDir := setupAuthorizeTest(t)
	unlockedEmptyStore(t)

	// Each account is walked in order, so the counter is read once per account.
	// The device code carries the account through the stubs: the real flow has no
	// other way to say which one is signing in, and that is exactly the gap the
	// identity check fills.
	order := []string{"alice@hotmail.com", "bob@hotmail.com"}
	next := 0
	emailAuthorizes.startSignIn = func(ctx context.Context, egress, clientID string) (email.DeviceAuthorization, error) {
		account := order[next]
		next++
		return email.DeviceAuthorization{
			DeviceCode: account, UserCode: "CODE", VerifyURL: "https://www.microsoft.com/link",
			ExpiresIn: 10 * time.Second, Interval: time.Millisecond,
		}, nil
	}
	emailAuthorizes.pollSignIn = func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
		return email.DeviceToken{AccessToken: deviceCode, RefreshToken: "rt-" + deviceCode, Expires: time.Now().Add(time.Hour)}, nil
	}
	emailAuthorizes.identify = func(ctx context.Context, egress, accessToken string) (email.GraphIdentity, error) {
		return email.GraphIdentity{Mail: accessToken}, nil
	}

	code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com\nbob@hotmail.com"}`)
	if code != http.StatusOK {
		t.Fatalf("start: %d %v", code, resp)
	}
	flows, _ := resp["flows"].([]any)
	if len(flows) != 2 {
		t.Fatalf("started %d flows, want 2", len(flows))
	}

	// Both accounts are walked, and both end up stored. The pool is read in
	// memory here: the batch is still saving, and on Windows opening the document
	// while it is being replaced fails instead of returning the older copy.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(supply.DefaultPool().Mailboxes()) == 2 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	waitForIdleBatch(t)
	if records := loadPool(t, stateDir).Mailboxes(); len(records) != 2 {
		t.Fatalf("pool mailboxes = %d, want 2", len(records))
	}
}

// A locked store stops the batch instead of walking on. Every later account would
// need the same sign-in and would park the same way, and the panel can only show
// one code at a time — the rest would be codes nobody reads, followed by
// credentials nobody can write.
func TestAuthorizeStopsTheBatchWhenTheStoreLocks(t *testing.T) {
	_, r, _ := setupAuthorizeTest(t)
	unlockedEmptyStore(t)
	store := secretstore.Default()

	codes := 0
	emailAuthorizes.startSignIn = func(ctx context.Context, egress, clientID string) (email.DeviceAuthorization, error) {
		codes++
		return email.DeviceAuthorization{
			DeviceCode: "dc", UserCode: "CODE", VerifyURL: "https://www.microsoft.com/link",
			ExpiresIn: 10 * time.Second, Interval: time.Millisecond,
		}, nil
	}
	emailAuthorizes.pollSignIn = func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
		store.Lock()
		return email.DeviceToken{
			AccessToken: "at", RefreshToken: "rt", Expires: time.Now().Add(time.Hour),
		}, nil
	}
	emailAuthorizes.identify = func(ctx context.Context, egress, accessToken string) (email.GraphIdentity, error) {
		return email.GraphIdentity{Mail: "alice@hotmail.com"}, nil
	}

	code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com\nbob@hotmail.com"}`)
	if code != http.StatusOK {
		t.Fatalf("start: %d %v", code, resp)
	}
	waitForStatus(t, r, authorizeAwaitingUnlock)
	waitForIdleBatch(t)

	if codes != 1 {
		t.Fatalf("asked for %d codes, want 1: a locked store must not walk the batch", codes)
	}
	flows := listAuthorizes(t, r)
	if len(flows) != 2 || flows[1]["status"] != authorizeCancelled {
		t.Fatalf("flows = %v, want the second account stopped", flows)
	}
}

// A parked sign-in holds a token that only a save can finish, so it keeps the slot
// the same way a running batch does. Letting a new batch start would drop that token
// without telling anyone.
func TestAuthorizeRefusesASecondBatchWhileOneIsParked(t *testing.T) {
	_, r, _ := setupAuthorizeTest(t)
	unlockedEmptyStore(t)
	store := secretstore.Default()
	stubSignIn(t, email.GraphIdentity{Mail: "alice@hotmail.com"}, "rt-parked")

	emailAuthorizes.pollSignIn = func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
		store.Lock()
		return email.DeviceToken{AccessToken: "at", RefreshToken: "rt-parked", Expires: time.Now().Add(time.Hour)}, nil
	}

	if code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`); code != http.StatusOK {
		t.Fatalf("first start: %d %v", code, resp)
	}
	waitForStatus(t, r, authorizeAwaitingUnlock)
	waitForIdleBatch(t)

	if code, _ := startAuthorize(t, r, `{"accounts":"bob@hotmail.com"}`); code != http.StatusConflict {
		t.Fatalf("start while parked: %d, want %d", code, http.StatusConflict)
	}
	// The parked one is still there, still holding its token.
	flows := listAuthorizes(t, r)
	if len(flows) != 1 || flows[0]["status"] != authorizeAwaitingUnlock {
		t.Fatalf("flows = %v, want the parked one alone", flows)
	}
}

// Stopping a parked sign-in is the only way to let go of it, so it has to actually
// drop the token rather than answer "already finished".
func TestAuthorizeCancelDropsAParkedToken(t *testing.T) {
	_, r, _ := setupAuthorizeTest(t)
	unlockedEmptyStore(t)
	store := secretstore.Default()
	stubSignIn(t, email.GraphIdentity{Mail: "alice@hotmail.com"}, "rt-parked")

	emailAuthorizes.pollSignIn = func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
		store.Lock()
		return email.DeviceToken{AccessToken: "at", RefreshToken: "rt-parked", Expires: time.Now().Add(time.Hour)}, nil
	}

	if code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`); code != http.StatusOK {
		t.Fatalf("start: %d %v", code, resp)
	}
	flow := waitForStatus(t, r, authorizeAwaitingUnlock)
	waitForIdleBatch(t)

	id, _ := flow["id"].(string)
	req := httptest.NewRequest(http.MethodPost, "/supply/email/authorize/"+id+"/cancel", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", rr.Code, rr.Body.String())
	}
	parked, _ := emailAuthorizes.get(id)
	if parked.Status != authorizeCancelled {
		t.Fatalf("status = %q, want %q", parked.Status, authorizeCancelled)
	}
	if parked.held != "" {
		t.Fatal("a cancelled sign-in still holds a token")
	}
}

// One batch at a time: a second one would mean two codes and two sign-ins against
// the same exit in the same minute, which is exactly the pattern to avoid.
func TestAuthorizeRefusesASecondBatch(t *testing.T) {
	_, r, _ := setupAuthorizeTest(t)
	unlockedEmptyStore(t)

	// A sign-in that never completes keeps the first batch running.
	emailAuthorizes.startSignIn = func(ctx context.Context, egress, clientID string) (email.DeviceAuthorization, error) {
		return email.DeviceAuthorization{
			DeviceCode: "dc", UserCode: "CODE", VerifyURL: "https://www.microsoft.com/link",
			ExpiresIn: time.Minute, Interval: time.Hour,
		}, nil
	}
	emailAuthorizes.pollSignIn = func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
		return email.DeviceToken{}, email.ErrDevicePending
	}
	emailAuthorizes.identify = func(ctx context.Context, egress, accessToken string) (email.GraphIdentity, error) {
		return email.GraphIdentity{Mail: "alice@hotmail.com"}, nil
	}

	if code, resp := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`); code != http.StatusOK {
		t.Fatalf("first start: %d %v", code, resp)
	}
	if code, _ := startAuthorize(t, r, `{"accounts":"bob@hotmail.com"}`); code != http.StatusConflict {
		t.Fatalf("second start: %d, want %d", code, http.StatusConflict)
	}
}

// The paste format belongs to the other mode. Accepting it here would look like a
// working import while storing nothing, because the token field would be dropped.
func TestAuthorizeRejectsPastedCredentials(t *testing.T) {
	_, r, _ := setupAuthorizeTest(t)
	unlockedEmptyStore(t)

	code, _ := startAuthorize(t, r,
		`{"accounts":"alice@hotmail.com----pw----11111111-1111-1111-1111-111111111111----tok"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("pasted credentials: %d, want %d", code, http.StatusBadRequest)
	}
}

// A locked store cannot start a batch: the passphrase gate is what turns "this
// session may write" into "this operator asked for these mailboxes now".
func TestAuthorizeRefusesALockedStore(t *testing.T) {
	_, r, _ := setupAuthorizeTest(t)

	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	if errInitialize := store.Initialize("master"); errInitialize != nil {
		t.Fatalf("initialize store: %v", errInitialize)
	}
	store.Lock()
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })

	code, _ := startAuthorize(t, r, `{"accounts":"alice@hotmail.com"}`)
	if code != http.StatusConflict {
		t.Fatalf("locked store: %d, want %d", code, http.StatusConflict)
	}
	if flows := listAuthorizes(t, r); len(flows) != 0 {
		t.Fatalf("a refused batch started %d flows", len(flows))
	}
}

func TestParseAuthorizeAccounts(t *testing.T) {
	accounts, errParse := parseAuthorizeAccounts("# seller header\nalice@hotmail.com\n\nALICE@hotmail.com\r\nbob@outlook.com\n")
	if errParse != nil {
		t.Fatalf("parse: %v", errParse)
	}
	if len(accounts) != 2 || accounts[0] != "alice@hotmail.com" || accounts[1] != "bob@outlook.com" {
		t.Fatalf("accounts = %v", accounts)
	}

	if _, errEmpty := parseAuthorizeAccounts("  \n# only a header\n"); errEmpty == nil {
		t.Fatal("an empty batch was accepted")
	}
	if _, errLine := parseAuthorizeAccounts("not-an-address"); errLine == nil {
		t.Fatal("a line without an address was accepted")
	}
}
