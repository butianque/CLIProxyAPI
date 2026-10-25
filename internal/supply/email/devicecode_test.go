package email

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// The device authorization is the only way to obtain a refresh token without
// already holding one, so the request it sends is the contract: a wrong scope
// silently returns a token that cannot read mail, and a missing offline_access
// returns one that dies within the hour.
func TestRequestDeviceCodeAsksForReadIdentityAndOffline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if errForm := r.ParseForm(); errForm != nil {
			t.Errorf("ParseForm: %v", errForm)
		}
		if got := r.Form.Get("client_id"); got != "app-123" {
			t.Errorf("client_id = %q, want app-123", got)
		}
		scope := r.Form.Get("scope")
		for _, want := range []string{"Mail.Read", "User.Read", "offline_access"} {
			if !strings.Contains(scope, want) {
				t.Errorf("scope = %q, want it to name %s", scope, want)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"dc-1","user_code":"Z5UENLHM",` +
			`"verification_uri":"https://www.microsoft.com/link","expires_in":900,"interval":5}`))
	}))
	defer server.Close()

	authorization, errRequest := RequestDeviceCode(context.Background(), server.URL, "app-123", deviceCodeScope, nil)
	if errRequest != nil {
		t.Fatalf("RequestDeviceCode: %v", errRequest)
	}
	if authorization.UserCode != "Z5UENLHM" {
		t.Fatalf("user code = %q", authorization.UserCode)
	}
	if authorization.VerifyURL != "https://www.microsoft.com/link" {
		t.Fatalf("verification url = %q", authorization.VerifyURL)
	}
	if authorization.ExpiresIn != 15*time.Minute {
		t.Fatalf("expiry = %v, want 15m", authorization.ExpiresIn)
	}
	if authorization.Interval != 5*time.Second {
		t.Fatalf("interval = %v, want 5s", authorization.Interval)
	}
}

// The three answers that are not failures have to be told apart from a real one:
// pending means keep waiting, slow_down means wait longer, and anything else ends
// the flow.
func TestPollDeviceTokenTellsTheWaitingAnswersApart(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		status int
		want   error
		detail string
	}{
		{
			name:   "pending",
			body:   `{"error":"authorization_pending"}`,
			status: http.StatusBadRequest,
			want:   ErrDevicePending,
		},
		{
			name:   "slow down",
			body:   `{"error":"slow_down"}`,
			status: http.StatusBadRequest,
			want:   ErrDeviceSlowDown,
		},
		{
			name:   "expired",
			body:   `{"error":"expired_token"}`,
			status: http.StatusBadRequest,
			detail: "expired",
		},
		{
			name:   "declined",
			body:   `{"error":"access_denied","error_description":"AADSTS70000: the user declined"}`,
			status: http.StatusBadRequest,
			detail: "declined",
		},
	}
	for _, testCase := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(testCase.status)
			_, _ = w.Write([]byte(testCase.body))
		}))
		_, errPoll := PollDeviceToken(context.Background(), server.URL, "app-123", "dc-1", nil)
		server.Close()
		if errPoll == nil {
			t.Fatalf("%s: a failed poll reported success", testCase.name)
		}
		if testCase.want != nil && errPoll != testCase.want {
			t.Fatalf("%s: error = %v, want %v", testCase.name, errPoll, testCase.want)
		}
		if testCase.detail != "" && !strings.Contains(errPoll.Error(), testCase.detail) {
			t.Fatalf("%s: error = %q, want it to mention %q", testCase.name, errPoll, testCase.detail)
		}
		// Microsoft's free-text description can echo the request, and this
		// string reaches an operator's screen.
		if strings.Contains(errPoll.Error(), "AADSTS") {
			t.Fatalf("%s: error = %q, want the description left out", testCase.name, errPoll)
		}
	}
}

// A completed sign-in has to hand back the refresh token: it is the whole reason
// the flow exists, and a missing one means the authorization never carried
// offline_access.
func TestPollDeviceTokenReturnsTheRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if errForm := r.ParseForm(); errForm != nil {
			t.Errorf("ParseForm: %v", errForm)
		}
		if got := r.Form.Get("grant_type"); got != deviceCodeGrantType {
			t.Errorf("grant_type = %q, want %q", got, deviceCodeGrantType)
		}
		if got := r.Form.Get("device_code"); got != "dc-1" {
			t.Errorf("device_code = %q, want dc-1", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	token, errPoll := PollDeviceToken(context.Background(), server.URL, "app-123", "dc-1", nil)
	if errPoll != nil {
		t.Fatalf("PollDeviceToken: %v", errPoll)
	}
	if token.RefreshToken != "rt-1" {
		t.Fatalf("refresh token = %q, want rt-1", token.RefreshToken)
	}
	if remaining := time.Until(token.Expires); remaining < 30*time.Minute {
		t.Fatalf("expiry is %v away, want about an hour", remaining)
	}
}

// An answer with no refresh token is a failure worth naming: the sign-in worked
// but the grant cannot outlive the access token, and the operator has to repeat
// it rather than wonder why the mailbox stopped working tomorrow.
func TestPollDeviceTokenRejectsAnAnswerWithoutARefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","expires_in":3600}`))
	}))
	defer server.Close()

	_, errPoll := PollDeviceToken(context.Background(), server.URL, "app-123", "dc-1", nil)
	if errPoll == nil {
		t.Fatal("an answer with no refresh token was accepted")
	}
	if !strings.Contains(errPoll.Error(), "offline_access") {
		t.Fatalf("error = %q, want it to name the missing grant", errPoll)
	}
}

// The endpoint never says which mailbox was signed in to, so this call is the
// only thing that can tell "the account asked for" from "the account used". Both
// addresses it reports are needed: a personal account is spelled one way in mail
// and another in its login name.
func TestVerifyAccountReadsBothAddresses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/v1.0/me" {
			t.Errorf("path = %q, want /v1.0/me", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer at-1" {
			t.Errorf("Authorization = %q, want the bearer token", got)
		}
		if got := r.URL.Query().Get("$select"); !strings.Contains(got, "mail") || !strings.Contains(got, "userPrincipalName") {
			t.Errorf("$select = %q, want both addresses", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mail":"name@hotmail.com","userPrincipalName":"name@outlook.com"}`))
	}))
	defer server.Close()

	identity, errVerify := VerifyAccount(context.Background(), server.URL+"/v1.0", "at-1", nil)
	if errVerify != nil {
		t.Fatalf("VerifyAccount: %v", errVerify)
	}
	addresses := identity.Addresses()
	if len(addresses) != 2 || addresses[0] != "name@hotmail.com" || addresses[1] != "name@outlook.com" {
		t.Fatalf("addresses = %v", addresses)
	}
}

// An account that reports no address cannot be attributed to the request, so it
// must not be treated as a match.
func TestVerifyAccountRefusesAnAnswerWithoutAnAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mail":null,"userPrincipalName":""}`))
	}))
	defer server.Close()

	if _, errVerify := VerifyAccount(context.Background(), server.URL, "at-1", nil); errVerify == nil {
		t.Fatal("an identity with no address was accepted")
	}
}

// The write-back is what keeps a mailbox readable without an operator visiting
// it: Microsoft's refresh tokens expire 90 days after their last use, and only
// the newest value is honoured.
func TestPersistRefreshTokenWritesOnlyARotation(t *testing.T) {
	store := unlockedTestStore(t)
	entry := "email-oauth2-name@hotmail.com"
	if errSet := store.Set(entry, "rt-old"); errSet != nil {
		t.Fatalf("seed store: %v", errSet)
	}

	// The endpoint usually hands the same token back; writing it would be a
	// pointless store write on every read.
	persistRefreshToken(entry, "rt-old", "rt-old")
	if value, _ := store.Get(entry); value != "rt-old" {
		t.Fatalf("stored token = %q, want it untouched", value)
	}

	persistRefreshToken(entry, "rt-old", "rt-new")
	value, errGet := store.Get(entry)
	if errGet != nil {
		t.Fatalf("read stored token: %v", errGet)
	}
	if value != "rt-new" {
		t.Fatalf("stored token = %q, want the rotated value", value)
	}

	// A mailbox supplied directly (a probe) has no entry to write to, and an
	// empty answer carries no rotation.
	persistRefreshToken("", "rt-new", "rt-newer")
	persistRefreshToken(entry, "rt-new", "")
	if value, _ := store.Get(entry); value != "rt-new" {
		t.Fatalf("stored token = %q, want rt-new", value)
	}
}

// unlockedTestStore gives a test a real, open secret store. The write-back is a
// store operation, so faking the store would test nothing.
func unlockedTestStore(t *testing.T) *secretstore.Store {
	t.Helper()
	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	if errInitialize := store.Initialize("master"); errInitialize != nil {
		t.Fatalf("initialize store: %v", errInitialize)
	}
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })
	return store
}
