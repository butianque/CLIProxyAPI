package email

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A Graph message must land in the same shape the IMAP parser produces, because
// everything downstream — address matching, code extraction, the inbox listing —
// is written against that shape and knows nothing about the transport.
func TestGraphMessageReducesToMail(t *testing.T) {
	message := graphMessage{
		Subject:      "Your code is 483920",
		ReceivedTime: "2026-10-18T22:01:09Z",
		From:         &graphRecipient{EmailAddress: graphEmailAddress{Address: "no-reply@service.example"}},
		ToRecipients: []graphRecipient{{EmailAddress: graphEmailAddress{Address: "box@outlook.com"}}},
		// The cc entry repeats the to entry in a different case: a recipient list
		// is a set of addresses, not a count of headers.
		CcRecipients: []graphRecipient{{EmailAddress: graphEmailAddress{Address: "BOX@outlook.com"}}},
		Body:         graphBody{ContentType: "text", Content: "Use 483920 to sign in."},
		Headers: []graphHeader{
			{Name: "X-Original-To", Value: "alias@forward.example"},
			{Name: "Received", Value: "by mx.example with SMTP"},
		},
	}

	mail := message.toMail("Inbox")

	if mail.Mailbox != "Inbox" {
		t.Fatalf("mailbox = %q, want Inbox", mail.Mailbox)
	}
	if mail.From != "no-reply@service.example" {
		t.Fatalf("from = %q", mail.From)
	}
	if len(mail.To) != 2 || mail.To[0] != "box@outlook.com" || mail.To[1] != "alias@forward.example" {
		t.Fatalf("to = %v, want the two distinct addresses", mail.To)
	}
	if mail.Code != "483920" {
		t.Fatalf("code = %q, want 483920", mail.Code)
	}
	if !mail.Date.Equal(time.Date(2026, 10, 18, 22, 1, 9, 0, time.UTC)) {
		t.Fatalf("date = %v", mail.Date)
	}
	// A forward rewrites To and leaves the original recipient in a trace header,
	// so the match has to see the header too.
	if !mail.Mentions("alias@forward.example") {
		t.Fatalf("a forwarded recipient is not matched; haystack = %q", mail.haystack)
	}
	if mail.Mentions("someone-else@example.com") {
		t.Fatalf("an unrelated address matched; haystack = %q", mail.haystack)
	}
}

// Graph answers an HTML body when the preference is ignored, and a code has to
// be readable from it either way.
func TestGraphHTMLBodyIsReducedToText(t *testing.T) {
	message := graphMessage{
		Subject:      "Verification",
		ReceivedTime: "2026-10-18T22:01:09Z",
		Body:         graphBody{ContentType: "html", Content: "<p>Your code is <b>778899</b></p>"},
	}

	mail := message.toMail("Inbox")

	if strings.Contains(mail.Text, "<") {
		t.Fatalf("html survived as markup: %q", mail.Text)
	}
	if mail.Code != "778899" {
		t.Fatalf("code = %q, want 778899", mail.Code)
	}
}

// Graph accepts a well-known folder name in the path and nothing else: any other
// folder has to be resolved to its id, which is what the cached listing is for.
func TestGraphFolderTargetResolution(t *testing.T) {
	session := &graphSession{folders: map[string]string{"receipts 2026": "AAMk-receipts"}}
	cases := []struct {
		folder string
		want   string
	}{
		{"INBOX", "inbox"},
		{"Inbox", "inbox"},
		{"Junk Email", "junkemail"},
		{"", "inbox"},
		{"Receipts 2026", "AAMk-receipts"},
	}
	for _, testCase := range cases {
		got, errTarget := session.folderTarget(context.Background(), testCase.folder)
		if errTarget != nil {
			t.Fatalf("folderTarget(%q): %v", testCase.folder, errTarget)
		}
		if got != testCase.want {
			t.Errorf("folderTarget(%q) = %q, want %q", testCase.folder, got, testCase.want)
		}
	}

	if _, errTarget := session.folderTarget(context.Background(), "no such folder"); errTarget == nil {
		t.Fatal("an unknown folder resolved to something")
	}
}

// A grant narrower than the application's declaration refuses ".default" and
// accepts the permissions it does carry. Without the second attempt the mailbox
// reads as unreachable while its credential is perfectly good, which is exactly
// how a mailbox that signed in successfully ends up shown as offline.
func TestGraphTokenFallsBackToTheScopeTheGrantCarries(t *testing.T) {
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if errForm := r.ParseForm(); errForm != nil {
			t.Errorf("ParseForm: %v", errForm)
		}
		scope := r.Form.Get("scope")
		asked = append(asked, scope)
		w.Header().Set("Content-Type", "application/json")
		if scope == graphScope {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"AADSTS70011: scope refused"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at-1","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	token, errMint := mintGraphToken(context.Background(), server.URL, "app-123", "rt-1", nil)
	if errMint != nil {
		t.Fatalf("mintGraphToken: %v", errMint)
	}
	if token.access != "at-1" {
		t.Fatalf("access token = %q, want at-1", token.access)
	}
	if len(asked) != 2 {
		t.Fatalf("scopes asked = %v, want two attempts", asked)
	}
	if asked[0] != graphScope {
		t.Fatalf("first scope = %q, want %q", asked[0], graphScope)
	}
	// The second attempt must be a scope the sign-in itself could have granted,
	// otherwise a narrower grant is refused a second time for the same reason.
	if asked[1] != deviceCodeScope {
		t.Fatalf("second scope = %q, want %q", asked[1], deviceCodeScope)
	}
}

// A dead credential answers the same way whatever the scope says, so retrying it
// spends requests on an answer that cannot change — and enough of those is how a
// mailbox gets throttled.
func TestGraphTokenDoesNotRetryADeadCredential(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"AADSTS70008: expired"}`))
	}))
	defer server.Close()

	_, errMint := mintGraphToken(context.Background(), server.URL, "app-123", "rt-1", nil)
	if errMint == nil {
		t.Fatal("a dead credential was accepted")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if !strings.Contains(errMint.Error(), "expired or been revoked") {
		t.Fatalf("error = %q, want it to name the dead credential", errMint)
	}
	// The description is free text that can echo the request, and this sentence
	// reaches an operator's screen.
	if strings.Contains(errMint.Error(), "AADSTS") {
		t.Fatalf("error = %q, want the description left out", errMint)
	}
}

// The sub-code is what separates "consent was never granted" from "the client
// type is wrong", and the operator-facing sentence cannot carry it.
func TestAADSTSCodeIsReadOutOfTheDescription(t *testing.T) {
	cases := []struct {
		name        string
		description string
		want        string
	}{
		{"present", "AADSTS65001: The user has not consented.", "AADSTS65001"},
		{"mid sentence", "error AADSTS70011 while parsing", "AADSTS70011"},
		{"absent", "invalid scope", ""},
		{"marker without digits", "AADSTS something", ""},
		{"empty", "", ""},
	}
	for _, testCase := range cases {
		if got := aadstsCode(testCase.description); got != testCase.want {
			t.Errorf("%s: aadstsCode = %q, want %q", testCase.name, got, testCase.want)
		}
	}
}
