package email

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// The extractor's whole job is to refuse to guess. These cases pin the two
// halves of that: a labelled code is returned, and an unlabelled number is not.
func TestExtractCode(t *testing.T) {
	cases := []struct {
		name    string
		subject string
		body    string
		want    string
	}{
		{name: "keyword before the value", body: "Your verification code is 482913. It expires in 10 minutes.", want: "482913"},
		{name: "keyword with a colon", body: "验证码：731204，10 分钟内有效。", want: "731204"},
		{name: "value before the keyword", body: "905112 is your verification code.", want: "905112"},
		{name: "subject wins over body", subject: "Your code: 114477", body: "Order 2026 shipped on 2026-10-14.", want: "114477"},
		{name: "alphanumeric code with a digit", body: "Your login code: A7K2P9", want: "A7K2P9"},
		{name: "letters only is not a code", body: "Your verification code is PENDING", want: ""},
		{name: "an unlabelled number is not a code", body: "Order 12345678 shipped on 2026-10-14 for 199.00 CNY.", want: ""},
		{name: "nothing to find", subject: "Newsletter", body: "No numbers here at all.", want: ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ExtractCode(testCase.subject, testCase.body); got != testCase.want {
				t.Fatalf("ExtractCode(%q, %q) = %q, want %q", testCase.subject, testCase.body, got, testCase.want)
			}
		})
	}
}

// A folder name written in modified UTF-7 has to decode before it can be
// recognised, or a Chinese provider's junk folder is invisible to the junk
// filter and a forwarded code is never looked for.
func TestDecodeMailboxName(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain name is unchanged", raw: "INBOX", want: "INBOX"},
		{name: "encoded Chinese", raw: "&V4NXPpCuTvY-", want: "垃圾邮件"},
		// RFC 3501 §5.1.3's own example: it also exercises the "," escape that
		// modified UTF-7 uses where base64 would write "/".
		{name: "RFC 3501 example", raw: "~peter/mail/&U,BTFw-/&ZeVnLIqe-", want: "~peter/mail/台北/日本語"},
		{name: "ampersand escape", raw: "Tom&-Jerry", want: "Tom&Jerry"},
		{name: "mixed text and escape", raw: "Sent &V4NXPpCuTvY-", want: "Sent 垃圾邮件"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := decodeMailboxName(testCase.raw); got != testCase.want {
				t.Fatalf("decodeMailboxName(%q) = %q, want %q", testCase.raw, got, testCase.want)
			}
		})
	}
}

// INBOX is always read; a junk folder is read too, because a forwarded message
// is exactly what a provider sorts into junk.
func TestJunkMailboxes(t *testing.T) {
	got := junkMailboxes([]string{"INBOX", "Sent", "Junk", "&V4NXPpCuTvY-", "Archive"})
	want := []string{"INBOX", "Junk", "&V4NXPpCuTvY-"}
	if len(got) != len(want) {
		t.Fatalf("junkMailboxes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("junkMailboxes = %v, want %v", got, want)
		}
	}
}

// Forwarding rewrites To and leaves the original recipient in a trace header, so
// the match has to look at the trace headers too. This is the case that would
// silently fail if matching only read To.
func TestParseMailMatchesForwardedRecipient(t *testing.T) {
	raw := strings.Join([]string{
		"From: noreply@example.com",
		"To: yayueso@qq.com",
		"Delivered-To: abc123@ormnes.com",
		"Subject: Your code: 552211",
		"Date: Wed, 14 Oct 2026 10:00:00 +0800",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"Use 552211 to finish signing in.",
		"",
	}, "\r\n")
	parsed, errParse := parseMail([]byte(raw))
	if errParse != nil {
		t.Fatalf("parseMail: %v", errParse)
	}
	if !parsed.Mentions("abc123@ormnes.com") {
		t.Fatalf("forwarded recipient not matched; haystack = %q", parsed.haystack)
	}
	if !parsed.Mentions("yayueso@qq.com") {
		t.Fatalf("envelope recipient not matched; haystack = %q", parsed.haystack)
	}
	if parsed.Mentions("someone@else.com") {
		t.Fatalf("an unrelated address matched; haystack = %q", parsed.haystack)
	}
	if parsed.Code != "552211" {
		t.Fatalf("code = %q, want 552211", parsed.Code)
	}
	if parsed.From != "noreply@example.com" {
		t.Fatalf("from = %q", parsed.From)
	}
}

// fakeSession stands in for a live mailbox so the read logic can be exercised
// without a server.
type fakeSession struct {
	folders []string
	// mails is keyed by folder.
	mails map[string][]Mail
	// recentErr makes every folder read fail, which is how a server that rejects
	// the search looks to the provider.
	recentErr error
	// validity is the folder generation the fake reports, so a test can prove a
	// position is carried in a cursor and dropped when the folder is reset.
	validity uint32
	// dialled records the password the provider resolved, so a test can prove
	// the credential was read instead of assumed.
	dialled string
	closed  bool
}

func (f *fakeSession) Mailboxes(ctx context.Context) ([]string, error) { return f.folders, nil }

func (f *fakeSession) Recent(ctx context.Context, mailbox string, since time.Time, after FolderPosition, limit int) ([]Mail, uint32, error) {
	if f.recentErr != nil {
		return nil, 0, f.recentErr
	}
	mails := f.mails[mailbox]
	// Honour the position the way a real folder does: only messages past it.
	if after.UID > 0 {
		newer := make([]Mail, 0, len(mails))
		for _, mail := range mails {
			if mail.UID > after.UID {
				newer = append(newer, mail)
			}
		}
		mails = newer
	}
	if limit > 0 && len(mails) > limit {
		mails = mails[len(mails)-limit:]
	}
	return mails, f.validity, nil
}

func (f *fakeSession) Close() error {
	f.closed = true
	return nil
}

// writeChannels writes a channel document and returns its path.
func writeChannels(t *testing.T, channels ...supply.Channel) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "channels.json")
	document := supply.ChannelDocument{Version: 1, Channels: channels}
	raw, errMarshal := json.Marshal(document)
	if errMarshal != nil {
		t.Fatalf("marshal channels: %v", errMarshal)
	}
	if errWrite := os.WriteFile(path, raw, 0o600); errWrite != nil {
		t.Fatalf("write channels: %v", errWrite)
	}
	return path
}

// mailTo builds a message that mentions address.
func mailTo(address, code string, when time.Time) Mail {
	return Mail{
		Mailbox:  "INBOX",
		To:       []string{address},
		Subject:  "Your code: " + code,
		Text:     "Use " + code + " to sign in.",
		Date:     when,
		Code:     code,
		haystack: strings.ToLower(address),
	}
}

// imapChannel is one enabled catch-all mailbox.
//
// The category is what makes it a catch-all: the provider derives the usage from
// it, so the fixture states ownership rather than a usage flag.
func imapChannel(id, account, domain string, enabled bool) supply.Channel {
	return supply.Channel{
		ID:       id,
		Label:    id,
		Category: "self-built",
		Email: &supply.KindConfig{
			Enabled: enabled,
			Natures: []supply.Nature{supply.NatureIMAP},
			Connections: map[supply.Nature]supply.Connection{
				supply.NatureIMAP: {
					Endpoint: "imap.example.com:993",
					Account:  account,
					Domain:   domain,
				},
			},
		},
	}
}

// newProvider builds a provider whose mailbox is the fake session.
func newProvider(t *testing.T, session *fakeSession, channels ...supply.Channel) *ProviderImpl {
	t.Helper()
	provider, errNew := New(Config{
		ChannelsPath: writeChannels(t, channels...),
		Credential: func(name string) (string, error) {
			return "auth-code-for-" + name, nil
		},
		Dial: func(ctx context.Context, target Target) (Session, error) {
			session.dialled = target.Password
			return session, nil
		},
	})
	if errNew != nil {
		t.Fatalf("New: %v", errNew)
	}
	return provider
}

// A read returns the newest message addressed to the address, and ignores mail
// addressed to a different one in the same mailbox.
func TestProviderReadReturnsNewestMatch(t *testing.T) {
	base := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	session := &fakeSession{
		folders: []string{"INBOX"},
		mails: map[string][]Mail{
			"INBOX": {
				mailTo("other@ormnes.com", "111111", base),
				mailTo("abc@ormnes.com", "222222", base.Add(time.Minute)),
				mailTo("abc@ormnes.com", "333333", base.Add(2*time.Minute)),
			},
		},
	}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	message, errRead := provider.Read(context.Background(), "", "abc@ormnes.com")
	if errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if !message.Ready {
		t.Fatal("Ready = false, want true")
	}
	if message.Code != "333333" {
		t.Fatalf("code = %q, want the newest match 333333", message.Code)
	}
	// The entry is named after the mailbox, not after the channel: the password
	// belongs to the login, so the name is derived rather than configured.
	if want := "auth-code-for-" + supply.EmailCredentialName("box@qq.com"); session.dialled != want {
		t.Fatalf("dialled with %q, want the mailbox credential %q", session.dialled, want)
	}
	if !session.closed {
		t.Fatal("the session was not closed")
	}
}

// No mail yet is the ordinary state while a verification message is in flight,
// so it must not be reported as a failure.
func TestProviderReadWithoutMailIsNotAnError(t *testing.T) {
	session := &fakeSession{folders: []string{"INBOX"}, mails: map[string][]Mail{}}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	message, errRead := provider.Read(context.Background(), "", "abc@ormnes.com")
	if errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if message.Ready {
		t.Fatalf("Ready = true with no mail: %+v", message)
	}
}

// A credential that cannot be read is an error, not an empty inbox: the two mean
// different things to the operator.
func TestProviderReadWithoutCredentialIsAnError(t *testing.T) {
	provider, errNew := New(Config{
		ChannelsPath: writeChannels(t, imapChannel("qq", "box@qq.com", "ormnes.com", true)),
		Credential:   func(name string) (string, error) { return "", errors.New("the secret store is locked") },
		Dial:         func(ctx context.Context, target Target) (Session, error) { return &fakeSession{}, nil },
	})
	if errNew != nil {
		t.Fatalf("New: %v", errNew)
	}
	_, errRead := provider.Read(context.Background(), "", "abc@ormnes.com")
	if errRead == nil {
		t.Fatal("expected an error when the credential cannot be read")
	}
	if !errors.Is(errRead, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errRead)
	}
}

// A disabled channel is not a mailbox: it must not be read, and it must not make
// the kind look configured.
func TestProviderIgnoresDisabledChannels(t *testing.T) {
	session := &fakeSession{folders: []string{"INBOX"}, mails: map[string][]Mail{}}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", false))

	views, errViews := provider.TargetViews()
	if errViews != nil {
		t.Fatalf("TargetViews: %v", errViews)
	}
	if len(views) != 0 {
		t.Fatalf("TargetViews = %+v, want none", views)
	}
	status, errStatus := provider.Status(context.Background())
	if errStatus != nil {
		t.Fatalf("Status: %v", errStatus)
	}
	if status.Enabled {
		t.Fatal("Enabled = true with only a disabled channel")
	}
	_, errRead := provider.Read(context.Background(), "", "abc@ormnes.com")
	if !errors.Is(errRead, supply.ErrUnavailable) {
		t.Fatalf("Read err = %v, want ErrUnavailable", errRead)
	}
}

// A catch-all domain hands out a fresh address; a personal mailbox can only hand
// out itself.
func TestProviderGrab(t *testing.T) {
	session := &fakeSession{folders: []string{"INBOX"}, mails: map[string][]Mail{}}
	catchAll := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	identity, errGrab := catchAll.Grab(context.Background(), supply.GrabOptions{})
	if errGrab != nil {
		t.Fatalf("Grab: %v", errGrab)
	}
	if !strings.HasSuffix(identity.Address, "@ormnes.com") {
		t.Fatalf("address = %q, want a catch-all address on the configured domain", identity.Address)
	}
	if identity.Kind != supply.KindEmail {
		t.Fatalf("kind = %q", identity.Kind)
	}

	personal := imapChannel("personal", "me@qq.com", "", true)
	personal.Category = "third-party"
	personal.Email.Connections[supply.NatureIMAP] = supply.Connection{
		Endpoint: "imap.qq.com:993",
		Account:  "me@qq.com",
		Secret:   "mail-personal",
	}
	personalProvider := newProvider(t, session, personal)
	identity, errGrab = personalProvider.Grab(context.Background(), supply.GrabOptions{})
	if errGrab != nil {
		t.Fatalf("Grab personal: %v", errGrab)
	}
	if identity.Address != "me@qq.com" {
		t.Fatalf("address = %q, want the mailbox itself", identity.Address)
	}

	// An address no configured mailbox receives is not one this service handed
	// out, and the caller's right answer is a manual path.
	_, errUnknown := catchAll.Grab(context.Background(), supply.GrabOptions{Address: "x@elsewhere.com"})
	if !errors.Is(errUnknown, supply.ErrUnknownIdentity) {
		t.Fatalf("Grab unknown err = %v, want ErrUnknownIdentity", errUnknown)
	}
}

// A mailbox where every folder read failed is not an empty inbox. Reporting it
// as one would send the operator looking for mail that is sitting right there.
func TestProviderInboxReportsUnreadableFolders(t *testing.T) {
	session := &fakeSession{
		folders:   []string{"INBOX", "Junk"},
		recentErr: errors.New("search rejected"),
	}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	_, errInbox := provider.Inbox(context.Background(), "", 10)
	if errInbox == nil {
		t.Fatal("Inbox returned no error for a mailbox it could not read")
	}
	if !strings.Contains(errInbox.Error(), "search rejected") {
		t.Fatalf("err = %v, want the folder failure", errInbox)
	}
}

// An inbox listing without an address is the whole mailbox, newest first.
func TestProviderInboxListsNewestFirst(t *testing.T) {
	base := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	session := &fakeSession{
		folders: []string{"INBOX"},
		mails: map[string][]Mail{
			"INBOX": {
				mailTo("a@ormnes.com", "111111", base),
				mailTo("b@ormnes.com", "222222", base.Add(time.Hour)),
			},
		},
	}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	reading, errInbox := provider.Inbox(context.Background(), "", 10)
	if errInbox != nil {
		t.Fatalf("Inbox: %v", errInbox)
	}
	if len(reading.Mails) != 2 {
		t.Fatalf("got %d messages, want 2", len(reading.Mails))
	}
	if reading.Mails[0].Code != "222222" {
		t.Fatalf("first message code = %q, want the newest", reading.Mails[0].Code)
	}
	if reading.Mails[0].ChannelID != "qq" {
		t.Fatalf("channel = %q, want the mailbox that carried it", reading.Mails[0].ChannelID)
	}
	if len(reading.Mailboxes) != 1 {
		t.Fatalf("got %d mailbox summaries, want 1", len(reading.Mailboxes))
	}
	box := reading.Mailboxes[0]
	if box.ChannelID != "qq" || box.Count != 2 || box.Latest == nil || box.Latest.Code != "222222" {
		t.Fatalf("summary = %+v, want two messages with the newest first", box)
	}
	if reading.Window <= 0 {
		t.Fatalf("window = %v, want the read window", reading.Window)
	}
}

// A configured mailbox with nothing in it reports zero, not a missing row:
// "configured but nothing arrived" is an answer the channel row has to show.
func TestProviderInboxCountsPerMailbox(t *testing.T) {
	empty := &fakeSession{folders: []string{"INBOX"}, mails: map[string][]Mail{}}
	provider := newProvider(t, empty, imapChannel("quiet", "box@qq.com", "ormnes.com", true))
	reading, errInbox := provider.Inbox(context.Background(), "", 10)
	if errInbox != nil {
		t.Fatalf("Inbox: %v", errInbox)
	}
	if len(reading.Mailboxes) != 1 {
		t.Fatalf("got %d mailbox summaries, want 1", len(reading.Mailboxes))
	}
	if reading.Mailboxes[0].Count != 0 {
		t.Fatalf("count = %d, want 0", reading.Mailboxes[0].Count)
	}
	if reading.Mailboxes[0].Latest != nil {
		t.Fatal("an empty mailbox reported a latest message")
	}
	if reading.Mailboxes[0].Err != "" {
		t.Fatalf("err = %q, want an empty mailbox to read as a success", reading.Mailboxes[0].Err)
	}
}

// Covers is what decides whether a mailbox could receive an address at all.
func TestTargetCovers(t *testing.T) {
	catchAll := Target{Account: "box@qq.com", Domain: "ormnes.com"}
	if !catchAll.Covers("anything@ormnes.com") {
		t.Fatal("a catch-all mailbox must cover its domain")
	}
	if !catchAll.Covers("box@qq.com") {
		t.Fatal("a mailbox must cover its own address")
	}
	if catchAll.Covers("anything@elsewhere.com") {
		t.Fatal("a catch-all mailbox must not cover another domain")
	}
	if (Target{Account: "box@qq.com"}).Covers("anything@ormnes.com") {
		t.Fatal("a personal mailbox must not cover a domain")
	}
}

// The SASL blob is a wire contract: Microsoft reads exactly these bytes, so a
// stray separator or a missing trailing pair is an authentication failure that
// no amount of retrying fixes.
func TestXOAuth2ClientStart(t *testing.T) {
	mechanism, response, errStart := xoauth2Client{account: "box@outlook.com", token: "at-1"}.Start()
	if errStart != nil {
		t.Fatalf("Start: %v", errStart)
	}
	if mechanism != "XOAUTH2" {
		t.Fatalf("mechanism = %q, want XOAUTH2", mechanism)
	}
	want := "user=box@outlook.com\x01auth=Bearer at-1\x01\x01"
	if string(response) != want {
		t.Fatalf("response = %q, want %q", response, want)
	}
	if _, _, errEmpty := (xoauth2Client{account: "box@outlook.com"}).Start(); errEmpty == nil {
		t.Fatal("a session with no token must be refused before the exchange")
	}
}

// A refresh token is exchanged for an access token at the token endpoint. The
// request shape is the contract: the wrong grant type, a client id in a Basic
// header instead of the form, or the refresh token in the wrong field is refused
// by the server, and the failure looks like a bad credential.
func TestOAuth2AccessTokenExchangesRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if errForm := r.ParseForm(); errForm != nil {
			t.Errorf("ParseForm: %v", errForm)
		}
		if got := r.Form.Get("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", got)
		}
		if got := r.Form.Get("client_id"); got != "app-123" {
			t.Errorf("client_id = %q, want app-123", got)
		}
		if got := r.Form.Get("refresh_token"); got != "rt-1" {
			t.Errorf("refresh_token = %q, want rt-1", got)
		}
		// A public client has no secret, so nothing may be sent in a Basic
		// header: Microsoft reads the id from the form.
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want no header", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	token, expires, errToken := oauth2AccessToken(context.Background(), server.URL, "app-123", "rt-1", nil)
	if errToken != nil {
		t.Fatalf("oauth2AccessToken: %v", errToken)
	}
	if token != "at-1" {
		t.Fatalf("access token = %q, want at-1", token)
	}
	if remaining := time.Until(expires); remaining < 30*time.Minute {
		t.Fatalf("expiry is %v away, want about an hour", remaining)
	}
}

// A refused exchange has to say what the operator can do about it, and it must
// not repeat Microsoft's free-text description: that text can echo the request,
// and this string ends up in a channel row.
//
// The two refusals an operator actually meets are told apart: an expired refresh
// token needs a new mailbox, while a grant that never covered IMAP needs the
// other receiving method — and reporting the second as the first sends someone
// shopping for a mailbox that was fine all along.
func TestOAuth2AccessTokenReportsRefusal(t *testing.T) {
	cases := []struct {
		name        string
		description string
		want        string
	}{
		{
			name:        "expired",
			description: "AADSTS700082: The refresh token has expired due to inactivity.",
			want:        "expired or been revoked",
		},
		{
			name:        "no imap scope",
			description: "AADSTS70000: The request was denied because one or more scopes requested are unauthorized or expired.",
			want:        "choose Graph",
		},
	}
	for _, testCase := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"` + testCase.description + `"}`))
		}))

		_, _, errToken := oauth2AccessToken(context.Background(), server.URL, "app-123", "rt-1", nil)
		server.Close()
		if errToken == nil {
			t.Fatalf("%s: a refused exchange reported success", testCase.name)
		}
		if !strings.Contains(errToken.Error(), testCase.want) {
			t.Fatalf("%s: error = %q, want it to mention %q", testCase.name, errToken, testCase.want)
		}
		if strings.Contains(errToken.Error(), "AADSTS") {
			t.Fatalf("%s: error = %q, want the endpoint's description left out", testCase.name, errToken)
		}
	}
}

// A token exchange can succeed and still hand back a token the IMAP server will
// refuse, because without a named scope Microsoft returns whatever the grant
// covers. Catching that here is what turns a bare "AUTHENTICATE failed" into the
// one instruction that fixes it.
func TestOAuth2AccessTokenRejectsAGraphOnlyGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer","expires_in":3600,` +
			`"scope":"https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/User.ReadWrite"}`))
	}))
	defer server.Close()

	_, _, errToken := oauth2AccessToken(context.Background(), server.URL, "app-123", "rt-1", nil)
	if errToken == nil {
		t.Fatal("a Graph-only grant produced an IMAP token")
	}
	if !strings.Contains(errToken.Error(), "choose Graph") {
		t.Fatalf("error = %q, want it to point at the other receiving method", errToken)
	}
}

// A token that carries the IMAP scope, or one whose answer omits the scope list
// entirely, is accepted: the scope list is a diagnostic, not a gate.
func TestOAuth2AccessTokenAcceptsImapScopeOrNoScopeList(t *testing.T) {
	for _, body := range []string{
		`{"access_token":"at-1","token_type":"Bearer","expires_in":3600,"scope":"https://outlook.office.com/IMAP.AccessAsUser.All offline_access"}`,
		`{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		token, _, errToken := oauth2AccessToken(context.Background(), server.URL, "app-123", "rt-1", nil)
		server.Close()
		if errToken != nil {
			t.Fatalf("a usable token was refused: %v", errToken)
		}
		if token != "at-1" {
			t.Fatalf("access token = %q, want at-1", token)
		}
	}
}

// An OAuth2 mailbox reaches the provider through the same document as an IMAP
// one, and carries the method plus the application id. Its credential is the
// refresh token entry: handing that value to a LOGIN command would fail as a
// wrong password and hide the real cause.
func TestProviderTargetsOAuth2Mailbox(t *testing.T) {
	channel := supply.Channel{
		ID:       "outlook",
		Label:    "outlook",
		Category: "self-owned",
		Email: &supply.KindConfig{
			Enabled: true,
			Natures: []supply.Nature{supply.NatureOAuth2},
			Connections: map[supply.Nature]supply.Connection{
				supply.NatureOAuth2: {
					Endpoint: "outlook.office365.com:993",
					Account:  "box@outlook.com",
					ClientID: "app-123",
				},
			},
		},
	}
	session := &fakeSession{folders: []string{"INBOX"}, mails: map[string][]Mail{}}
	provider := newProvider(t, session, channel)

	targets, errTargets := provider.targets()
	if errTargets != nil {
		t.Fatalf("targets: %v", errTargets)
	}
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].Auth != AuthOAuth2 {
		t.Fatalf("auth = %q, want %q", targets[0].Auth, AuthOAuth2)
	}
	if targets[0].ClientID != "app-123" {
		t.Fatalf("client id = %q, want app-123", targets[0].ClientID)
	}
	if want := supply.EmailOAuth2CredentialName("box@outlook.com"); targets[0].SecretName != want {
		t.Fatalf("secret name = %q, want %q", targets[0].SecretName, want)
	}
	if _, errInbox := provider.Inbox(context.Background(), "", 10); errInbox != nil {
		t.Fatalf("Inbox: %v", errInbox)
	}
	if want := "auth-code-for-" + targets[0].SecretName; session.dialled != want {
		t.Fatalf("credential read = %q, want %q", session.dialled, want)
	}
}

// A cursor round-trips and refuses anything this build did not write, so a
// caller cannot poll with a position that nothing can honour.
func TestCursorRoundTrip(t *testing.T) {
	if got := EncodeCursor(Cursor{}); got != "" {
		t.Fatalf("zero cursor encoded to %q, want the empty string", got)
	}
	decoded, errEmpty := DecodeCursor("")
	if errEmpty != nil || !decoded.IsZero() {
		t.Fatalf("empty cursor = %+v, err = %v; want the zero cursor", decoded, errEmpty)
	}

	original := Cursor{
		Nature:  cursorNatureIMAP,
		Folders: []FolderPosition{{Folder: "INBOX", UIDValidity: 42, UID: 900}},
	}
	decoded, errDecode := DecodeCursor(EncodeCursor(original))
	if errDecode != nil {
		t.Fatalf("DecodeCursor: %v", errDecode)
	}
	if decoded.Nature != original.Nature {
		t.Fatalf("nature = %q, want %q", decoded.Nature, original.Nature)
	}
	if len(decoded.Folders) != 1 || decoded.Folders[0] != original.Folders[0] {
		t.Fatalf("positions = %+v, want %+v", decoded.Folders, original.Folders)
	}

	for _, bad := range []string{"900", "v1.!!!", "v1.eyJuIjoicG9wMyJ9"} {
		if _, errBad := DecodeCursor(bad); !errors.Is(errBad, ErrCursor) {
			t.Fatalf("DecodeCursor(%q) err = %v, want ErrCursor", bad, errBad)
		}
	}
}

// A second read continues from the position the first one handed back: the
// message already reported is not reported again, and only the new one is.
func TestProviderReadAfterContinuesFromCursor(t *testing.T) {
	base := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	first := mailTo("abc@ormnes.com", "111111", base)
	first.UID = 900
	second := mailTo("abc@ormnes.com", "222222", base.Add(time.Minute))
	second.UID = 901
	session := &fakeSession{
		folders:  []string{"INBOX"},
		mails:    map[string][]Mail{"INBOX": {first}},
		validity: 42,
	}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	answer, errRead := provider.ReadAfter(context.Background(), "abc@ormnes.com", "", 0)
	if errRead != nil {
		t.Fatalf("ReadAfter: %v", errRead)
	}
	if answer.Code != "111111" {
		t.Fatalf("code = %q, want 111111", answer.Code)
	}
	if answer.Cursor == "" {
		t.Fatal("no cursor was handed back, so the next read cannot continue")
	}

	// Nothing new: the position comes back unchanged and no code is invented.
	same, errSame := provider.ReadAfter(context.Background(), "abc@ormnes.com", answer.Cursor, 0)
	if errSame != nil {
		t.Fatalf("ReadAfter again: %v", errSame)
	}
	if same.Code != "" || len(same.Mails) != 0 {
		t.Fatalf("re-read reported %+v, want nothing new", same)
	}
	if same.Cursor != answer.Cursor {
		t.Fatalf("cursor moved without new mail: %q -> %q", answer.Cursor, same.Cursor)
	}

	// A new message arrives; only it is reported.
	session.mails["INBOX"] = []Mail{first, second}
	next, errNext := provider.ReadAfter(context.Background(), "abc@ormnes.com", answer.Cursor, 0)
	if errNext != nil {
		t.Fatalf("ReadAfter after arrival: %v", errNext)
	}
	if next.Code != "222222" {
		t.Fatalf("code = %q, want the new 222222", next.Code)
	}
	if len(next.Mails) != 1 || next.Mails[0].UID != 901 {
		t.Fatalf("mails = %+v, want only UID 901", next.Mails)
	}
	if next.Reset {
		t.Fatal("Reset = true while the folder validity did not change")
	}
}

// A folder whose generation changed invalidates every stored UID, so the read
// starts over from the window and says so instead of silently skipping mail.
func TestProviderReadAfterReportsFolderReset(t *testing.T) {
	base := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	mail := mailTo("abc@ormnes.com", "333333", base)
	mail.UID = 5
	session := &fakeSession{
		folders:  []string{"INBOX"},
		mails:    map[string][]Mail{"INBOX": {mail}},
		validity: 42,
	}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	stale := EncodeCursor(Cursor{
		Nature:  cursorNatureIMAP,
		Folders: []FolderPosition{{Folder: "INBOX", UIDValidity: 7, UID: 4}},
	})
	answer, errRead := provider.ReadAfter(context.Background(), "abc@ormnes.com", stale, 0)
	if errRead != nil {
		t.Fatalf("ReadAfter: %v", errRead)
	}
	if !answer.Reset {
		t.Fatal("Reset = false, want true when the folder generation changed")
	}
	if answer.Code != "333333" {
		t.Fatalf("code = %q, want the message read from the window", answer.Code)
	}
}

// A read that names an address no configured mailbox receives is not a retry: it
// is an identity this service never handed out.
func TestProviderReadAfterUnknownAddress(t *testing.T) {
	session := &fakeSession{folders: []string{"INBOX"}, mails: map[string][]Mail{}}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	_, errRead := provider.ReadAfter(context.Background(), "x@elsewhere.com", "", 0)
	if !errors.Is(errRead, supply.ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", errRead)
	}
}

// A handout narrowed to one kind of source must not fall back to the other: a
// caller that asked for a bought mailbox did not ask for an alias.
func TestProviderGrabNarrowsByUsage(t *testing.T) {
	session := &fakeSession{folders: []string{"INBOX"}, mails: map[string][]Mail{}}
	catchAll := imapChannel("qq", "box@qq.com", "ormnes.com", true)
	personal := imapChannel("personal", "me@qq.com", "", true)
	personal.Category = "third-party"
	personal.Email.Connections[supply.NatureIMAP] = supply.Connection{
		Endpoint: "imap.qq.com:993",
		Account:  "me@qq.com",
		Secret:   "mail-personal",
	}
	provider := newProvider(t, session, catchAll, personal)

	identity, errPersonal := provider.Grab(context.Background(), supply.GrabOptions{Usage: "personal"})
	if errPersonal != nil {
		t.Fatalf("Grab personal: %v", errPersonal)
	}
	if identity.Address != "me@qq.com" {
		t.Fatalf("address = %q, want the bought mailbox", identity.Address)
	}

	identity, errAlias := provider.Grab(context.Background(), supply.GrabOptions{Usage: "self-domain"})
	if errAlias != nil {
		t.Fatalf("Grab self-domain: %v", errAlias)
	}
	if !strings.HasSuffix(identity.Address, "@ormnes.com") {
		t.Fatalf("address = %q, want an alias on the catch-all domain", identity.Address)
	}

	if _, errNone := provider.Grab(context.Background(), supply.GrabOptions{Usage: "reserved"}); !errors.Is(errNone, supply.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable for a kind of source nothing serves", errNone)
	}
}

// The gate bounds how many mailboxes are open at once, and a release gives the
// slot back exactly once: a caller that defers a release and also calls it on an
// error path must not free a slot someone else is holding.
func TestDialGateBoundsTotal(t *testing.T) {
	gate := newDialGate(1, 1)
	ctx := context.Background()

	release, errAcquire := gate.acquire(ctx, "imap.example.com")
	if errAcquire != nil {
		t.Fatalf("acquire: %v", errAcquire)
	}
	// A second mailbox cannot be opened while the only slot is held. The bound
	// is a bound: the wait ends when the caller's context does.
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, errSecond := gate.acquire(short, "imap.example.com"); errSecond == nil {
		t.Fatal("a second mailbox was opened while the bound was one")
	}

	release()
	// Releasing twice is not a second release.
	release()

	again, errAgain := gate.acquire(ctx, "imap.example.com")
	if errAgain != nil {
		t.Fatalf("acquire after release: %v", errAgain)
	}
	again()
}

// The per-host bound is per host: one busy server does not consume the slots a
// different server's mailbox needs.
func TestDialGateSeparatesHosts(t *testing.T) {
	gate := newDialGate(2, 1)
	ctx := context.Background()

	first, errFirst := gate.acquire(ctx, "imap.a.example")
	if errFirst != nil {
		t.Fatalf("acquire a: %v", errFirst)
	}
	defer first()

	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	second, errSecond := gate.acquire(short, "imap.b.example")
	if errSecond != nil {
		t.Fatalf("a different host was refused while another held its slot: %v", errSecond)
	}
	second()
}

// An unconfigured bound means no bound, which is what an operator setting zero
// asked for: the gate must never turn a missing setting into a refusal.
func TestDialGateWithoutLimitsAlwaysAdmits(t *testing.T) {
	gate := newDialGate(0, 0)
	releases := make([]func(), 0, 32)
	for range 32 {
		release, errAcquire := gate.acquire(context.Background(), "imap.example.com")
		if errAcquire != nil {
			t.Fatalf("acquire: %v", errAcquire)
		}
		releases = append(releases, release)
	}
	for _, release := range releases {
		release()
	}
}

// The panel's inbox read is a channel view, not a sweep of every address the
// service holds. Opening a thousand bought mailboxes to fill one view would cost
// a thousand connections and say nothing a channel row could show.
func TestProviderInboxReadsChannelMailboxesOnly(t *testing.T) {
	base := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	session := &fakeSession{
		folders: []string{"INBOX"},
		mails:   map[string][]Mail{"INBOX": {mailTo("box@qq.com", "111111", base)}},
	}
	pool := supply.NewPool()
	pool.AttachMailbox(supply.KindEmail, "bought@outlook.com", supply.Mailbox{
		Nature:   supply.NatureGraph,
		Endpoint: "graph.microsoft.com",
		ClientID: "app-1",
	}, base.Unix())

	provider, errNew := New(Config{
		ChannelsPath: writeChannels(t, imapChannel("qq", "box@qq.com", "ormnes.com", true)),
		Credential:   func(name string) (string, error) { return "secret-for-" + name, nil },
		Dial: func(ctx context.Context, target Target) (Session, error) {
			session.dialled = target.Account
			return session, nil
		},
		Pool: pool,
	})
	if errNew != nil {
		t.Fatalf("New: %v", errNew)
	}

	reading, errInbox := provider.Inbox(context.Background(), "", 5)
	if errInbox != nil {
		t.Fatalf("Inbox: %v", errInbox)
	}
	if len(reading.Mailboxes) != 1 {
		t.Fatalf("read %d mailboxes, want only the channel's one", len(reading.Mailboxes))
	}
	if reading.Mailboxes[0].Account != "box@qq.com" {
		t.Fatalf("mailbox = %q, want the channel's", reading.Mailboxes[0].Account)
	}
	if session.dialled != "box@qq.com" {
		t.Fatalf("opened %q, want the channel's mailbox only", session.dialled)
	}

	// An address no mailbox receives is not "no mail": nothing was read, and
	// saying otherwise would hide the address behind a convincing empty answer.
	if _, errUnknown := provider.Inbox(context.Background(), "x@elsewhere.com", 5); !errors.Is(errUnknown, supply.ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", errUnknown)
	}
}

// An address that carries its own credential is probed through the mailbox that
// receives it: that mailbox is the only thing that can say whether the address
// can be used right now.
func TestProviderProbeAddressOpensCoveringMailbox(t *testing.T) {
	session := &fakeSession{folders: []string{"INBOX", "Junk"}}
	provider := newProvider(t, session, imapChannel("qq", "box@qq.com", "ormnes.com", true))

	detail, errProbe := provider.ProbeAddress(context.Background(), "abc@ormnes.com")
	if errProbe != nil {
		t.Fatalf("ProbeAddress: %v", errProbe)
	}
	if detail != "connected, 2 mailboxes" {
		t.Fatalf("detail = %q, want the folder count", detail)
	}
	// The credential was read from the store rather than assumed, and the
	// session was closed again: a probe that left a mailbox open would leak a
	// connection per page load.
	if strings.TrimSpace(session.dialled) == "" {
		t.Fatal("the probe dialled without a credential")
	}
	if !session.closed {
		t.Fatal("the probe left the mailbox open")
	}

	// An address no mailbox receives cannot be reached, and the answer says so
	// instead of reporting a connection that was never attempted.
	if _, errUnknown := provider.ProbeAddress(context.Background(), "x@elsewhere.com"); !errors.Is(errUnknown, supply.ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", errUnknown)
	}
}

// A credential that cannot be read is not an unreachable mailbox: the probe
// reports it as unready so the panel does not send the operator looking for a
// network fault.
func TestProviderProbeAddressReportsUnreadableCredential(t *testing.T) {
	provider, errNew := New(Config{
		ChannelsPath: writeChannels(t, imapChannel("qq", "box@qq.com", "ormnes.com", true)),
		Credential:   func(string) (string, error) { return "", errors.New("the secret store is locked") },
		Dial: func(context.Context, Target) (Session, error) {
			t.Fatal("a probe with no readable credential must not dial")
			return nil, nil
		},
	})
	if errNew != nil {
		t.Fatalf("New: %v", errNew)
	}
	if _, errProbe := provider.ProbeAddress(context.Background(), "abc@ormnes.com"); !errors.Is(errProbe, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errProbe)
	}
}
