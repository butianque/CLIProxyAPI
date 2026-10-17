package supply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelNormalizePhoneOnly(t *testing.T) {
	c := Channel{
		Label:    "Haozhuma",
		Category: "third-party",
		Phone: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureAPI},
			Connections: map[Nature]Connection{
				NatureAPI: {Endpoint: "https://api.example.com", Account: "user", Secret: "haozhuma"},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if got.Category != "third-party" {
		t.Errorf("category = %q, want third-party", got.Category)
	}
	if got.Phone == nil {
		t.Fatal("phone is nil")
	}
	if got.Email != nil {
		t.Error("email should be nil")
	}
}

func TestChannelNormalizeBothKinds(t *testing.T) {
	c := Channel{
		Label: "Multi Platform",
		Phone: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureAPI, NatureWeb},
			Connections: map[Nature]Connection{
				NatureAPI: {Endpoint: "https://api.example.com", Secret: "api-key"},
				NatureWeb: {Account: "admin", Secret: "web-key"},
			},
		},
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Secret: "imap-pass"},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if got.Phone == nil || got.Email == nil {
		t.Fatal("both phone and email must be non-nil")
	}
	if len(got.Phone.Natures) != 2 {
		t.Errorf("phone natures = %d, want 2", len(got.Phone.Natures))
	}
	if len(got.Email.Natures) != 1 {
		t.Errorf("email natures = %d, want 1", len(got.Email.Natures))
	}
}

func TestChannelNormalizeNoKind(t *testing.T) {
	c := Channel{Label: "Empty"}
	_, err := c.Normalize()
	if err == nil {
		t.Fatal("expected error for channel with no kind")
	}
}

func TestChannelNormalizeImapSelfDomain(t *testing.T) {
	// The category is the only place that says "a domain I built"; the usage
	// follows from it, so a caller that sends neither still lands on self-domain.
	c := Channel{
		Label:    "ormnes.com",
		Category: "self-built",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Secret: "imap-pass", Domain: "ormnes.com"},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	conn := got.Email.Connections[NatureIMAP]
	if conn.Usage != "self-domain" {
		t.Errorf("usage = %q, want self-domain", conn.Usage)
	}
	if conn.Domain != "ormnes.com" {
		t.Errorf("domain = %q, want ormnes.com", conn.Domain)
	}
}

// A mailbox of mine is mine, but it is still one address: only a domain I built
// can hand out new ones. This is the difference between self-owned and
// self-built, and it is the difference the panel shows as two categories.
func TestChannelNormalizeImapOwnMailboxIsPersonal(t *testing.T) {
	c := Channel{
		Label:    "my-qq",
		Category: "self-owned",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Secret: "imap-pass"},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	conn := got.Email.Connections[NatureIMAP]
	if conn.Usage != "personal" {
		t.Errorf("usage = %q, want personal", conn.Usage)
	}
	if conn.Domain != "" {
		t.Errorf("domain = %q, want empty", conn.Domain)
	}
}

// The same mailbox cannot claim a domain just because it is self-owned: a domain
// is only meaningful where addresses are minted on it.
func TestChannelNormalizeImapOwnMailboxRejectsDomain(t *testing.T) {
	c := Channel{
		Label:    "my-qq",
		Category: "self-owned",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Domain: "ormnes.com"},
			},
		},
	}
	if _, err := c.Normalize(); err == nil {
		t.Fatal("expected error for a domain on a self-owned mailbox")
	}
}

func TestChannelNormalizeImapSelfDomainNoDomain(t *testing.T) {
	c := Channel{
		Label:    "bad",
		Category: "self-built",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com"},
			},
		},
	}
	_, err := c.Normalize()
	if err == nil {
		t.Fatal("expected error for a catch-all mailbox without a domain")
	}
}

func TestChannelNormalizeImapPersonalMailbox(t *testing.T) {
	// A third-party mailbox is one address, so any usage the caller sent is
	// replaced rather than trusted.
	c := Channel{
		Label: "qq",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Secret: "imap-pass", Usage: "self-domain"},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	conn := got.Email.Connections[NatureIMAP]
	if conn.Usage != "personal" {
		t.Errorf("usage = %q, want personal", conn.Usage)
	}
	if conn.Domain != "" {
		t.Errorf("domain = %q, want empty", conn.Domain)
	}
}

// A domain typed with the at-sign is the same domain. Stored as typed it could
// never match anything: the catch-all check appends "@" to it and the mint path
// builds "local@" + it, so "configured" would silently mean "never finds a code".
func TestChannelNormalizeImapDomainAcceptsAtSign(t *testing.T) {
	c := Channel{
		Label:    "ormnes.com",
		Category: "self-built",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Domain: " @Ormnes.com. "},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if domain := got.Email.Connections[NatureIMAP].Domain; domain != "ormnes.com" {
		t.Errorf("domain = %q, want ormnes.com", domain)
	}
}

// A whole address in the domain field is a different mistake, and it fails the
// same way, so it is refused instead of stored.
func TestChannelNormalizeImapDomainRejectsAddress(t *testing.T) {
	c := Channel{
		Label:    "bad",
		Category: "self-built",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Domain: "box@ormnes.com"},
			},
		},
	}
	if _, err := c.Normalize(); err == nil {
		t.Fatal("expected error for an address in the domain field")
	}
}

func TestChannelNormalizeImapDomainWithoutCatchAllCategory(t *testing.T) {
	// A domain on a channel that cannot catch all of it is a contradiction, not
	// something to drop silently: the operator typed it, and the answer is to
	// change the category rather than to lose the domain.
	c := Channel{
		Label:    "contradiction",
		Category: "third-party",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Domain: "ormnes.com"},
			},
		},
	}
	_, err := c.Normalize()
	if err == nil {
		t.Fatal("expected error for a domain on a non catch-all channel")
	}
}

func TestChannelNormalizeImapOnPhone(t *testing.T) {
	c := Channel{
		Label: "bad",
		Phone: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {},
			},
		},
	}
	_, err := c.Normalize()
	if err == nil {
		t.Fatal("expected error: IMAP cannot serve phone")
	}
}

func TestChannelNormalizeInvalidCategory(t *testing.T) {
	c := Channel{
		Label:    "bad",
		Category: "unknown",
		Phone: &KindConfig{
			Enabled:     true,
			Natures:     []Nature{NatureAPI},
			Connections: map[Nature]Connection{NatureAPI: {}},
		},
	}
	_, err := c.Normalize()
	if err == nil {
		t.Fatal("expected error for invalid category")
	}
}

func TestChannelNormalizeCategoryDefault(t *testing.T) {
	c := Channel{
		Label: "no-cat",
		Phone: &KindConfig{
			Enabled:     true,
			Natures:     []Nature{NatureAPI},
			Connections: map[Nature]Connection{NatureAPI: {}},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if got.Category != "third-party" {
		t.Errorf("category = %q, want third-party", got.Category)
	}
}

// A connection address written without a scheme is completed to https when the
// channel is written, so the stored value is a URL that can actually be used.
// An explicit scheme is respected and a blank address stays blank.
func TestChannelNormalizeConnectionEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "no scheme", endpoint: "api.haozhuma.com", want: "https://api.haozhuma.com"},
		{name: "no scheme with trailing slash", endpoint: "api.haozhuma.com/", want: "https://api.haozhuma.com"},
		{name: "trailing slash is trimmed", endpoint: "https://api.haozhuma.com/", want: "https://api.haozhuma.com"},
		{name: "explicit http is kept", endpoint: "http://api.haozhuma.com", want: "http://api.haozhuma.com"},
		{name: "blank stays blank", endpoint: "   ", want: ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			c := Channel{
				Label: "Haozhuma",
				Phone: &KindConfig{
					Enabled: true,
					Natures: []Nature{NatureAPI},
					Connections: map[Nature]Connection{
						NatureAPI: {Endpoint: testCase.endpoint, Secret: "s"},
					},
				},
			}
			got, err := c.Normalize()
			if err != nil {
				t.Fatalf("normalize failed for %q: %v", testCase.endpoint, err)
			}
			if endpoint := got.Phone.Connections[NatureAPI].Endpoint; endpoint != testCase.want {
				t.Fatalf("endpoint for %q = %q, want %q", testCase.endpoint, endpoint, testCase.want)
			}
		})
	}
}

// An IMAP address is a host:port, not a URL. Applying the http(s) rule would
// rewrite "imap.qq.com:993" into "https://imap.qq.com:993", and the client would
// then be handed an address it cannot dial — so the two rules must stay apart.
func TestChannelNormalizeImapEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		want     string
	}{
		{name: "host and port", endpoint: "imap.qq.com:993", want: "imap.qq.com:993"},
		{name: "host only keeps the port off", endpoint: "imap.qq.com", want: "imap.qq.com"},
		{name: "surrounding space is trimmed", endpoint: "  imap.qq.com:993  ", want: "imap.qq.com:993"},
		{name: "blank stays blank", endpoint: "   ", want: ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			c := Channel{
				Label: "QQ",
				Email: &KindConfig{
					Enabled: true,
					Natures: []Nature{NatureIMAP},
					Connections: map[Nature]Connection{
						NatureIMAP: {Endpoint: testCase.endpoint, Account: "box@qq.com", Secret: "mail-key"},
					},
				},
			}
			got, err := c.Normalize()
			if err != nil {
				t.Fatalf("normalize failed for %q: %v", testCase.endpoint, err)
			}
			if endpoint := got.Email.Connections[NatureIMAP].Endpoint; endpoint != testCase.want {
				t.Fatalf("endpoint for %q = %q, want %q", testCase.endpoint, endpoint, testCase.want)
			}
		})
	}
}

// A URL in an IMAP address is refused rather than silently rewritten: the
// operator meant something the mailbox client will not do.
func TestChannelNormalizeRejectsImapURL(t *testing.T) {
	for _, endpoint := range []string{"https://imap.qq.com", "imap://imap.qq.com", "imap.qq.com:notaport"} {
		t.Run(endpoint, func(t *testing.T) {
			c := Channel{
				Label: "bad",
				Email: &KindConfig{
					Enabled: true,
					Natures: []Nature{NatureIMAP},
					Connections: map[Nature]Connection{
						NatureIMAP: {Endpoint: endpoint, Account: "box@qq.com", Secret: "s"},
					},
				},
			}
			_, err := c.Normalize()
			if err == nil {
				t.Fatalf("expected %q to be rejected", endpoint)
			}
			if !strings.Contains(err.Error(), "endpoint") {
				t.Fatalf("err = %v, want it to name the endpoint", err)
			}
		})
	}
}

// An address that is not an http(s) URL is refused at write time, so the panel
// answers 400 instead of the request failing later.
func TestChannelNormalizeRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{"://bad", "ht tp://x", "ftp://x", "https://"} {
		t.Run(endpoint, func(t *testing.T) {
			c := Channel{
				Label: "bad",
				Phone: &KindConfig{
					Enabled: true,
					Natures: []Nature{NatureAPI},
					Connections: map[Nature]Connection{
						NatureAPI: {Endpoint: endpoint, Secret: "s"},
					},
				},
			}
			_, err := c.Normalize()
			if err == nil {
				t.Fatalf("expected %q to be rejected", endpoint)
			}
			if !strings.Contains(err.Error(), "endpoint") {
				t.Fatalf("err = %v, want it to name the endpoint", err)
			}
		})
	}
}

func TestChannelStoreListByKind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "channels.json")
	store := NewChannelStore(path)

	// A phone-only channel.
	_, err := store.Upsert(Channel{
		Label: "Phone Only",
		Phone: &KindConfig{
			Enabled:     true,
			Natures:     []Nature{NatureAPI},
			Connections: map[Nature]Connection{NatureAPI: {}},
		},
	}, 1000)
	if err != nil {
		t.Fatalf("upsert phone: %v", err)
	}

	// A both-kinds channel.
	_, err = store.Upsert(Channel{
		Label: "Both",
		Phone: &KindConfig{
			Enabled:     true,
			Natures:     []Nature{NatureAPI},
			Connections: map[Nature]Connection{NatureAPI: {}},
		},
		Email: &KindConfig{
			Enabled:     true,
			Natures:     []Nature{NatureIMAP},
			Connections: map[Nature]Connection{NatureIMAP: {Account: "x@q.com", Secret: "s"}},
		},
	}, 1001)
	if err != nil {
		t.Fatalf("upsert both: %v", err)
	}

	if got := store.List(KindPhone); len(got) != 2 {
		t.Errorf("phone list = %d, want 2", len(got))
	}
	if got := store.List(KindEmail); len(got) != 1 {
		t.Errorf("email list = %d, want 1", len(got))
	}
	if got := store.All(); len(got) != 2 {
		t.Errorf("all = %d, want 2", len(got))
	}
}

func TestChannelStorePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "channels.json")
	store := NewChannelStore(path)

	_, err := store.Upsert(Channel{
		Label: "Persist",
		Phone: &KindConfig{
			Enabled:     true,
			Natures:     []Nature{NatureAPI},
			Connections: map[Nature]Connection{NatureAPI: {Secret: "s"}},
		},
	}, 1000)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Reload from disk.
	store2, err := LoadChannels(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := store2.All(); len(got) != 1 || got[0].Label != "Persist" {
		t.Errorf("reload: got %+v", got)
	}

	// Delete and verify file still exists but empty.
	if err := store2.Delete(store2.All()[0].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got := store2.All(); len(got) != 0 {
		t.Errorf("after delete: %d channels", len(got))
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should still exist: %v", err)
	}
}

// An OAuth2 mailbox is a mailbox: it takes the same address rules and the same
// catch-all question, and its credential is derived from the login like the
// password entry is. What differs is the entry prefix — the two hold different
// kinds of value, so sharing a name would feed a refresh token to a LOGIN.
func TestChannelNormalizeOAuth2Mailbox(t *testing.T) {
	c := Channel{
		Label:    "outlook",
		Category: "self-built",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureOAuth2},
			Connections: map[Nature]Connection{
				NatureOAuth2: {
					Endpoint: "outlook.office365.com:993",
					Account:  "Box@Outlook.com",
					ClientID: "app-123",
					Domain:   "ormnes.com",
				},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	conn := got.Email.Connections[NatureOAuth2]
	if want := "email-oauth2-box@outlook.com"; conn.Secret != want {
		t.Errorf("secret name = %q, want %q", conn.Secret, want)
	}
	if conn.Usage != "self-domain" {
		t.Errorf("usage = %q, want self-domain", conn.Usage)
	}
	if conn.ClientID != "app-123" {
		t.Errorf("client id = %q, want app-123", conn.ClientID)
	}
}

// Without the application id the token endpoint cannot be asked for anything, so
// the connection can never authenticate: refusing it at write time keeps it from
// becoming a channel that looks configured and silently reads nothing.
func TestChannelNormalizeOAuth2NeedsClientID(t *testing.T) {
	c := Channel{
		Label:    "outlook",
		Category: "self-owned",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureOAuth2},
			Connections: map[Nature]Connection{
				NatureOAuth2: {Endpoint: "outlook.office365.com:993", Account: "box@outlook.com"},
			},
		},
	}
	if _, err := c.Normalize(); err == nil {
		t.Fatal("an OAuth2 mailbox without an application id was accepted")
	}
}

// One mailbox is read one way. Declaring both methods would leave the host
// choosing, and a wrong choice is a channel that never reads its mail.
func TestChannelNormalizeRejectsBothMailboxMethods(t *testing.T) {
	c := Channel{
		Label:    "both",
		Category: "self-owned",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP, NatureOAuth2},
			Connections: map[Nature]Connection{
				NatureIMAP:   {Endpoint: "imap.qq.com:993", Account: "box@qq.com"},
				NatureOAuth2: {Endpoint: "outlook.office365.com:993", Account: "box@outlook.com", ClientID: "app-123"},
			},
		},
	}
	if _, err := c.Normalize(); err == nil {
		t.Fatal("a mailbox declaring both methods was accepted")
	}
}

// An application id belongs to the method that uses it. A leftover from an
// earlier OAuth2 attempt must not ride along on a password login.
func TestChannelNormalizeClearsClientIDOutsideOAuth2(t *testing.T) {
	c := Channel{
		Label:    "qq",
		Category: "self-owned",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Endpoint: "imap.qq.com:993", Account: "box@qq.com", ClientID: "app-123"},
			},
		},
	}
	got, err := c.Normalize()
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if conn := got.Email.Connections[NatureIMAP]; conn.ClientID != "" {
		t.Errorf("client id = %q, want it cleared", conn.ClientID)
	}
}
