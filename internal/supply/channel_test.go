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

// A personal mailbox used to be its own category. It is not one any more: a
// channel covers many addresses from one connection, while a personal mailbox is
// exactly one address with its own credential — a pool identity. The category is
// refused so an old document cannot quietly keep claiming it.
func TestChannelNormalizeRejectsTheRetiredOwnMailboxCategory(t *testing.T) {
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
	if _, err := c.Normalize(); err == nil {
		t.Fatal("expected the retired self-owned category to be refused")
	}
}

// A third-party mailbox is one address too, and that is the answer the usage
// field carries: nothing can be minted on it.
func TestChannelNormalizeThirdPartyMailboxIsPersonal(t *testing.T) {
	c := Channel{
		Label:    "my-qq",
		Category: "third-party",
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

// A domain is only meaningful where addresses are minted on it, so a mailbox
// outside the self-built category cannot carry one.
func TestChannelNormalizeThirdPartyMailboxRejectsDomain(t *testing.T) {
	c := Channel{
		Label:    "my-qq",
		Category: "third-party",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Domain: "ormnes.com"},
			},
		},
	}
	if _, err := c.Normalize(); err == nil {
		t.Fatal("expected error for a domain on a third-party mailbox")
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

// A token-based mailbox is not a channel nature. Its credential belongs to the
// mailbox, which makes it one bought identity — a pool record — and a channel is
// one connection that covers many addresses. Accepting it here is what used to
// turn the channel table into an address book, one row per mailbox.
func TestChannelNormalizeRejectsTokenMailboxChannels(t *testing.T) {
	for _, nature := range []Nature{NatureOAuth2, NatureGraph} {
		c := Channel{
			Label:    "outlook",
			Category: "third-party",
			Email: &KindConfig{
				Enabled: true,
				Natures: []Nature{nature},
				Connections: map[Nature]Connection{
					nature: {Endpoint: "outlook.office365.com:993", Account: "box@outlook.com", ClientID: "app-123"},
				},
			},
		}
		if _, err := c.Normalize(); err == nil {
			t.Fatalf("a channel declaring %q was accepted", nature)
		}
	}
}

// The set a channel may declare is deliberately narrower than what a nature can
// serve: the token transports serve the email kind, but only as pool identities.
func TestChannelNaturesIsNarrowerThanSupportsKind(t *testing.T) {
	if got := ChannelNatures(KindEmail); len(got) != 1 || got[0] != NatureIMAP {
		t.Fatalf("email channel natures = %v, want only imap", got)
	}
	if got := ChannelNatures(KindPhone); len(got) != 2 || got[0] != NatureAPI || got[1] != NatureWeb {
		t.Fatalf("phone channel natures = %v, want api and web", got)
	}
	for _, nature := range []Nature{NatureOAuth2, NatureGraph} {
		if !nature.SupportsKind(KindEmail) {
			t.Fatalf("%q should still serve the email kind as a pool identity", nature)
		}
		if containsNature(ChannelNatures(KindEmail), nature) {
			t.Fatalf("%q must not be a channel nature", nature)
		}
	}
}

// An application id belongs to the method that uses it. A leftover from an
// earlier OAuth2 attempt must not ride along on a password login.
func TestChannelNormalizeClearsClientIDOutsideOAuth2(t *testing.T) {
	c := Channel{
		Label:    "qq",
		Category: "third-party",
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
