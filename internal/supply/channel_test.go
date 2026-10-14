package supply

import (
	"os"
	"path/filepath"
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
				NatureIMAP: {Account: "me@qq.com", Secret: "imap-pass", Usage: "personal"},
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
	c := Channel{
		Label:    "ormnes.com",
		Category: "self-built",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Account: "me@qq.com", Secret: "imap-pass", Usage: "self-domain", Domain: "ormnes.com"},
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

func TestChannelNormalizeImapSelfDomainNoDomain(t *testing.T) {
	c := Channel{
		Label: "bad",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Usage: "self-domain"},
			},
		},
	}
	_, err := c.Normalize()
	if err == nil {
		t.Fatal("expected error for self-domain without domain")
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
