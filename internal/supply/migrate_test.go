package supply

import (
	"path/filepath"
	"testing"
)

// A channel that declared a token-based mailbox is what an older installation
// looks like. The migration moves that mailbox into the pool and drops the
// channel, so the address keeps being read instead of being refused at load time.
func TestMigrateChannelsMovesATokenMailboxIntoThePool(t *testing.T) {
	dir := t.TempDir()
	path := ChannelPath(dir)
	// Upsert normalizes, and a graph channel is refused now — which is exactly
	// why this document can only exist on disk. Write it directly.
	if errWrite := saveJSON(path, ChannelDocument{
		Version: channelVersion,
		Channels: []Channel{{
			ID:       "outlook",
			Label:    "box@outlook.com",
			Category: "third-party",
			Email: &KindConfig{
				Enabled: true,
				Natures: []Nature{NatureGraph},
				Connections: map[Nature]Connection{
					NatureGraph: {Account: "box@outlook.com", ClientID: "app-123", Secret: "email-oauth2-box@outlook.com"},
				},
			},
		}},
	}); errWrite != nil {
		t.Fatalf("write channels: %v", errWrite)
	}

	store, errLoad := LoadChannels(path)
	if errLoad != nil {
		t.Fatalf("load channels: %v", errLoad)
	}
	pool := NewPool()
	moved, errMigrate := MigrateChannelsToPool(store, pool, 200)
	if errMigrate != nil {
		t.Fatalf("migrate: %v", errMigrate)
	}
	if moved != 1 {
		t.Fatalf("moved = %d, want 1", moved)
	}
	record, ok := pool.Get(KindEmail, "box@outlook.com")
	if !ok {
		t.Fatal("the mailbox was not moved into the pool")
	}
	if record.Mailbox == nil || record.Mailbox.Nature != NatureGraph {
		t.Fatalf("mailbox = %+v, want a graph transport", record.Mailbox)
	}
	if record.Mailbox.ClientID != "app-123" {
		t.Fatalf("client id = %q", record.Mailbox.ClientID)
	}
	if record.Mailbox.Secret != "email-oauth2-box@outlook.com" {
		t.Fatalf("credential entry = %q", record.Mailbox.Secret)
	}
	if got := store.List(KindEmail); len(got) != 0 {
		t.Fatalf("the channel table still has %d email channels", len(got))
	}
}

// An IMAP channel is a real channel — one connection covering many addresses —
// so the migration must leave it exactly as it is.
func TestMigrateChannelsLeavesAnImapChannelAlone(t *testing.T) {
	dir := t.TempDir()
	store := NewChannelStore(ChannelPath(dir))
	original := Channel{
		ID:       "domain",
		Label:    "my domain",
		Category: "self-built",
		Email: &KindConfig{
			Enabled: true,
			Natures: []Nature{NatureIMAP},
			Connections: map[Nature]Connection{
				NatureIMAP: {Endpoint: "imap.qq.com:993", Account: "box@qq.com", Domain: "example.com"},
			},
		},
	}
	if _, err := store.Upsert(original, 100); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	pool := NewPool()
	moved, errMigrate := MigrateChannelsToPool(store, pool, 200)
	if errMigrate != nil {
		t.Fatalf("migrate: %v", errMigrate)
	}
	if moved != 0 {
		t.Fatalf("moved = %d, want 0", moved)
	}
	if len(pool.All()) != 0 {
		t.Fatalf("the pool gained %d records", len(pool.All()))
	}
	got := store.List(KindEmail)
	if len(got) != 1 || got[0].Email == nil {
		t.Fatalf("the imap channel was changed: %+v", got)
	}
	if got[0].Email.Connections[NatureIMAP].Domain != "example.com" {
		t.Fatalf("the catch-all domain was lost: %+v", got[0].Email.Connections[NatureIMAP])
	}
}

// A channel can serve both kinds. Moving its mailbox out must not take its phone
// block with it.
func TestMigrateChannelsKeepsThePhoneBlock(t *testing.T) {
	dir := t.TempDir()
	path := ChannelPath(dir)
	if errWrite := saveJSON(path, ChannelDocument{
		Version: channelVersion,
		Channels: []Channel{{
			ID:       "mixed",
			Label:    "mixed",
			Category: "third-party",
			Phone: &KindConfig{
				Enabled: true,
				Natures: []Nature{NatureAPI},
				Connections: map[Nature]Connection{
					NatureAPI: {Secret: "haozhuma"},
				},
			},
			Email: &KindConfig{
				Enabled: true,
				Natures: []Nature{NatureOAuth2},
				Connections: map[Nature]Connection{
					NatureOAuth2: {Endpoint: "outlook.office365.com:993", Account: "box@outlook.com", ClientID: "app-123"},
				},
			},
		}},
	}); errWrite != nil {
		t.Fatalf("write channels: %v", errWrite)
	}
	store, errLoad := LoadChannels(path)
	if errLoad != nil {
		t.Fatalf("load channels: %v", errLoad)
	}
	pool := NewPool()
	if _, errMigrate := MigrateChannelsToPool(store, pool, 200); errMigrate != nil {
		t.Fatalf("migrate: %v", errMigrate)
	}
	all := store.All()
	if len(all) != 1 {
		t.Fatalf("channels = %d, want 1", len(all))
	}
	if all[0].Phone == nil {
		t.Fatal("the phone block was dropped with the mailbox")
	}
	if all[0].Email != nil {
		t.Fatalf("the email block survived: %+v", all[0].Email)
	}
	if _, ok := pool.Get(KindEmail, "box@outlook.com"); !ok {
		t.Fatal("the mailbox did not reach the pool")
	}
}

// The retired category is lowered rather than left in place: a channel keeping it
// would be refused by the next save.
func TestMigrateChannelsLowersTheRetiredCategory(t *testing.T) {
	dir := t.TempDir()
	path := ChannelPath(dir)
	if errWrite := saveJSON(path, ChannelDocument{
		Version: channelVersion,
		Channels: []Channel{{
			ID:       "old",
			Label:    "old",
			Category: "self-owned",
			Email: &KindConfig{
				Enabled: true,
				Natures: []Nature{NatureIMAP},
				Connections: map[Nature]Connection{
					NatureIMAP: {Endpoint: "imap.qq.com:993", Account: "box@qq.com"},
				},
			},
		}},
	}); errWrite != nil {
		t.Fatalf("write channels: %v", errWrite)
	}
	store, errLoad := LoadChannels(path)
	if errLoad != nil {
		t.Fatalf("load channels: %v", errLoad)
	}
	pool := NewPool()
	if _, errMigrate := MigrateChannelsToPool(store, pool, 200); errMigrate != nil {
		t.Fatalf("migrate: %v", errMigrate)
	}
	// A self-owned mailbox is one address, so it becomes a pool identity and the
	// channel disappears.
	if _, ok := pool.Get(KindEmail, "box@qq.com"); !ok {
		t.Fatal("the self-owned mailbox did not reach the pool")
	}
	if all := store.All(); len(all) != 0 {
		t.Fatalf("channels = %d, want 0", len(all))
	}
	if _, errLoad := LoadChannels(filepath.Join(dir, "channels.json")); errLoad != nil {
		t.Fatalf("reload: %v", errLoad)
	}
}
