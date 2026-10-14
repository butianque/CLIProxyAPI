package supply

import (
	"path/filepath"
	"testing"
)

func TestNatureSupportsKind(t *testing.T) {
	cases := []struct {
		nature Nature
		kind   Kind
		want   bool
	}{
		{NatureAPI, KindPhone, true},
		{NatureWeb, KindPhone, true},
		{NatureIMAP, KindPhone, false},
		{NatureAPI, KindEmail, true},
		{NatureIMAP, KindEmail, true},
		{NatureWeb, KindEmail, false},
	}
	for _, tc := range cases {
		if got := tc.nature.SupportsKind(tc.kind); got != tc.want {
			t.Errorf("%s/%s = %v, want %v", tc.nature, tc.kind, got, tc.want)
		}
	}
}

func TestChannelNormalizeRejects(t *testing.T) {
	cases := []struct {
		name    string
		channel Channel
	}{
		{"no label", Channel{Kind: KindPhone, Nature: NatureAPI}},
		{"unknown kind", Channel{Kind: "sms", Nature: NatureAPI, Label: "x"}},
		{"unknown nature", Channel{Kind: KindPhone, Nature: "smtp", Label: "x"}},
		// A mailbox cannot hand out a number, and a website session cannot read
		// mail: the mismatch is refused when the channel is saved.
		{"imap for phone", Channel{Kind: KindPhone, Nature: NatureIMAP, Label: "x"}},
		{"web for email", Channel{Kind: KindEmail, Nature: NatureWeb, Label: "x"}},
	}
	for _, tc := range cases {
		if _, err := tc.channel.Normalize(); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestChannelStoreUpsertPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "channels.json")
	store, errLoad := LoadChannels(path)
	if errLoad != nil {
		t.Fatalf("load: %v", errLoad)
	}
	created, errUpsert := store.Upsert(Channel{
		Kind:   KindEmail,
		Label:  "Ormnes Domain",
		Nature: NatureIMAP,
	}, 100)
	if errUpsert != nil {
		t.Fatalf("upsert: %v", errUpsert)
	}
	if created.ID != "email-ormnes-domain" {
		t.Fatalf("id = %q, want %q", created.ID, "email-ormnes-domain")
	}
	if created.Created != 100 || created.Updated != 100 {
		t.Fatalf("timestamps = %d/%d, want 100/100", created.Created, created.Updated)
	}

	reloaded, errReload := LoadChannels(path)
	if errReload != nil {
		t.Fatalf("reload: %v", errReload)
	}
	got, ok := reloaded.Get(created.ID)
	if !ok || got.Label != "Ormnes Domain" || got.Nature != NatureIMAP {
		t.Fatalf("reloaded = %+v, ok=%v", got, ok)
	}
}

// A rename must not change the id: the id is what the ledger attributes
// identities by, so a label is free text and nothing more.
func TestChannelStoreRenameKeepsID(t *testing.T) {
	store, _ := LoadChannels(filepath.Join(t.TempDir(), "channels.json"))
	created, errCreate := store.Upsert(Channel{Kind: KindPhone, Label: "Haozhuma", Nature: NatureAPI}, 100)
	if errCreate != nil {
		t.Fatalf("create: %v", errCreate)
	}
	updated, errUpdate := store.Upsert(Channel{ID: created.ID, Kind: KindPhone, Label: "Haozhuma 2", Nature: NatureAPI}, 200)
	if errUpdate != nil {
		t.Fatalf("update: %v", errUpdate)
	}
	if updated.ID != created.ID {
		t.Fatalf("id changed: %q -> %q", created.ID, updated.ID)
	}
	if updated.Created != 100 {
		t.Fatalf("created = %d, want 100 (creation time is kept)", updated.Created)
	}
	if list := store.List(KindPhone); len(list) != 1 {
		t.Fatalf("channels = %d, want 1", len(list))
	}
}

func TestChannelStoreKindIsImmutable(t *testing.T) {
	store, _ := LoadChannels(filepath.Join(t.TempDir(), "channels.json"))
	created, _ := store.Upsert(Channel{Kind: KindPhone, Label: "Haozhuma", Nature: NatureAPI}, 100)
	if _, err := store.Upsert(Channel{ID: created.ID, Kind: KindEmail, Label: "Haozhuma", Nature: NatureAPI}, 200); err == nil {
		t.Fatal("expected changing a channel's kind to be refused")
	}
}

// Labels are free text and may carry no Latin characters at all; the derived id
// still has to be usable, and two such channels must not collide.
func TestChannelStoreNonLatinLabelsGetDistinctIDs(t *testing.T) {
	store, _ := LoadChannels(filepath.Join(t.TempDir(), "channels.json"))
	first, errFirst := store.Upsert(Channel{Kind: KindEmail, Label: "自建域名", Nature: NatureIMAP}, 1)
	if errFirst != nil {
		t.Fatalf("first: %v", errFirst)
	}
	second, errSecond := store.Upsert(Channel{Kind: KindEmail, Label: "自有邮箱", Nature: NatureIMAP}, 2)
	if errSecond != nil {
		t.Fatalf("second: %v", errSecond)
	}
	if first.ID == "" || second.ID == "" {
		t.Fatalf("ids = %q/%q, want non-empty", first.ID, second.ID)
	}
	if first.ID == second.ID {
		t.Fatalf("both channels got id %q", first.ID)
	}
}

func TestChannelStoreDelete(t *testing.T) {
	store, _ := LoadChannels(filepath.Join(t.TempDir(), "channels.json"))
	created, _ := store.Upsert(Channel{Kind: KindPhone, Label: "Haozhuma", Nature: NatureAPI}, 1)
	if err := store.Delete(created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := store.Get(created.ID); ok {
		t.Fatal("channel still present after delete")
	}
	// Deleting what is not there is the caller's intent already satisfied.
	if err := store.Delete(created.ID); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

func TestChannelStoreListsByKind(t *testing.T) {
	store, _ := LoadChannels(filepath.Join(t.TempDir(), "channels.json"))
	if _, err := store.Upsert(Channel{Kind: KindPhone, Label: "Haozhuma", Nature: NatureAPI}, 1); err != nil {
		t.Fatalf("phone: %v", err)
	}
	if _, err := store.Upsert(Channel{Kind: KindEmail, Label: "Ormnes", Nature: NatureIMAP}, 1); err != nil {
		t.Fatalf("email: %v", err)
	}
	if got := store.List(KindPhone); len(got) != 1 || got[0].Kind != KindPhone {
		t.Fatalf("phone list = %+v", got)
	}
	if got := store.List(KindEmail); len(got) != 1 || got[0].Kind != KindEmail {
		t.Fatalf("email list = %+v", got)
	}
	if got := store.All(); len(got) != 2 {
		t.Fatalf("all = %d, want 2", len(got))
	}
}
