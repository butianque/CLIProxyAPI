package supply

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// Knows is what keeps a caller from asking a source to re-occupy an identity it
// never handed out: only an identity in the pool may take the automated
// re-authentication path, and anything else stays on the manual path.
func TestPoolKnows(t *testing.T) {
	pool := NewPool()
	if pool.Knows(KindPhone, "13800000000") {
		t.Fatal("a fresh pool must not know any identity")
	}
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)
	if !pool.Knows(KindPhone, "13800000000") {
		t.Fatal("a recorded identity must be known")
	}
	if pool.Knows(KindPhone, "13900000000") {
		t.Fatal("an unrelated identity must not be known")
	}
	if pool.Knows(KindEmail, "13800000000") {
		t.Fatal("the key is (kind, address): a phone must not answer for an email")
	}
}

// Recording the same identity twice accumulates spend and rental count instead
// of duplicating the record, and later kind-specific details win.
func TestPoolRecordIsIdempotentByIdentity(t *testing.T) {
	pool := NewPool()
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.13, map[string]any{"channel": "21614-a"}, 1)
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.18, map[string]any{"channel": "21614-b"}, 2)

	if len(pool.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(pool.Records))
	}
	record, _ := pool.Get(KindPhone, "13800000000")
	if record.Rents != 2 {
		t.Fatalf("rents = %d, want 2", record.Rents)
	}
	if got := record.MetaString("channel"); got != "21614-b" {
		t.Fatalf("channel = %q, want the latest one", got)
	}
	if record.Spend < 0.309 || record.Spend > 0.311 {
		t.Fatalf("spend = %v, want 0.31", record.Spend)
	}
	if pool.Spent() < 0.309 || pool.Spent() > 0.311 {
		t.Fatalf("total spend = %v, want 0.31", pool.Spent())
	}
}

// A refund must never drive the pool negative, even if asked to reverse more
// than the record ever booked.
func TestPoolRefundNeverGoesNegative(t *testing.T) {
	pool := NewPool()
	pool.Record(KindPhone, "13800000010", "haozhuma", 0.13, nil, 1)

	if !pool.Refund(KindPhone, "13800000010", 5.0, 2) {
		t.Fatal("an over-large refund should still be applied, capped at the booked spend")
	}
	if got := pool.Spent(); got != 0 {
		t.Fatalf("spent = %v, want 0 after a capped refund", got)
	}
	if pool.Refund(KindPhone, "13800000010", 0.13, 3) {
		t.Fatal("a second refund with nothing left to reverse must be a no-op")
	}
}

// Link is the step that makes a record traceable: it names the platform and the
// account, and it never invents a credential index that was not supplied.
func TestPoolLinkNamesTargetAndAccount(t *testing.T) {
	pool := NewPool()
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)

	pool.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "", 5)

	record, _ := pool.Get(KindPhone, "13800000000")
	if record.Target != "loomy" {
		t.Fatalf("target = %q, want loomy", record.Target)
	}
	if record.Account != "loomy-13800000000" {
		t.Fatalf("account = %q, want the credential name", record.Account)
	}
	if record.AuthIndex != "" {
		t.Fatalf("auth index = %q, want empty: it is not knowable at link time", record.AuthIndex)
	}
	if record.Outcome != "registered" {
		t.Fatalf("outcome = %q, want registered", record.Outcome)
	}
	if record.State != "held" {
		t.Fatalf("state = %q, want held: the account holds the identity now", record.State)
	}
	if record.LastUsed != 5 {
		t.Fatalf("last used = %d, want the link time", record.LastUsed)
	}
}

// A record that a failed attempt marked timed-out must not keep saying so after
// a later attempt registers the same identity: the bound account is the newest
// fact, so the outcome and state describe it.
func TestPoolLinkOverwritesAnEarlierFailure(t *testing.T) {
	pool := NewPool()
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)
	pool.Mark(KindPhone, "13800000000", "timeout", "released", 2)

	pool.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "", 3)

	record, _ := pool.Get(KindPhone, "13800000000")
	if record.Outcome != "registered" || record.State != "held" {
		t.Fatalf("record = %+v, want the registration to be the newest fact", record)
	}
}

// Mark records the standing of an identity without clearing the other field.
func TestPoolMarkSetsState(t *testing.T) {
	pool := NewPool()
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)

	pool.Mark(KindPhone, "13800000000", "timeout", "released", 9)

	record, _ := pool.Get(KindPhone, "13800000000")
	if record.Outcome != "timeout" || record.State != "released" {
		t.Fatalf("record = %+v, want the timeout outcome and released state", record)
	}
}

// The pool round-trips through its file, so a restart keeps the history and
// the running spend.
func TestPoolRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	pool := NewPool()
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.13, map[string]any{"channel": "21614-a"}, 1)
	pool.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "idx-1", 2)
	if errSave := pool.Save(path); errSave != nil {
		t.Fatalf("Save: %v", errSave)
	}

	reloaded, errLoad := LoadPool(path)
	if errLoad != nil {
		t.Fatalf("LoadPool: %v", errLoad)
	}
	record, ok := reloaded.Get(KindPhone, "13800000000")
	if !ok {
		t.Fatal("the reloaded pool lost the identity")
	}
	if record.Target != "loomy" || record.Account != "loomy-13800000000" || record.AuthIndex != "idx-1" {
		t.Fatalf("record = %+v, want the linked identity", record)
	}
	if got := record.MetaString("channel"); got != "21614-a" {
		t.Fatalf("channel = %q, want it to survive the round trip", got)
	}
	if reloaded.Spent() != 0.13 {
		t.Fatalf("spent = %v, want 0.13", reloaded.Spent())
	}
}

// A missing file is an empty pool, not an error: the first run has no history.
func TestLoadPoolMissingFileIsEmpty(t *testing.T) {
	pool, errLoad := LoadPool(filepath.Join(t.TempDir(), "absent.json"))
	if errLoad != nil {
		t.Fatalf("LoadPool: %v", errLoad)
	}
	if len(pool.Records) != 0 {
		t.Fatalf("records = %d, want an empty pool", len(pool.Records))
	}
}

// Register states the fact a handout alone cannot: which platform account the
// identity produced. It creates the record when the identity is new, because a
// caller that knows the account does not need a handout to have been booked
// first, and it keeps the registration so one identity can show every account it
// was used for.
func TestPoolRegisterCreatesRecordAndRegistration(t *testing.T) {
	pool := NewPool()

	record := pool.Register(KindEmail, "1@ormnes.com", "ormnesqq", "zcode", "zcode-1@ormnes.com", "", "registered", 10)
	if record == nil {
		t.Fatal("Register must return the record it wrote")
	}
	if len(pool.Records) != 1 {
		t.Fatalf("records = %d, want the one identity", len(pool.Records))
	}

	got, ok := pool.Get(KindEmail, "1@ormnes.com")
	if !ok {
		t.Fatal("the registered identity is not in the pool")
	}
	if got.Source != "ormnesqq" || got.ChannelID != "ormnesqq" {
		t.Fatalf("source = %q channel = %q, want the channel that handed the address out", got.Source, got.ChannelID)
	}
	if got.Target != "zcode" || got.Account != "zcode-1@ormnes.com" {
		t.Fatalf("record = %+v, want the registered platform and account", got)
	}
	if got.Outcome != "registered" {
		t.Fatalf("outcome = %q, want registered", got.Outcome)
	}
	if got.FirstSeen != 10 || got.LastUsed != 10 {
		t.Fatalf("first seen = %d last used = %d, want the registration time", got.FirstSeen, got.LastUsed)
	}
	if got.Rents != 1 {
		t.Fatalf("rents = %d, want 1 for the first use", got.Rents)
	}
	if len(got.Registrations) != 1 {
		t.Fatalf("registrations = %+v, want the one account", got.Registrations)
	}
	if got.Registrations[0].Target != "zcode" || got.Registrations[0].Account != "zcode-1@ormnes.com" || got.Registrations[0].At != 10 {
		t.Fatalf("registration = %+v, want the account and the time it was seen", got.Registrations[0])
	}
}

// The same account reported again is the same fact restated: it updates the
// entry instead of adding a second line, and it is not another use of the
// identity. The channel is not reassigned either, because a record keeps the
// channel that first produced it.
func TestPoolRegisterRestatesTheSameAccount(t *testing.T) {
	pool := NewPool()
	pool.Register(KindEmail, "1@ormnes.com", "ormnesqq", "zcode", "zcode-1@ormnes.com", "", "registered", 10)

	pool.Register(KindEmail, "1@ormnes.com", "other-channel", "zcode", "zcode-1@ormnes.com", "idx-9", "verified", 20)

	got, _ := pool.Get(KindEmail, "1@ormnes.com")
	if len(got.Registrations) != 1 {
		t.Fatalf("registrations = %+v, want the same account restated, not duplicated", got.Registrations)
	}
	if got.Rents != 1 {
		t.Fatalf("rents = %d, want 1: restating an account is not another use", got.Rents)
	}
	registration := got.Registrations[0]
	if registration.At != 20 || registration.Outcome != "verified" || registration.AuthIndex != "idx-9" {
		t.Fatalf("registration = %+v, want the newest facts", registration)
	}
	if got.ChannelID != "ormnesqq" {
		t.Fatalf("channel = %q, want the channel that first produced the identity", got.ChannelID)
	}
}

// A second account on the same platform is a new use of the identity, so it is
// appended and counted, and the record's Target/Account follow the newest one.
func TestPoolRegisterCountsANewAccountOnTheSameTarget(t *testing.T) {
	pool := NewPool()
	pool.Register(KindEmail, "1@ormnes.com", "ormnesqq", "zcode", "zcode-1@ormnes.com", "", "registered", 10)

	pool.Register(KindEmail, "1@ormnes.com", "ormnesqq", "zcode", "zcode-2@ormnes.com", "", "registered", 30)

	got, _ := pool.Get(KindEmail, "1@ormnes.com")
	if len(got.Registrations) != 2 {
		t.Fatalf("registrations = %+v, want both accounts", got.Registrations)
	}
	if got.Rents != 2 {
		t.Fatalf("rents = %d, want 2 uses", got.Rents)
	}
	if got.Account != "zcode-2@ormnes.com" {
		t.Fatalf("account = %q, want the newest registration", got.Account)
	}
}

// Link annotates what the pool already knows, so an address it never handed out
// stays unknown: a registration report must not invent an identity.
func TestPoolLinkUnknownIdentityIsNoop(t *testing.T) {
	pool := NewPool()

	pool.Link(KindEmail, "absent@ormnes.com", "zcode", "zcode-absent", "", 5)

	if len(pool.Records) != 0 {
		t.Fatalf("records = %+v, want nothing for an address that was never handed out", pool.Records)
	}
}

// ForAccount and ForTarget answer the two questions the pool exists for.
func TestPoolQueriesByAccountAndTarget(t *testing.T) {
	pool := NewPool()
	pool.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)
	pool.Record(KindPhone, "13800000001", "haozhuma", 0.13, nil, 1)
	pool.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "", 2)
	pool.Link(KindPhone, "13800000001", "zcode", "zcode-13800000001", "", 2)

	if got := pool.ForAccount("loomy-13800000000"); len(got) != 1 || got[0].Address != "13800000000" {
		t.Fatalf("ForAccount = %+v, want the one matching identity", got)
	}
	if got := pool.ForTarget("zcode"); len(got) != 1 || got[0].Address != "13800000001" {
		t.Fatalf("ForTarget = %+v, want the one matching identity", got)
	}
}

// An imported mailbox has never been handed out, so no other writer would create
// its record: attaching the mailbox is what puts it in the pool.
func TestPoolAttachMailboxCreatesTheRecord(t *testing.T) {
	pool := NewPool()
	record, created := pool.AttachMailbox(KindEmail, "box@outlook.com", Mailbox{
		Nature:   NatureGraph,
		ClientID: "app-123",
		Secret:   "email-oauth2-box@outlook.com",
		Password: "email-password-box@outlook.com",
	}, 7)

	if !created {
		t.Fatal("the first attach must report that it created the record")
	}
	if record.Mailbox == nil || record.Mailbox.Nature != NatureGraph {
		t.Fatalf("mailbox = %+v, want a graph transport", record.Mailbox)
	}
	if record.Rents != 0 || record.LastUsed != 0 {
		t.Fatalf("attaching a credential is not a use: rents %d last_used %d", record.Rents, record.LastUsed)
	}
	if got := pool.Mailboxes(); len(got) != 1 || got[0].Address != "box@outlook.com" {
		t.Fatalf("Mailboxes = %+v, want the one identity", got)
	}
}

// Re-attaching replaces the whole block, which is what makes a re-import with a
// different receiving method an update rather than a second identity.
func TestPoolAttachMailboxReplacesTheTransport(t *testing.T) {
	pool := NewPool()
	pool.AttachMailbox(KindEmail, "box@outlook.com", Mailbox{Nature: NatureGraph, ClientID: "app-123"}, 7)
	record, created := pool.AttachMailbox(KindEmail, "box@outlook.com", Mailbox{
		Nature:   NatureOAuth2,
		Endpoint: "outlook.office365.com:993",
		ClientID: "app-123",
	}, 9)

	if created {
		t.Fatal("re-attaching must update, not create")
	}
	if record.Mailbox.Nature != NatureOAuth2 || record.Mailbox.Endpoint == "" {
		t.Fatalf("mailbox = %+v, want the oauth2 transport", record.Mailbox)
	}
	if len(pool.All()) != 1 {
		t.Fatalf("records = %d, want 1", len(pool.All()))
	}
}

// CountByChannel is the number the channel row shows: how much supply a channel
// actually contributed. An email record names its channel outright; a phone
// record names the platform, so that join runs through the credential entry the
// channel row holds. A released identity still counts, because the ledger still
// lists it — the strip must agree with the rows under that channel.
func TestCountByChannel(t *testing.T) {
	channels := []Channel{
		{
			ID: "sms",
			Phone: &KindConfig{
				Enabled:     true,
				Natures:     []Nature{NatureAPI},
				Connections: map[Nature]Connection{NatureAPI: {Secret: "haozhuma"}},
			},
		},
		{ID: "ormnesqq", Email: &KindConfig{Enabled: true, Natures: []Nature{NatureIMAP}}},
		{ID: "idle"},
	}
	records := []Record{
		{Kind: KindPhone, Address: "13800000001", Source: "haozhuma"},
		{Kind: KindPhone, Address: "13800000002", Source: "haozhuma", State: "released"},
		{Kind: KindPhone, Address: "13800000003", Source: "haozhuma", State: "blacklisted"},
		{Kind: KindPhone, Address: "13800000004", Source: "some-other-platform"},
		{Kind: KindEmail, Address: "1@ormnes.com", ChannelID: "ormnesqq"},
		{Kind: KindEmail, Address: "2@ormnes.com", ChannelID: "deleted-channel"},
	}

	counts := CountByChannel(channels, records)
	if got := counts["sms"][KindPhone]; got != 3 {
		t.Errorf("phone supply = %d, want 3: every row under the channel counts, a foreign platform does not", got)
	}
	if got := counts["ormnesqq"][KindEmail]; got != 1 {
		t.Errorf("email supply = %d, want 1", got)
	}
	if _, ok := counts["idle"]; ok {
		t.Error("a channel that supplied nothing must be absent from the counts, not present as zero")
	}
	if got := counts["sms"][KindEmail]; got != 0 {
		t.Errorf("a channel serving phones must not answer for emails, got %d", got)
	}
	if _, ok := counts["deleted-channel"]; !ok {
		t.Error("a record naming a channel keeps that channel: its history must not move to whoever is left")
	}
}

// A mailbox is readable only when it names a transport, and a protocol transport
// needs a host: graph answers at one fixed endpoint, so it needs none.
func TestMailboxUsable(t *testing.T) {
	cases := []struct {
		name string
		box  Mailbox
		want bool
	}{
		{"graph without a host", Mailbox{Nature: NatureGraph}, true},
		{"imap without a host", Mailbox{Nature: NatureIMAP}, false},
		{"imap with a host", Mailbox{Nature: NatureIMAP, Endpoint: "imap.qq.com:993"}, true},
		{"a nature that reads no mailbox", Mailbox{Nature: NatureAPI}, false},
		{"no nature at all", Mailbox{}, false},
	}
	for _, testCase := range cases {
		if got := testCase.box.Usable(); got != testCase.want {
			t.Errorf("%s: usable = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

// Concurrent handouts each save the whole document, and every one of them must
// survive. A snapshot taken outside the write lock would let an older state
// overwrite a newer one, and the records added in between would be gone.
func TestPoolConcurrentSaveKeepsEveryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	pool := NewPool()
	const writers = 8
	const perWriter = 5

	var wg sync.WaitGroup
	for writer := range writers {
		wg.Go(func() {
			for index := range perWriter {
				address := fmt.Sprintf("w%d-%d@ormnes.com", writer, index)
				pool.Record(KindEmail, address, "ormnesqq", 0, map[string]any{"domain": "ormnes.com"}, int64(writer*10+index))
				if errSave := pool.Save(path); errSave != nil {
					t.Errorf("save: %v", errSave)
					return
				}
			}
		})
	}
	wg.Wait()

	loaded, errLoad := LoadPool(path)
	if errLoad != nil {
		t.Fatalf("LoadPool: %v", errLoad)
	}
	if got := len(loaded.All()); got != writers*perWriter {
		t.Fatalf("persisted %d records, want %d: a save lost another writer's records", got, writers*perWriter)
	}
	for writer := range writers {
		for index := range perWriter {
			address := fmt.Sprintf("w%d-%d@ormnes.com", writer, index)
			if !loaded.Knows(KindEmail, address) {
				t.Fatalf("%s is missing from the persisted document", address)
			}
		}
	}
}
