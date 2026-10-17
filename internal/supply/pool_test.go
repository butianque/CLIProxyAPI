package supply

import (
	"path/filepath"
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
