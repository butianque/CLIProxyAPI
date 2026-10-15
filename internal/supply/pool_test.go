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
