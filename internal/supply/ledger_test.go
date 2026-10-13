package supply

import (
	"path/filepath"
	"testing"
)

// Knows is what keeps a caller from asking a source to re-occupy an identity it
// never handed out: only an identity in the ledger may take the automated
// re-authentication path, and anything else stays on the manual path.
func TestLedgerKnows(t *testing.T) {
	ledger := NewLedger()
	if ledger.Knows(KindPhone, "13800000000") {
		t.Fatal("a fresh ledger must not know any identity")
	}
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)
	if !ledger.Knows(KindPhone, "13800000000") {
		t.Fatal("a recorded identity must be known")
	}
	if ledger.Knows(KindPhone, "13900000000") {
		t.Fatal("an unrelated identity must not be known")
	}
	if ledger.Knows(KindEmail, "13800000000") {
		t.Fatal("the key is (kind, address): a phone must not answer for an email")
	}
}

// Recording the same identity twice accumulates spend and rental count instead
// of duplicating the record, and later kind-specific details win.
func TestLedgerRecordIsIdempotentByIdentity(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.13, map[string]any{"channel": "21614-a"}, 1)
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.18, map[string]any{"channel": "21614-b"}, 2)

	if len(ledger.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(ledger.Records))
	}
	record, _ := ledger.Get(KindPhone, "13800000000")
	if record.Rents != 2 {
		t.Fatalf("rents = %d, want 2", record.Rents)
	}
	if got := record.MetaString("channel"); got != "21614-b" {
		t.Fatalf("channel = %q, want the latest one", got)
	}
	if record.Spend < 0.309 || record.Spend > 0.311 {
		t.Fatalf("spend = %v, want 0.31", record.Spend)
	}
	if ledger.Spent() < 0.309 || ledger.Spent() > 0.311 {
		t.Fatalf("total spend = %v, want 0.31", ledger.Spent())
	}
}

// A refund must never drive the ledger negative, even if asked to reverse more
// than the record ever booked.
func TestLedgerRefundNeverGoesNegative(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(KindPhone, "13800000010", "haozhuma", 0.13, nil, 1)

	if !ledger.Refund(KindPhone, "13800000010", 5.0, 2) {
		t.Fatal("an over-large refund should still be applied, capped at the booked spend")
	}
	if got := ledger.Spent(); got != 0 {
		t.Fatalf("spent = %v, want 0 after a capped refund", got)
	}
	if ledger.Refund(KindPhone, "13800000010", 0.13, 3) {
		t.Fatal("a second refund with nothing left to reverse must be a no-op")
	}
}

// Link is the step that makes a record traceable: it names the platform and the
// account, and it never invents a credential index that was not supplied.
func TestLedgerLinkNamesTargetAndAccount(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)

	ledger.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "", 5)

	record, _ := ledger.Get(KindPhone, "13800000000")
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
func TestLedgerLinkOverwritesAnEarlierFailure(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)
	ledger.Mark(KindPhone, "13800000000", "timeout", "released", 2)

	ledger.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "", 3)

	record, _ := ledger.Get(KindPhone, "13800000000")
	if record.Outcome != "registered" || record.State != "held" {
		t.Fatalf("record = %+v, want the registration to be the newest fact", record)
	}
}

// Mark records the standing of an identity without clearing the other field.
func TestLedgerMarkSetsState(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)

	ledger.Mark(KindPhone, "13800000000", "timeout", "released", 9)

	record, _ := ledger.Get(KindPhone, "13800000000")
	if record.Outcome != "timeout" || record.State != "released" {
		t.Fatalf("record = %+v, want the timeout outcome and released state", record)
	}
}

// The ledger round-trips through its file, so a restart keeps the history and
// the running spend.
func TestLedgerRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.json")
	ledger := NewLedger()
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.13, map[string]any{"channel": "21614-a"}, 1)
	ledger.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "idx-1", 2)
	if errSave := ledger.Save(path); errSave != nil {
		t.Fatalf("Save: %v", errSave)
	}

	reloaded, errLoad := LoadLedger(path)
	if errLoad != nil {
		t.Fatalf("LoadLedger: %v", errLoad)
	}
	record, ok := reloaded.Get(KindPhone, "13800000000")
	if !ok {
		t.Fatal("the reloaded ledger lost the identity")
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

// A missing file is an empty ledger, not an error: the first run has no history.
func TestLoadLedgerMissingFileIsEmpty(t *testing.T) {
	ledger, errLoad := LoadLedger(filepath.Join(t.TempDir(), "absent.json"))
	if errLoad != nil {
		t.Fatalf("LoadLedger: %v", errLoad)
	}
	if len(ledger.Records) != 0 {
		t.Fatalf("records = %d, want an empty ledger", len(ledger.Records))
	}
}

// ForAccount and ForTarget answer the two questions the ledger exists for.
func TestLedgerQueriesByAccountAndTarget(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(KindPhone, "13800000000", "haozhuma", 0.13, nil, 1)
	ledger.Record(KindPhone, "13800000001", "haozhuma", 0.13, nil, 1)
	ledger.Link(KindPhone, "13800000000", "loomy", "loomy-13800000000", "", 2)
	ledger.Link(KindPhone, "13800000001", "zcode", "zcode-13800000001", "", 2)

	if got := ledger.ForAccount("loomy-13800000000"); len(got) != 1 || got[0].Address != "13800000000" {
		t.Fatalf("ForAccount = %+v, want the one matching identity", got)
	}
	if got := ledger.ForTarget("zcode"); len(got) != 1 || got[0].Address != "13800000001" {
		t.Fatalf("ForTarget = %+v, want the one matching identity", got)
	}
}
