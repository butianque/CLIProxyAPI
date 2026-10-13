package phone

import "testing"

// Knows is what keeps the plugin from asking the platform to re-occupy a number
// it never rented: only a number in the ledger may take the automated
// re-authentication path, and anything else stays on the manual path.
func TestLedgerKnows(t *testing.T) {
	ledger := NewLedger()
	if ledger.Knows("13800000000") {
		t.Fatal("a fresh ledger must not know any number")
	}
	ledger.Record(Number{Phone: "13800000000", SID: "21614"}, 0.13, "haozhuma", 1)
	if !ledger.Knows("13800000000") {
		t.Fatal("a recorded number must be known")
	}
	if ledger.Knows("13900000000") {
		t.Fatal("an unrelated number must not be known")
	}
}

// Recording the same number twice accumulates spend and rental count instead of
// duplicating the entry.
func TestLedgerRecordIsIdempotentByIdentity(t *testing.T) {
	ledger := NewLedger()
	ledger.Record(Number{Phone: "13800000000", SID: "21614", Code: "21614-a"}, 0.13, "haozhuma", 1)
	ledger.Record(Number{Phone: "13800000000", SID: "21614", Code: "21614-b"}, 0.18, "haozhuma", 2)

	if len(ledger.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(ledger.Entries))
	}
	entry, _ := ledger.Get("13800000000")
	if entry.Rents != 2 {
		t.Fatalf("rents = %d, want 2", entry.Rents)
	}
	if entry.Code != "21614-b" {
		t.Fatalf("code = %q, want the latest channel", entry.Code)
	}
	if entry.Spend < 0.309 || entry.Spend > 0.311 {
		t.Fatalf("spend = %v, want 0.31", entry.Spend)
	}
	if ledger.Spent() < 0.309 || ledger.Spent() > 0.311 {
		t.Fatalf("total spend = %v, want 0.31", ledger.Spent())
	}
}
