package supply

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEgressPoolAssignsMonotonicIDs pins that an id is a durable name, not a
// slot: deleting #1 must not let the next entry become #1 again, because an
// account still holding the old reference would silently point at a new address.
func TestEgressPoolAssignsMonotonicIDs(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))

	first, err := pool.Add("socks5://user:pass@10.0.0.1:1080", "one", "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if first.ID != 1 {
		t.Fatalf("first id = %d, want 1", first.ID)
	}
	if !first.Enabled {
		t.Fatal("a new exit must start enabled")
	}

	if err := pool.Delete(first.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	second, err := pool.Add("http://10.0.0.2:8080", "two", "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if second.ID != 2 {
		t.Fatalf("id after delete = %d, want 2 (ids are never reused)", second.ID)
	}
}

// TestEgressPoolRejectsUnusableAddresses pins the one rule the pool enforces:
// an entry must name a proxy. "direct" would let an identity look bound while
// leaving from the host's own address.
func TestEgressPoolRejectsUnusableAddresses(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))
	for _, raw := range []string{"", "   ", "direct", "none", "not-a-url", "socks5://"} {
		if _, err := pool.Add(raw, "", ""); err == nil {
			t.Fatalf("Add(%q) accepted an address that is not a proxy", raw)
		}
	}
	if got := len(pool.List()); got != 0 {
		t.Fatalf("rejected addresses left %d entries behind", got)
	}
}

// TestEgressPoolUpdateKeepsOmittedAddress pins the read/write asymmetry the
// panel depends on: the address is only ever read back redacted, so an update
// that leaves it out must keep the stored value rather than wipe it.
func TestEgressPoolUpdateKeepsOmittedAddress(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))
	entry, err := pool.Add("socks5://user:pass@10.0.0.1:1080", "one", "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	label := "renamed"
	updated, err := pool.Update(entry.ID, EgressEdit{Label: &label})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Label != "renamed" {
		t.Fatalf("label = %q, want renamed", updated.Label)
	}
	if updated.URL != entry.URL {
		t.Fatalf("url = %q, want the stored %q", updated.URL, entry.URL)
	}
}

// TestEgressPoolChangingAddressDropsTheOldProbe pins that a probe result belongs
// to the address it measured: keeping it after the address changed would show a
// green exit that was never tested.
func TestEgressPoolChangingAddressDropsTheOldProbe(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))
	entry, err := pool.Add("socks5://user:pass@10.0.0.1:1080", "one", "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := pool.RecordProbe(entry.ID, EgressProbe{OK: true, IP: "10.0.0.1"}); err != nil {
		t.Fatalf("RecordProbe: %v", err)
	}

	sameAddress := entry.URL
	kept, err := pool.Update(entry.ID, EgressEdit{URL: &sameAddress})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if kept.LastProbe == nil {
		t.Fatal("rewriting the same address must keep the probe")
	}

	moved := "socks5://user:pass@10.0.0.9:1080"
	cleared, err := pool.Update(entry.ID, EgressEdit{URL: &moved})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if cleared.LastProbe != nil {
		t.Fatalf("changing the address kept a probe for the old one: %+v", cleared.LastProbe)
	}
}

// TestEgressPoolNextPrefersTheEmptiestEnabledExit pins the assignment rule:
// fewest bindings, ties to the lowest id, disabled entries skipped. A random
// pick would make "why is this account on #3" unanswerable.
func TestEgressPoolNextPrefersTheEmptiestEnabledExit(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))
	one, _ := pool.Add("socks5://u:p@10.0.0.1:1080", "one", "")
	two, _ := pool.Add("socks5://u:p@10.0.0.2:1080", "two", "")
	three, _ := pool.Add("socks5://u:p@10.0.0.3:1080", "three", "")

	next, ok := pool.Next(map[int]int{one.ID: 5, two.ID: 1, three.ID: 1})
	if !ok {
		t.Fatal("Next found no exit")
	}
	if next.ID != two.ID {
		t.Fatalf("next = #%d, want #%d (tie broken by the lowest id)", next.ID, two.ID)
	}

	disabled := false
	if _, err := pool.Update(three.ID, EgressEdit{Enabled: &disabled}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	next, ok = pool.Next(map[int]int{one.ID: 5, two.ID: 1, three.ID: 0})
	if !ok || next.ID != two.ID {
		t.Fatalf("next = #%d (found=%v), want #%d: a disabled exit must never be picked", next.ID, ok, two.ID)
	}

	for _, entry := range pool.List() {
		if entry.ID == three.ID {
			continue
		}
		if _, err := pool.Update(entry.ID, EgressEdit{Enabled: &disabled}); err != nil {
			t.Fatalf("Update: %v", err)
		}
	}
	if _, ok := pool.Next(map[int]int{}); ok {
		t.Fatal("Next picked an exit with every entry disabled")
	}
}

// TestEgressPoolNextPassesOverAFailedProbe pins that a known-bad exit is not
// handed to a new identity while a working one exists — but is still used when
// it is the only thing left, because a failed echo probe is weaker evidence
// than an empty pool.
func TestEgressPoolNextPassesOverAFailedProbe(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))
	one, _ := pool.Add("socks5://u:p@10.0.0.1:1080", "one", "")
	two, _ := pool.Add("socks5://u:p@10.0.0.2:1080", "two", "")
	if _, err := pool.RecordProbe(one.ID, EgressProbe{OK: false, Error: "refused"}); err != nil {
		t.Fatalf("RecordProbe: %v", err)
	}

	// #1 has fewer bindings, but its last probe failed, so #2 wins.
	next, ok := pool.Next(map[int]int{one.ID: 0, two.ID: 4})
	if !ok || next.ID != two.ID {
		t.Fatalf("next = #%d (found=%v), want #%d: a failed probe must be passed over", next.ID, ok, two.ID)
	}

	// With nothing else enabled, the failed one is still better than nothing.
	disabled := false
	if _, err := pool.Update(two.ID, EgressEdit{Enabled: &disabled}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	next, ok = pool.Next(map[int]int{})
	if !ok || next.ID != one.ID {
		t.Fatalf("next = #%d (found=%v), want #%d when it is the only candidate", next.ID, ok, one.ID)
	}
}

// TestEgressPoolResolveRefFailsClosedOnADanglingID pins the invariant the whole
// design rests on: an id that no longer exists is an error, never a quiet
// fallback to the address beside it or to a direct connection.
func TestEgressPoolResolveRefFailsClosedOnADanglingID(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))
	entry, _ := pool.Add("socks5://u:p@10.0.0.1:1080", "one", "")

	if got, err := pool.ResolveRef(EgressRef{URL: "socks5://u:p@10.0.0.9:1080"}); err != nil || got != "socks5://u:p@10.0.0.9:1080" {
		t.Fatalf("a bare address resolved to (%q, %v), want the address itself", got, err)
	}
	if _, err := pool.ResolveRef(EgressRef{ID: 99, URL: entry.URL}); err == nil {
		t.Fatal("a dangling id resolved instead of failing")
	}
	// A disabled entry still resolves: disabling means "assign nothing new here",
	// not "cut off what is already bound".
	disabled := false
	if _, err := pool.Update(entry.ID, EgressEdit{Enabled: &disabled}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got, err := pool.ResolveRef(EgressRef{ID: entry.ID}); err != nil || got != entry.URL {
		t.Fatalf("a disabled entry resolved to (%q, %v), want (%q, nil)", got, err, entry.URL)
	}
}

// TestEgressPoolResolveDistinguishesMissingFromDisabled pins that a caller about
// to send traffic can tell a configuration error from an operator's decision.
func TestEgressPoolResolveDistinguishesMissingFromDisabled(t *testing.T) {
	pool := NewEgressPool(filepath.Join(t.TempDir(), "egress-pool.json"))
	entry, _ := pool.Add("socks5://u:p@10.0.0.1:1080", "one", "")

	if _, found, _ := pool.Resolve(99); found {
		t.Fatal("Resolve reported a missing entry as found")
	}
	disabled := false
	if _, err := pool.Update(entry.ID, EgressEdit{Enabled: &disabled}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	url, found, enabled := pool.Resolve(entry.ID)
	if !found || enabled || url != entry.URL {
		t.Fatalf("Resolve = (%q, %v, %v), want (%q, true, false)", url, found, enabled, entry.URL)
	}
}

// TestEgressPoolSurvivesAReload pins the on-disk shape: the address, the id and
// the last probe all come back.
func TestEgressPoolSurvivesAReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-pool.json")
	pool := NewEgressPool(path)
	entry, err := pool.Add("socks5://user:pass@10.0.0.1:1080", "香港 #1", "试跑")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := pool.RecordProbe(entry.ID, EgressProbe{OK: true, IP: "10.0.0.1", Country: "Hong Kong", ASN: "AS9009"}); err != nil {
		t.Fatalf("RecordProbe: %v", err)
	}

	reloaded, err := LoadEgressPool(path)
	if err != nil {
		t.Fatalf("LoadEgressPool: %v", err)
	}
	got, found := reloaded.Get(entry.ID)
	if !found {
		t.Fatalf("reload lost #%d", entry.ID)
	}
	if got.URL != entry.URL || got.Label != "香港 #1" || got.Note != "试跑" {
		t.Fatalf("reload = %+v, want the stored entry", got)
	}
	if got.LastProbe == nil || got.LastProbe.IP != "10.0.0.1" || !got.LastProbe.OK {
		t.Fatalf("reload lost the probe: %+v", got.LastProbe)
	}
	if got.LastProbe.At == 0 {
		t.Fatal("RecordProbe did not stamp a time")
	}
}

// TestLoadEgressPoolOnAMissingFileIsEmpty pins that a fresh installation does
// not need a file to exist.
func TestLoadEgressPoolOnAMissingFileIsEmpty(t *testing.T) {
	pool, err := LoadEgressPool(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("LoadEgressPool on a missing file: %v", err)
	}
	if len(pool.List()) != 0 {
		t.Fatalf("missing file produced %d entries", len(pool.List()))
	}
	if next, ok := pool.Next(nil); ok {
		t.Fatalf("empty pool assigned #%d", next.ID)
	}
}

// TestLoadEgressPoolDerivesAMissingNextID pins that a hand-edited document
// cannot hand out an id that is already taken.
func TestLoadEgressPoolDerivesAMissingNextID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "egress-pool.json")
	document := `{"version":1,"entries":[{"id":7,"url":"socks5://u:p@10.0.0.7:1080","enabled":true}]}`
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadEgressPool(path)
	if err != nil {
		t.Fatalf("LoadEgressPool: %v", err)
	}
	added, err := pool.Add("socks5://u:p@10.0.0.8:1080", "", "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if added.ID != 8 {
		t.Fatalf("id = %d, want 8 (derived from the highest stored id)", added.ID)
	}
}
