package credentialpools

import "testing"

func TestPublishNormalizesAndClears(t *testing.T) {
	t.Cleanup(func() { Publish(nil) })

	Publish(map[string][]string{
		"  Handwritten-Pool  ": {"  Member-One.json ", "", "member-two"},
		"":                     {"ignored"},
		"empty-pool":           {"", "   "},
	})

	if !Contains("handwritten-pool", "member-one.json") {
		t.Fatal("normalized pool key/member did not match")
	}
	if !Contains("HANDWRITTEN-POOL", "MEMBER-TWO") {
		t.Fatal("comparison should be case-insensitive on both sides")
	}
	if Contains("", "ignored") {
		t.Fatal("an empty pool name must not be stored")
	}
	if Contains("empty-pool", "anything") {
		t.Fatal("a pool with no usable members must not be stored")
	}

	Publish(nil)
	if Contains("handwritten-pool", "member-one.json") {
		t.Fatal("Publish(nil) must clear the table")
	}
	Publish(map[string][]string{})
	if Contains("handwritten-pool", "member-one.json") {
		t.Fatal("Publish(empty map) must clear the table")
	}
}

func TestContainsRejectsEmptyName(t *testing.T) {
	t.Cleanup(func() { Publish(nil) })
	Publish(map[string][]string{"pool": {"member"}})

	if Contains("pool", "") {
		t.Fatal("an empty credential name must never match")
	}
	if Contains("pool", "   ") {
		t.Fatal("a blank credential name must never match")
	}
	if Contains("missing", "member") {
		t.Fatal("an unknown pool must not match")
	}
}

func TestMatchesScope(t *testing.T) {
	t.Cleanup(func() { Publish(nil) })
	Publish(map[string][]string{"handwritten-pool": {"member-one"}})

	cases := []struct {
		name     string
		scope    []string
		provider string
		cred     string
		want     bool
	}{
		{"provider form", []string{"zcode"}, "zcode", "some-cred", true},
		{"credential name form", []string{"some-cred"}, "zcode", "some-cred", true},
		{"pool member form", []string{"handwritten-pool"}, "zcode", "member-one", true},
		{"case and padding ignored", []string{" ZCODE "}, "zcode", "some-cred", true},
		{"empty entries skipped", []string{"", "   ", "zcode"}, "zcode", "some-cred", true},
		{"empty scope matches nothing", nil, "zcode", "some-cred", false},
		{"blank scope matches nothing", []string{"", "  "}, "zcode", "some-cred", false},
		{"outside scope", []string{"other"}, "zcode", "some-cred", false},
		{"empty provider cannot match provider entry", []string{""}, "", "some-cred", false},
		{"empty name cannot match name entry", []string{"some-cred"}, "zcode", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesScope(tc.scope, tc.provider, tc.cred); got != tc.want {
				t.Fatalf("MatchesScope(%v, %q, %q) = %v, want %v", tc.scope, tc.provider, tc.cred, got, tc.want)
			}
		})
	}
}
