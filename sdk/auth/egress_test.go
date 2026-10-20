package auth

import (
	"errors"
	"testing"
)

// TestEgressIDWinsOverTheStoredAddress pins the core invariant: an id is
// authoritative and the address beside it is only a cache. Honouring the cached
// address would keep sending traffic from an exit the operator already replaced.
func TestEgressIDWinsOverTheStoredAddress(t *testing.T) {
	t.Cleanup(func() { SetEgressResolver(nil) })
	SetEgressResolver(func(id int) (string, error) {
		if id != 2 {
			t.Fatalf("resolver asked for #%d, want #2", id)
		}
		return "socks5://user:pass@10.0.0.2:1080", nil
	})

	metadata := map[string]any{
		"egress_id": float64(2),
		"proxy_url": "socks5://user:pass@10.0.0.1:1080",
	}
	id, ok := EgressIDFromMetadata(metadata)
	if !ok || id != 2 {
		t.Fatalf("EgressIDFromMetadata = (%d, %v), want (2, true)", id, ok)
	}
	if got := ResolveEgressID(id); got != "socks5://user:pass@10.0.0.2:1080" {
		t.Fatalf("ResolveEgressID = %q, want the pool's address", got)
	}
}

// TestDanglingEgressIDFailsClosed pins the one failure this design must not
// allow: a reference that cannot be resolved must not fall back to a direct
// connection, because that would put an identity on an address nobody chose.
func TestDanglingEgressIDFailsClosed(t *testing.T) {
	t.Cleanup(func() { SetEgressResolver(nil) })
	SetEgressResolver(func(int) (string, error) {
		return "", errors.New("no such exit")
	})

	if got := ResolveEgressID(7); got != UnresolvedEgress {
		t.Fatalf("ResolveEgressID on a dangling id = %q, want %q", got, UnresolvedEgress)
	}
}

// TestNoResolverFailsClosed pins that forgetting to install the resolver is not
// a licence to connect directly.
func TestNoResolverFailsClosed(t *testing.T) {
	t.Cleanup(func() { SetEgressResolver(nil) })
	SetEgressResolver(nil)

	if got := ResolveEgressID(1); got != UnresolvedEgress {
		t.Fatalf("ResolveEgressID without a resolver = %q, want %q", got, UnresolvedEgress)
	}
}

// TestEgressIDFromMetadataAcceptsTheShapesAFileCanHold pins that the same
// reference reads the same whether it was written by the panel, by hand, or
// survived a round trip through a generic map.
func TestEgressIDFromMetadataAcceptsTheShapesAFileCanHold(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  int
		ok    bool
	}{
		{"json number", float64(3), 3, true},
		{"int", 3, 3, true},
		{"int64", int64(3), 3, true},
		{"string", " 3 ", 3, true},
		{"zero", float64(0), 0, false},
		{"negative", float64(-1), 0, false},
		{"not a number", "abc", 0, false},
		{"absent", nil, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]any{}
			if tc.value != nil {
				metadata["egress_id"] = tc.value
			}
			got, ok := EgressIDFromMetadata(metadata)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("EgressIDFromMetadata(%v) = (%d, %v), want (%d, %v)", tc.value, got, ok, tc.want, tc.ok)
			}
		})
	}
	if _, ok := EgressIDFromMetadata(nil); ok {
		t.Fatal("nil metadata reported an id")
	}
}
