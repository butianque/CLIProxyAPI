package email

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestDialForEgressRoutesThroughProxy is the whole point of the file under test:
// a mailbox with an exit must open its TCP connection at the proxy, not at the
// mailbox server.
//
// The stub below is a plain listener that accepts and closes. It is not a
// working SOCKS proxy, so the dial is expected to fail — the assertion is that
// the connection arrived at the stub at all. A dialer that quietly fell back to
// a direct connection would never touch it.
func TestDialForEgressRoutesThroughProxy(t *testing.T) {
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	defer func() { _ = listener.Close() }()

	reached := make(chan struct{}, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			return
		}
		reached <- struct{}{}
		_ = conn.Close()
	}()

	dial, errDial := dialForEgress("socks5://" + listener.Addr().String())
	if errDial != nil {
		t.Fatalf("dialForEgress: %v", errDial)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// A host that cannot resolve: if the route were direct, the dial would fail
	// before any proxy saw a byte.
	if _, errConn := dial(ctx, "tcp", "imap.invalid:993"); errConn == nil {
		t.Fatal("dial through a stub proxy succeeded, want a failure")
	}

	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the dial never reached the configured proxy")
	}
}

// TestDialForEgressRejectsMalformed keeps the setting honest: a typo must
// surface as an error, because reading mail through an exit the operator did not
// choose would hide the mistake until the platform refused the account.
func TestDialForEgressRejectsMalformed(t *testing.T) {
	if _, errDial := dialForEgress("imap.example.com:993"); errDial == nil {
		t.Fatal("dialForEgress accepted a value that is not a proxy URL")
	}
}

func TestDialForEgressPlainRoutes(t *testing.T) {
	for _, egress := range []string{"", "direct", "none", "DIRECT"} {
		dial, errDial := dialForEgress(egress)
		if errDial != nil {
			t.Fatalf("dialForEgress(%q): %v", egress, errDial)
		}
		if dial == nil {
			t.Fatalf("dialForEgress(%q) returned no dialer", egress)
		}
	}
}

// TestClientForEgressSharesByAddress pins the pool: a poll loop must not rebuild
// a transport per read, while two different exits must not share one.
func TestClientForEgressSharesByAddress(t *testing.T) {
	first, errFirst := clientForEgress("http://127.0.0.1:18801")
	if errFirst != nil {
		t.Fatalf("clientForEgress: %v", errFirst)
	}
	again, errAgain := clientForEgress("http://127.0.0.1:18801")
	if errAgain != nil {
		t.Fatalf("clientForEgress: %v", errAgain)
	}
	if first != again {
		t.Fatal("the same exit produced two clients")
	}

	other, errOther := clientForEgress("http://127.0.0.1:18802")
	if errOther != nil {
		t.Fatalf("clientForEgress: %v", errOther)
	}
	if first == other {
		t.Fatal("two different exits share one client")
	}

	inherited, errInherited := clientForEgress("")
	if errInherited != nil {
		t.Fatalf("clientForEgress: %v", errInherited)
	}
	if inherited != graphHTTPClient {
		t.Fatal("an empty exit must keep the package default client")
	}
}

func TestFirstNonEmpty(t *testing.T) {
	cases := []struct {
		values []string
		want   string
	}{
		{values: nil, want: ""},
		{values: []string{"", "  ", ""}, want: ""},
		{values: []string{"", "http://a:1", "http://b:2"}, want: "http://a:1"},
		{values: []string{"direct", "http://b:2"}, want: "direct"},
	}
	for _, tc := range cases {
		if got := firstNonEmpty(tc.values...); got != tc.want {
			t.Fatalf("firstNonEmpty(%v) = %q, want %q", tc.values, got, tc.want)
		}
	}
}
