package supply

import (
	"context"
	"errors"
	"testing"
)

// stubProvider is a minimal provider used to exercise the registry routing.
type stubProvider struct {
	kind     Kind
	grabbed  Identity
	read     Message
	failGrab error
}

func (s *stubProvider) Kind() Kind { return s.kind }

func (s *stubProvider) Status(context.Context) (Status, error) {
	return Status{Enabled: true, Kinds: []Kind{s.kind}}, nil
}

func (s *stubProvider) Grab(context.Context, GrabOptions) (Identity, error) {
	if s.failGrab != nil {
		return Identity{}, s.failGrab
	}
	return s.grabbed, nil
}

func (s *stubProvider) Read(context.Context, string, string) (Message, error) {
	return s.read, nil
}

func (s *stubProvider) Link(context.Context, string, string, string) error { return nil }

func (s *stubProvider) Release(context.Context, string, string) error { return nil }

// plainSupply implements Supply but not KindLookup, standing in for a decorator
// or a future implementation that does not route per kind.
type plainSupply struct{}

func (plainSupply) Status(context.Context) (Status, error) { return Status{}, nil }
func (plainSupply) Grab(context.Context, Kind, GrabOptions) (Identity, error) {
	return Identity{}, nil
}
func (plainSupply) Read(context.Context, Kind, string, string) (Message, error) {
	return Message{}, nil
}
func (plainSupply) Link(context.Context, Kind, string, string, string) error { return nil }
func (plainSupply) Release(context.Context, Kind, string, string) error      { return nil }

// TestRegistryRoutesByKind checks that a call reaches the provider registered
// for its kind and that an unconfigured kind is reported as unavailable.
func TestRegistryRoutesByKind(t *testing.T) {
	registry := NewRegistry()
	phone := &stubProvider{kind: KindPhone, grabbed: Identity{Kind: KindPhone, Address: "13800000000"}}
	if errRegister := registry.Register(phone); errRegister != nil {
		t.Fatalf("register phone: %v", errRegister)
	}

	got, errGrab := registry.Grab(context.Background(), KindPhone, GrabOptions{})
	if errGrab != nil {
		t.Fatalf("grab phone: %v", errGrab)
	}
	if got.Address != "13800000000" {
		t.Fatalf("grab address = %q, want 13800000000", got.Address)
	}

	if _, errEmail := registry.Grab(context.Background(), KindEmail, GrabOptions{}); !errors.Is(errEmail, ErrUnavailable) {
		t.Fatalf("grab unconfigured email kind = %v, want ErrUnavailable", errEmail)
	}
}

// TestRegistryRejectsUnknownKind checks that a provider declaring an unknown
// kind is refused at registration instead of becoming unreachable dead state.
func TestRegistryRejectsUnknownKind(t *testing.T) {
	registry := NewRegistry()
	errRegister := registry.Register(&stubProvider{kind: Kind("carrier-pigeon")})
	if errRegister == nil {
		t.Fatal("register with unknown kind should fail")
	}
}

// TestProviderForReportsUnconfiguredKindsAsUnavailable checks the lookup a
// kind-specific management surface uses: no service, a service that does not
// route by kind, and a kind with no provider all answer ErrUnavailable rather
// than panicking or returning a zero provider.
func TestProviderForReportsUnconfiguredKindsAsUnavailable(t *testing.T) {
	previous := Default()
	t.Cleanup(func() { SetDefault(previous) })

	SetDefault(nil)
	if _, errProvider := ProviderFor(KindPhone); !errors.Is(errProvider, ErrUnavailable) {
		t.Fatalf("lookup without a service = %v, want ErrUnavailable", errProvider)
	}

	// A service that does not expose per-kind routing (e.g. a decorator) must be
	// reported as unconfigured rather than asserted into a concrete type.
	SetDefault(plainSupply{})
	if _, errProvider := ProviderFor(KindPhone); !errors.Is(errProvider, ErrUnavailable) {
		t.Fatalf("lookup against a non-routing service = %v, want ErrUnavailable", errProvider)
	}

	registry := NewRegistry()
	SetDefault(registry)
	if _, errProvider := ProviderFor(KindEmail); !errors.Is(errProvider, ErrUnavailable) {
		t.Fatalf("lookup of an unconfigured kind = %v, want ErrUnavailable", errProvider)
	}

	phone := &stubProvider{kind: KindPhone}
	if errRegister := registry.Register(phone); errRegister != nil {
		t.Fatalf("register phone: %v", errRegister)
	}
	provider, errProvider := ProviderFor(KindPhone)
	if errProvider != nil || provider != Provider(phone) {
		t.Fatalf("lookup of the configured kind = (%v, %v), want the phone provider", provider, errProvider)
	}
}

// TestDefaultIsNilUntilSet checks that the process-wide service reports "not
// set up" (nil) rather than a zero value that would silently swallow calls.
func TestDefaultIsNilUntilSet(t *testing.T) {
	previous := Default()
	t.Cleanup(func() { SetDefault(previous) })

	SetDefault(nil)
	if Default() != nil {
		t.Fatal("Default() should be nil after SetDefault(nil)")
	}

	registry := NewRegistry()
	SetDefault(registry)
	if Default() == nil {
		t.Fatal("Default() should return the installed registry")
	}
}
