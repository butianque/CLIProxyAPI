package management

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// stubKindProvider serves one supply kind so the status handler can be checked
// without a real platform.
type stubKindProvider struct {
	kind supply.Kind
}

func (s stubKindProvider) Kind() supply.Kind { return s.kind }

func (s stubKindProvider) Status(context.Context) (supply.Status, error) {
	return supply.Status{Enabled: true, Kinds: []supply.Kind{s.kind}}, nil
}

func (s stubKindProvider) Grab(context.Context, supply.GrabOptions) (supply.Identity, error) {
	return supply.Identity{Kind: s.kind, Address: "13800000000"}, nil
}

func (s stubKindProvider) Read(context.Context, string, string) (supply.Message, error) {
	return supply.Message{}, nil
}

func (s stubKindProvider) Link(context.Context, string, string, string) error { return nil }
func (s stubKindProvider) Release(context.Context, string, string) error      { return nil }

// TestSupplyStatusReportsConfiguredKinds checks the management payload reflects
// the registered kinds and reports nothing configured when the service is
// absent. The phone kind appears exactly when a provider is registered, which
// is what the panel switches its category on.
func TestSupplyStatusReportsConfiguredKinds(t *testing.T) {
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })

	supply.SetDefault(nil)
	if got := supplyStatus(); got.Enabled || len(got.Kinds) != 0 {
		t.Fatalf("no service: payload = %+v, want not enabled", got)
	}

	registry := supply.NewRegistry()
	if errRegister := registry.Register(stubKindProvider{kind: supply.KindPhone}); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	supply.SetDefault(registry)

	got := supplyStatus()
	if !got.Enabled {
		t.Fatalf("payload = %+v, want enabled", got)
	}
	if len(got.Kinds) != 1 || got.Kinds[0] != "phone" {
		t.Fatalf("kinds = %v, want [phone]", got.Kinds)
	}
}