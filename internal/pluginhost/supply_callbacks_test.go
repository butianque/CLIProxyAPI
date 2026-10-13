package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func callSupply(t *testing.T, host *Host, method string, request any) ([]byte, error) {
	t.Helper()
	raw, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	return host.callFromPlugin(context.Background(), method, raw)
}

// stubSupplyProvider serves one kind with fixed values, enough to exercise the
// callback plumbing without a real platform.
type stubSupplyProvider struct {
	kind    supply.Kind
	address string
	grabErr error
}

func (s stubSupplyProvider) Kind() supply.Kind { return s.kind }

func (s stubSupplyProvider) Status(context.Context) (supply.Status, error) {
	return supply.Status{Enabled: true, Kinds: []supply.Kind{s.kind}}, nil
}

func (s stubSupplyProvider) Grab(context.Context, supply.GrabOptions) (supply.Identity, error) {
	if s.grabErr != nil {
		return supply.Identity{}, s.grabErr
	}
	return supply.Identity{Kind: s.kind, Address: s.address, Carrier: "unicom", Region: "cn"}, nil
}

func (s stubSupplyProvider) Read(context.Context, string, string) (supply.Message, error) {
	return supply.Message{Ready: true, Code: "123456", Text: "your code is 123456"}, nil
}

func (s stubSupplyProvider) Link(context.Context, string, string, string) error { return nil }

func (s stubSupplyProvider) Release(context.Context, string, string) error { return nil }

// TestHostSupplyCallbacksUnconfigured checks that with no supply service
// installed, status reports not-enabled and a grab fails instead of silently
// returning an empty identity.
func TestHostSupplyCallbacksUnconfigured(t *testing.T) {
	previous := supply.Default()
	supply.SetDefault(nil)
	t.Cleanup(func() { supply.SetDefault(previous) })
	host := New()

	resp, errDecode := decodeRPCEnvelope[pluginapi.HostSupplyStatusResponse](mustCall(t, host, pluginabi.MethodHostSupplyStatus, pluginapi.HostSupplyStatusRequest{}))
	if errDecode != nil {
		t.Fatalf("decode status: %v", errDecode)
	}
	if resp.Enabled || len(resp.Kinds) != 0 {
		t.Fatalf("status = %+v, want not enabled", resp)
	}

	if _, errGrab := callSupply(t, host, pluginabi.MethodHostSupplyGrab, pluginapi.HostSupplyGrabRequest{Kind: "phone"}); !errors.Is(errGrab, supply.ErrUnavailable) {
		t.Fatalf("grab with no service = %v, want ErrUnavailable", errGrab)
	}
}

// TestHostSupplyCallbacksRouteByKind checks the grab/inbox plumbing reaches the
// registered provider and that an unknown kind is refused.
func TestHostSupplyCallbacksRouteByKind(t *testing.T) {
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })
	registry := supply.NewRegistry()
	if errRegister := registry.Register(stubSupplyProvider{kind: supply.KindPhone, address: "13800000000"}); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	supply.SetDefault(registry)
	host := New()

	grabResp, errDecode := decodeRPCEnvelope[pluginapi.HostSupplyGrabResponse](mustCall(t, host, pluginabi.MethodHostSupplyGrab, pluginapi.HostSupplyGrabRequest{Kind: "phone"}))
	if errDecode != nil {
		t.Fatalf("decode grab: %v", errDecode)
	}
	if grabResp.Address != "13800000000" {
		t.Fatalf("grab address = %q, want 13800000000", grabResp.Address)
	}
	if grabResp.Meta["carrier"] != "unicom" || grabResp.Meta["region"] != "cn" {
		t.Fatalf("grab meta = %+v, want carrier=unicom region=cn", grabResp.Meta)
	}

	inboxResp, errDecode := decodeRPCEnvelope[pluginapi.HostSupplyInboxResponse](mustCall(t, host, pluginabi.MethodHostSupplyInbox, pluginapi.HostSupplyInboxRequest{Kind: "phone", Address: "13800000000"}))
	if errDecode != nil {
		t.Fatalf("decode inbox: %v", errDecode)
	}
	if !inboxResp.Ready || inboxResp.Code != "123456" {
		t.Fatalf("inbox = %+v, want ready with code 123456", inboxResp)
	}

	if _, errKind := callSupply(t, host, pluginabi.MethodHostSupplyGrab, pluginapi.HostSupplyGrabRequest{Kind: "carrier-pigeon"}); errKind == nil {
		t.Fatal("grab with unknown kind should fail")
	}
}

func mustCall(t *testing.T, host *Host, method string, request any) []byte {
	t.Helper()
	resp, errCall := callSupply(t, host, method, request)
	if errCall != nil {
		t.Fatalf("callFromPlugin(%s) error = %v", method, errCall)
	}
	return resp
}

// TestHostSupplyGrabUnknownIdentityIsData checks that "the host never handed out
// this identity" reaches a plugin as a successful response with an empty address
// and a reason, not as a transport error: a caller must act on it by falling
// back to its manual path, and it cannot tell one error string from another.
func TestHostSupplyGrabUnknownIdentityIsData(t *testing.T) {
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })
	registry := supply.NewRegistry()
	if errRegister := registry.Register(stubSupplyProvider{kind: supply.KindPhone, grabErr: supply.ErrUnknownIdentity}); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	supply.SetDefault(registry)
	host := New()

	resp, errDecode := decodeRPCEnvelope[pluginapi.HostSupplyGrabResponse](mustCall(t, host, pluginabi.MethodHostSupplyGrab, pluginapi.HostSupplyGrabRequest{Kind: "phone", Address: "13900000000"}))
	if errDecode != nil {
		t.Fatalf("decode grab: %v", errDecode)
	}
	if resp.Address != "" {
		t.Fatalf("address = %q, want empty for an identity the host never handed out", resp.Address)
	}
	if resp.Meta["reason"] != "unknown-identity" {
		t.Fatalf("meta = %+v, want reason=unknown-identity", resp.Meta)
	}
}

// TestHostSupplyGrabRealFailureStaysAnError checks the other side of the same
// rule: anything that is not "unknown identity" must still fail, so a transient
// rental error cannot be mistaken for "this number is not ours".
func TestHostSupplyGrabRealFailureStaysAnError(t *testing.T) {
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })
	registry := supply.NewRegistry()
	if errRegister := registry.Register(stubSupplyProvider{kind: supply.KindPhone, grabErr: errors.New("platform unreachable")}); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	supply.SetDefault(registry)
	host := New()

	if _, errGrab := callSupply(t, host, pluginabi.MethodHostSupplyGrab, pluginapi.HostSupplyGrabRequest{Kind: "phone"}); errGrab == nil {
		t.Fatal("a real grab failure must stay an error")
	}
}