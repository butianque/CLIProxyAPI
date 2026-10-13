package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// The supply callbacks expose the host's account-supply service to plugins
// over the same ABI style as host.secret.*: the host owns the implementation
// and the credentials, and a plugin only asks for an identity or reads its
// inbox. A plugin never imports internal/supply, so the protocol
// implementations stay private while remaining usable from any plugin.
//
// A missing or unconfigured kind is reported through a distinct error so the
// caller can tell "not set up" from "tried and failed"; the same single-code
// limitation that shapes host.secret.* applies here, so states that a caller
// must distinguish are carried as data, not as error codes.

// supplyService returns the host's supply service. It is nil when no supply
// kind is configured, which callers report as not-enabled rather than failing.
func supplyService() supply.Supply {
	return supply.Default()
}

// decodeSupplyKind validates a wire kind string.
func decodeSupplyKind(raw string) (supply.Kind, error) {
	kind := supply.Kind(strings.ToLower(strings.TrimSpace(raw)))
	if !kind.Valid() {
		return "", fmt.Errorf("unsupported supply kind %q", raw)
	}
	return kind, nil
}

// callHostSupplyStatus reports the supply service's readiness.
func (h *Host) callHostSupplyStatus(_ context.Context, request []byte) ([]byte, error) {
	if len(request) > 0 {
		var req pluginapi.HostSupplyStatusRequest
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			return nil, fmt.Errorf("decode host supply status request: %w", errUnmarshal)
		}
	}
	resp := pluginapi.HostSupplyStatusResponse{}
	service := supplyService()
	if service == nil {
		return marshalRPCResult(resp)
	}
	status, errStatus := service.Status(context.Background())
	if errStatus != nil {
		return nil, fmt.Errorf("host supply status: %w", errStatus)
	}
	resp.Enabled = status.Enabled
	resp.Locked = status.Locked
	resp.Kinds = make([]string, 0, len(status.Kinds))
	for _, kind := range status.Kinds {
		resp.Kinds = append(resp.Kinds, string(kind))
	}
	return marshalRPCResult(resp)
}

// callHostSupplyGrab hands out one identity. A kind with no provider is
// reported as unavailable.
func (h *Host) callHostSupplyGrab(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostSupplyGrabRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host supply grab request: %w", errUnmarshal)
	}
	kind, errKind := decodeSupplyKind(req.Kind)
	if errKind != nil {
		return nil, errKind
	}
	service := supplyService()
	if service == nil {
		return nil, supply.ErrUnavailable
	}
	identity, errGrab := service.Grab(ctx, kind, supply.GrabOptions{
		Purpose: strings.TrimSpace(req.Purpose),
		UID:     strings.TrimSpace(req.UID),
		Address: strings.TrimSpace(req.Address),
	})
	if errGrab != nil {
		// "This identity was never handed out" is a decision the caller must
		// act on, not a transport failure, so it is carried as data: a
		// successful response with an empty address and a reason in Meta. The
		// caller falls back to its manual path; every other failure stays an
		// error.
		if errors.Is(errGrab, supply.ErrUnknownIdentity) {
			return marshalRPCResult(pluginapi.HostSupplyGrabResponse{
				Kind: string(kind),
				Meta: map[string]any{"reason": "unknown-identity"},
			})
		}
		return nil, fmt.Errorf("host supply grab: %w", errGrab)
	}
	return marshalRPCResult(pluginapi.HostSupplyGrabResponse{
		Kind:    string(identity.Kind),
		Address: identity.Address,
		Price:   identity.Price,
		Meta:    identityMeta(identity),
	})
}

// identityMeta collects an identity's non-core fields into the wire Meta bag.
// The core fields (kind, address, price) are carried explicitly so a caller can
// act on them; everything else is informational and may be absent.
func identityMeta(identity supply.Identity) map[string]any {
	meta := map[string]any{}
	if identity.Code != "" {
		meta["code"] = identity.Code
	}
	if identity.Carrier != "" {
		meta["carrier"] = identity.Carrier
	}
	if identity.Region != "" {
		meta["region"] = identity.Region
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// callHostSupplyInbox reads one identity's inbox once. A missing message is
// Ready=false, not an error: it is the ordinary outcome of polling.
func (h *Host) callHostSupplyInbox(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostSupplyInboxRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host supply inbox request: %w", errUnmarshal)
	}
	kind, errKind := decodeSupplyKind(req.Kind)
	if errKind != nil {
		return nil, errKind
	}
	address := strings.TrimSpace(req.Address)
	if address == "" {
		return nil, errors.New("host supply inbox: address is required")
	}
	service := supplyService()
	if service == nil {
		return nil, supply.ErrUnavailable
	}
	message, errRead := service.Read(ctx, kind, strings.TrimSpace(req.Purpose), address)
	if errRead != nil {
		return nil, fmt.Errorf("host supply inbox: %w", errRead)
	}
	return marshalRPCResult(pluginapi.HostSupplyInboxResponse{
		Ready:   message.Ready,
		Code:    message.Code,
		Text:    message.Text,
		Subject: message.Subject,
		From:    message.From,
	})
}

// callHostSupplyLink binds one identity to the account it registered.
func (h *Host) callHostSupplyLink(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostSupplyLinkRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host supply link request: %w", errUnmarshal)
	}
	kind, errKind := decodeSupplyKind(req.Kind)
	if errKind != nil {
		return nil, errKind
	}
	address := strings.TrimSpace(req.Address)
	if address == "" {
		return nil, errors.New("host supply link: address is required")
	}
	service := supplyService()
	if service == nil {
		return nil, supply.ErrUnavailable
	}
	if errLink := service.Link(ctx, kind, address, strings.TrimSpace(req.Target), strings.TrimSpace(req.Account), strings.TrimSpace(req.AuthIndex)); errLink != nil {
		return nil, fmt.Errorf("host supply link: %w", errLink)
	}
	return marshalRPCResult(pluginapi.HostSupplyLinkResponse{Linked: true})
}

// callHostSupplyRelease returns one identity to its source.
func (h *Host) callHostSupplyRelease(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostSupplyReleaseRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host supply release request: %w", errUnmarshal)
	}
	kind, errKind := decodeSupplyKind(req.Kind)
	if errKind != nil {
		return nil, errKind
	}
	address := strings.TrimSpace(req.Address)
	if address == "" {
		return nil, errors.New("host supply release: address is required")
	}
	service := supplyService()
	if service == nil {
		return nil, supply.ErrUnavailable
	}
	if errRelease := service.Release(ctx, kind, address, strings.TrimSpace(req.Outcome)); errRelease != nil {
		return nil, fmt.Errorf("host supply release: %w", errRelease)
	}
	return marshalRPCResult(pluginapi.HostSupplyReleaseResponse{Released: true})
}
