package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// callHostSecretStatus reports whether the host secret store is enabled and
// unlocked, and which secret names exist while unlocked.
func (h *Host) callHostSecretStatus(_ context.Context, request []byte) ([]byte, error) {
	if len(request) > 0 {
		var req pluginapi.HostSecretStatusRequest
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			return nil, fmt.Errorf("decode host secret status request: %w", errUnmarshal)
		}
	}
	resp := pluginapi.HostSecretStatusResponse{}
	if store := secretstore.Default(); store != nil {
		resp.Enabled = true
		resp.Unlocked = store.Unlocked()
		if names, errNames := store.Names(); errNames == nil {
			resp.Names = names
		}
	}
	return marshalRPCResult(resp)
}

// callHostSecretGet reads one named secret. A locked store or a missing secret
// is reported in the successful envelope so the caller can distinguish the two
// without relying on an error code.
func (h *Host) callHostSecretGet(_ context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostSecretGetRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host secret get request: %w", errUnmarshal)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errors.New("host secret get: name is required")
	}
	resp := pluginapi.HostSecretGetResponse{Name: name}
	store := secretstore.Default()
	if store == nil {
		return marshalRPCResult(resp)
	}
	if !store.Unlocked() {
		resp.Locked = true
		return marshalRPCResult(resp)
	}
	value, errGet := store.Get(name)
	switch {
	case errGet == nil:
		resp.Found = true
		resp.Value = value
	case errors.Is(errGet, secretstore.ErrNotFound):
		// Report Found=false rather than an error so a plugin can fall back.
	default:
		return nil, fmt.Errorf("read host secret %q: %w", name, errGet)
	}
	return marshalRPCResult(resp)
}

// callHostSecretSet stores one named secret.
func (h *Host) callHostSecretSet(_ context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostSecretSetRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host secret set request: %w", errUnmarshal)
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errors.New("host secret set: name is required")
	}
	resp := pluginapi.HostSecretSetResponse{Name: name}
	store := secretstore.Default()
	if store == nil {
		return marshalRPCResult(resp)
	}
	if errSet := store.Set(name, req.Value); errSet != nil {
		if errors.Is(errSet, secretstore.ErrLocked) {
			resp.Locked = true
			return marshalRPCResult(resp)
		}
		return nil, fmt.Errorf("write host secret %q: %w", name, errSet)
	}
	resp.Stored = true
	return marshalRPCResult(resp)
}
