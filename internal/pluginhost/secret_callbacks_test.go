package pluginhost

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func callSecret(t *testing.T, host *Host, method string, request any) []byte {
	t.Helper()
	raw, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		t.Fatalf("marshal request: %v", errMarshal)
	}
	resp, errCall := host.callFromPlugin(context.Background(), method, raw)
	if errCall != nil {
		t.Fatalf("callFromPlugin(%s) error = %v", method, errCall)
	}
	return resp
}

func TestHostSecretCallbacksWithoutStore(t *testing.T) {
	secretstore.Configure(nil)
	t.Cleanup(func() { secretstore.Configure(nil) })
	host := New()

	resp, errDecode := decodeRPCEnvelope[pluginapi.HostSecretStatusResponse](callSecret(t, host, pluginabi.MethodHostSecretStatus, pluginapi.HostSecretStatusRequest{}))
	if errDecode != nil {
		t.Fatalf("decode status: %v", errDecode)
	}
	if resp.Enabled || resp.Unlocked {
		t.Fatalf("status = %+v, want disabled", resp)
	}

	getResp, errGet := decodeRPCEnvelope[pluginapi.HostSecretGetResponse](callSecret(t, host, pluginabi.MethodHostSecretGet, pluginapi.HostSecretGetRequest{Name: "haozhuma"}))
	if errGet != nil {
		t.Fatalf("decode get: %v", errGet)
	}
	if getResp.Locked || getResp.Found || getResp.Value != "" {
		t.Fatalf("get = %+v, want neither locked nor found", getResp)
	}
}

func TestHostSecretCallbacksLockedAndUnlocked(t *testing.T) {
	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })
	host := New()

	// Locked: reads and writes are reported in the envelope, not as errors.
	getResp, errGet := decodeRPCEnvelope[pluginapi.HostSecretGetResponse](callSecret(t, host, pluginabi.MethodHostSecretGet, pluginapi.HostSecretGetRequest{Name: "haozhuma"}))
	if errGet != nil {
		t.Fatalf("decode locked get: %v", errGet)
	}
	if !getResp.Locked || getResp.Found {
		t.Fatalf("locked get = %+v, want locked and not found", getResp)
	}
	setResp, errSet := decodeRPCEnvelope[pluginapi.HostSecretSetResponse](callSecret(t, host, pluginabi.MethodHostSecretSet, pluginapi.HostSecretSetRequest{Name: "haozhuma", Value: "v"}))
	if errSet != nil {
		t.Fatalf("decode locked set: %v", errSet)
	}
	if !setResp.Locked || setResp.Stored {
		t.Fatalf("locked set = %+v, want locked and not stored", setResp)
	}

	if errUnlock := store.Unlock("passphrase"); errUnlock != nil {
		t.Fatalf("unlock: %v", errUnlock)
	}

	stored, errStore := decodeRPCEnvelope[pluginapi.HostSecretSetResponse](callSecret(t, host, pluginabi.MethodHostSecretSet, pluginapi.HostSecretSetRequest{Name: "haozhuma", Value: "user=abc"}))
	if errStore != nil {
		t.Fatalf("decode set: %v", errStore)
	}
	if !stored.Stored || stored.Locked {
		t.Fatalf("set = %+v, want stored", stored)
	}

	got, errGot := decodeRPCEnvelope[pluginapi.HostSecretGetResponse](callSecret(t, host, pluginabi.MethodHostSecretGet, pluginapi.HostSecretGetRequest{Name: "haozhuma"}))
	if errGot != nil {
		t.Fatalf("decode get: %v", errGot)
	}
	if !got.Found || got.Value != "user=abc" {
		t.Fatalf("get = %+v, want found user=abc", got)
	}

	status, errStatus := decodeRPCEnvelope[pluginapi.HostSecretStatusResponse](callSecret(t, host, pluginabi.MethodHostSecretStatus, pluginapi.HostSecretStatusRequest{}))
	if errStatus != nil {
		t.Fatalf("decode status: %v", errStatus)
	}
	if !status.Enabled || !status.Unlocked {
		t.Fatalf("status = %+v, want enabled and unlocked", status)
	}
	if len(status.Names) != 1 || status.Names[0] != "haozhuma" {
		t.Fatalf("status names = %v, want [haozhuma]", status.Names)
	}
}
