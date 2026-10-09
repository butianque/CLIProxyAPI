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

func TestHostSecretCallbacksLockedUntilUnlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets.enc")
	store, errOpen := secretstore.Open(path)
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })
	host := New()

	// A brand-new store has no unlock policy yet, so it stays locked: a plugin
	// write is reported as Locked in the envelope rather than silently accepted.
	newStatus, errNewStatus := decodeRPCEnvelope[pluginapi.HostSecretStatusResponse](callSecret(t, host, pluginabi.MethodHostSecretStatus, pluginapi.HostSecretStatusRequest{}))
	if errNewStatus != nil {
		t.Fatalf("decode status: %v", errNewStatus)
	}
	if !newStatus.Enabled || newStatus.Unlocked || newStatus.Passphrase {
		t.Fatalf("status = %+v, want enabled but locked and uninitialized", newStatus)
	}
	lockedSet, errLockedSet := decodeRPCEnvelope[pluginapi.HostSecretSetResponse](callSecret(t, host, pluginabi.MethodHostSecretSet, pluginapi.HostSecretSetRequest{Name: "haozhuma", Value: "v"}))
	if errLockedSet != nil {
		t.Fatalf("decode set on fresh store: %v", errLockedSet)
	}
	if !lockedSet.Locked || lockedSet.Stored {
		t.Fatalf("set on fresh store = %+v, want locked and not stored", lockedSet)
	}

	// Install a passphrase: that initializes the store and leaves it unlocked.
	installed, errInstall := decodeRPCEnvelope[pluginapi.HostSecretSetPassphraseResponse](callSecret(t, host, pluginabi.MethodHostSecretSetPassphrase, pluginapi.HostSecretSetPassphraseRequest{Next: "master"}))
	if errInstall != nil {
		t.Fatalf("decode install: %v", errInstall)
	}
	if !installed.Installed {
		t.Fatal("passphrase must initialize the store")
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
	if !status.Enabled || !status.Unlocked || !status.Passphrase {
		t.Fatalf("status = %+v, want enabled, unlocked, passphrase-protected", status)
	}
	if len(status.Names) != 1 || status.Names[0] != "haozhuma" {
		t.Fatalf("status names = %v, want [haozhuma]", status.Names)
	}

	// After a Lock the key is gone, so reads and writes report Locked in the
	// envelope rather than as errors.
	store.Lock()
	lockedGet, errLockedGet := decodeRPCEnvelope[pluginapi.HostSecretGetResponse](callSecret(t, host, pluginabi.MethodHostSecretGet, pluginapi.HostSecretGetRequest{Name: "haozhuma"}))
	if errLockedGet != nil {
		t.Fatalf("decode locked get: %v", errLockedGet)
	}
	if !lockedGet.Locked || lockedGet.Found {
		t.Fatalf("locked get = %+v, want locked and not found", lockedGet)
	}
	lockedSetAfter, errLockedSetAfter := decodeRPCEnvelope[pluginapi.HostSecretSetResponse](callSecret(t, host, pluginabi.MethodHostSecretSet, pluginapi.HostSecretSetRequest{Name: "haozhuma", Value: "v"}))
	if errLockedSetAfter != nil {
		t.Fatalf("decode locked set: %v", errLockedSetAfter)
	}
	if !lockedSetAfter.Locked || lockedSetAfter.Stored {
		t.Fatalf("locked set = %+v, want locked and not stored", lockedSetAfter)
	}
}

func TestHostSecretPassphraseCallbacks(t *testing.T) {
	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })
	host := New()

	// Before any passphrase is installed, verify reports neither configured nor
	// verified rather than an error.
	before, errBefore := decodeRPCEnvelope[pluginapi.HostSecretVerifyResponse](callSecret(t, host, pluginabi.MethodHostSecretVerify, pluginapi.HostSecretVerifyRequest{Passphrase: "x"}))
	if errBefore != nil {
		t.Fatalf("decode verify: %v", errBefore)
	}
	if before.Configured || before.Verified {
		t.Fatalf("verify before install = %+v, want neither", before)
	}

	installed, errInstall := decodeRPCEnvelope[pluginapi.HostSecretSetPassphraseResponse](callSecret(t, host, pluginabi.MethodHostSecretSetPassphrase, pluginapi.HostSecretSetPassphraseRequest{Next: "master"}))
	if errInstall != nil {
		t.Fatalf("decode install: %v", errInstall)
	}
	if !installed.Installed {
		t.Fatal("passphrase must be installed")
	}

	ok, errOk := decodeRPCEnvelope[pluginapi.HostSecretVerifyResponse](callSecret(t, host, pluginabi.MethodHostSecretVerify, pluginapi.HostSecretVerifyRequest{Passphrase: "master"}))
	if errOk != nil {
		t.Fatalf("decode verify correct: %v", errOk)
	}
	if !ok.Configured || !ok.Verified {
		t.Fatalf("verify = %+v, want configured and verified", ok)
	}

	bad, errBad := decodeRPCEnvelope[pluginapi.HostSecretVerifyResponse](callSecret(t, host, pluginabi.MethodHostSecretVerify, pluginapi.HostSecretVerifyRequest{Passphrase: "wrong"}))
	if errBad != nil {
		t.Fatalf("decode verify wrong: %v", errBad)
	}
	if !bad.Configured || bad.Verified {
		t.Fatalf("verify wrong = %+v, want configured but not verified", bad)
	}
}
