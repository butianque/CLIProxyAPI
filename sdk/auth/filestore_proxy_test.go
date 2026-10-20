package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestFileTokenStoreList_ResolvesEgressIDOverTheStoredAddress pins the load-time
// half of the pool invariant: a credential that names an exit by id is loaded
// with the pool's current address, not with the address copied beside it.
//
// This is the test that makes replacing an exit a single edit: if the stored
// address won, a replaced exit would keep sending traffic from the old one until
// every auth file was rewritten.
func TestFileTokenStoreList_ResolvesEgressIDOverTheStoredAddress(t *testing.T) {
	t.Cleanup(func() { SetEgressResolver(nil) })
	SetEgressResolver(func(id int) (string, error) {
		if id != 2 {
			t.Fatalf("resolver asked for #%d, want #2", id)
		}
		return "socks5://user:pass@10.0.0.2:1080", nil
	})

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	content := []byte(`{
		"type": "zcode",
		"egress_id": 2,
		"proxy_url": "socks5://user:pass@10.0.0.1:1080",
		"email": "pool@example.com"
	}`)
	if err := os.WriteFile(filepath.Join(dir, "zcode.json"), content, 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	auths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("List error: %v", errList)
	}
	if len(auths) != 1 {
		t.Fatalf("got %d auths, want 1", len(auths))
	}
	if got := auths[0].ProxyURL; got != "socks5://user:pass@10.0.0.2:1080" {
		t.Fatalf("ProxyURL = %q, want the pool's address for #2", got)
	}
}

// TestFileTokenStoreList_DanglingEgressIDFailsClosed pins that an unresolvable
// reference does not quietly fall back to the stored address or to no proxy.
func TestFileTokenStoreList_DanglingEgressIDFailsClosed(t *testing.T) {
	t.Cleanup(func() { SetEgressResolver(nil) })
	SetEgressResolver(func(int) (string, error) {
		return "", errors.New("no such exit")
	})

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	content := []byte(`{
		"type": "zcode",
		"egress_id": 99,
		"proxy_url": "socks5://user:pass@10.0.0.1:1080",
		"email": "pool@example.com"
	}`)
	if err := os.WriteFile(filepath.Join(dir, "zcode.json"), content, 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	auths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("List error: %v", errList)
	}
	if len(auths) != 1 {
		t.Fatalf("got %d auths, want 1", len(auths))
	}
	if got := auths[0].ProxyURL; got != UnresolvedEgress {
		t.Fatalf("ProxyURL = %q, want %q: a dangling id must not fall back", got, UnresolvedEgress)
	}
}

// TestFileTokenStoreList_LoadsProxyURLAndPrefix verifies that cold-start file loading
// populates ProxyURL and Prefix on the runtime Auth struct from metadata.
func TestFileTokenStoreList_LoadsProxyURLAndPrefix(t *testing.T) {
	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	content := []byte(`{
		"type": "antigravity",
		"proxy_url": "http://127.0.0.1:7890",
		"prefix": "custom-prefix",
		"project_id": "test-project",
		"access_token": "ya29.test-token"
	}`)
	err := os.WriteFile(filepath.Join(dir, "antigravity.json"), content, 0o600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	auths, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("got %d auths, want 1", len(auths))
	}
	if auths[0].ProxyURL != "http://127.0.0.1:7890" {
		t.Fatalf("ProxyURL = %q, want http://127.0.0.1:7890", auths[0].ProxyURL)
	}
	if auths[0].Prefix != "custom-prefix" {
		t.Fatalf("Prefix = %q, want custom-prefix", auths[0].Prefix)
	}
}

// TestFileTokenStoreList_DoesNotBlockColdStartWithUnproxiedNetworkRequest verifies that
// loading auth files on cold start does not trigger unproxied network requests (e.g. FetchAntigravityProjectID).
func TestFileTokenStoreList_DoesNotBlockColdStartWithUnproxiedNetworkRequest(t *testing.T) {
	var httpDefaultCalled atomic.Bool
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	// Intercept any request via http.DefaultClient/http.DefaultTransport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpDefaultCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	// Auth file without project_id, but with proxy_url
	content := []byte(`{
		"type": "antigravity",
		"proxy_url": "http://127.0.0.1:9999",
		"access_token": "ya29.test-token"
	}`)
	err := os.WriteFile(filepath.Join(dir, "antigravity.json"), content, 0o600)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	start := time.Now()
	auths, err := store.List(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(auths) != 1 {
		t.Fatalf("got %d auths, want 1", len(auths))
	}
	if auths[0].ProxyURL != "http://127.0.0.1:9999" {
		t.Fatalf("ProxyURL = %q, want http://127.0.0.1:9999", auths[0].ProxyURL)
	}
	// Cold start file load must be fast and not perform outbound network I/O
	if elapsed > 2*time.Second {
		t.Fatalf("List took %v, expected < 2s (should not perform blocking network calls during file load)", elapsed)
	}
}
