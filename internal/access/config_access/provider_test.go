package configaccess

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func authResultFor(t *testing.T, p *provider, key string) map[string]string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	result, authErr := p.Authenticate(context.Background(), req)
	if authErr != nil {
		t.Fatalf("Authenticate(%q) error = %v", key, authErr)
	}
	return result.Metadata
}

func TestProviderAttachesPoolsMetadata(t *testing.T) {
	cfg := &sdkconfig.SDKConfig{
		APIKeys:  []string{"sk-scoped", "sk-open"},
		KeyPools: map[string][]string{"sk-scoped": {"loomy", "zcode-bigmodel"}},
	}
	p := newProvider("test", normalizeKeys(cfg.APIKeys), cfg.KeyPools)

	scoped := authResultFor(t, p, "sk-scoped")
	if got := scoped["pools"]; got != "loomy,zcode-bigmodel" {
		t.Fatalf("Metadata[pools] = %q, want %q", got, "loomy,zcode-bigmodel")
	}

	open := authResultFor(t, p, "sk-open")
	if _, exists := open["pools"]; exists {
		t.Fatalf("unrestricted key carried pools metadata: %v", open)
	}
}

func TestNormalizeKeyPoolsDropsUnknownAndEmpty(t *testing.T) {
	keys := map[string]struct{}{"sk-known": {}}
	pools := map[string][]string{
		"sk-known":   {" Loomy ", "", "loomy", "ZCODE-BIGMODEL"},
		"sk-unknown": {"loomy"},
		"sk-empty":   {},
	}
	got := normalizeKeyPools(keys, pools)
	if len(got) != 1 {
		t.Fatalf("normalizeKeyPools() = %v, want only sk-known", got)
	}
	if list := got["sk-known"]; len(list) != 2 || list[0] != "loomy" || list[1] != "zcode-bigmodel" {
		t.Fatalf("normalizeKeyPools()[sk-known] = %v, want [loomy zcode-bigmodel]", list)
	}
}

// TestRegisterDeniesAllWhenKeyListEmpty locks the fail-closed contract: once the
// last client key is removed, the proxy must reject requests instead of letting
// every credential through.
func TestRegisterDeniesAllWhenKeyListEmpty(t *testing.T) {
	sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
	t.Cleanup(func() { sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey) })

	Register(&sdkconfig.SDKConfig{}, true)

	manager := sdkaccess.NewManager()
	manager.SetProviders(sdkaccess.RegisteredProviders())

	tests := []struct {
		name     string
		header   string
		wantCode sdkaccess.AuthErrorCode
	}{
		{name: "leftover credential", header: "Bearer leftover-key", wantCode: sdkaccess.AuthErrorCodeInvalidCredential},
		{name: "no credential", header: "", wantCode: sdkaccess.AuthErrorCodeNoCredentials},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			if test.header != "" {
				req.Header.Set("Authorization", test.header)
			}

			result, authErr := manager.Authenticate(context.Background(), req)

			if result != nil {
				t.Fatalf("Authenticate() result = %v, want nil", result)
			}
			if authErr == nil {
				t.Fatal("Authenticate() allowed the request with an empty allowlist")
			}
			if authErr.HTTPStatusCode() != http.StatusUnauthorized {
				t.Fatalf("Authenticate() status = %d, want %d", authErr.HTTPStatusCode(), http.StatusUnauthorized)
			}
			if authErr.Code != test.wantCode {
				t.Fatalf("Authenticate() code = %q, want %q", authErr.Code, test.wantCode)
			}
		})
	}
}

// TestRegisterKeepsLegacyAnonymousWhenDenyDisabled covers the Home-mode path,
// which clears api-keys on purpose and must keep routing unauthenticated.
func TestRegisterKeepsLegacyAnonymousWhenDenyDisabled(t *testing.T) {
	sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey)
	t.Cleanup(func() { sdkaccess.UnregisterProvider(sdkaccess.AccessProviderTypeConfigAPIKey) })

	Register(&sdkconfig.SDKConfig{}, false)

	for _, provider := range sdkaccess.RegisteredProviders() {
		if provider.Identifier() == sdkaccess.DefaultAccessProviderName {
			t.Fatalf("config provider registered with denyAll disabled: %q", provider.Identifier())
		}
	}

	manager := sdkaccess.NewManager()
	manager.SetProviders(sdkaccess.RegisteredProviders())
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	result, authErr := manager.Authenticate(context.Background(), req)
	if result != nil || authErr != nil {
		t.Fatalf("Authenticate() = (%v, %v), want (nil, nil) when no provider is configured", result, authErr)
	}
}
