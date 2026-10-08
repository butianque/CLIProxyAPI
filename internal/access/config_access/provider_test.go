package configaccess

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
