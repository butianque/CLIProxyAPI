package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticateManagementKey_LocalhostIPBan_BlocksCorrectKeyDuringBan(t *testing.T) {
	h := &Handler{
		cfg:            &config.Config{},
		failedAttempts: make(map[string]*attemptInfo),
		envSecret:      "test-secret",
	}

	for i := 0; i < 5; i++ {
		allowed, statusCode, errMsg := h.AuthenticateManagementKey("127.0.0.1", true, "wrong-secret")
		if allowed {
			t.Fatalf("expected auth to be denied at attempt %d", i+1)
		}
		if statusCode != http.StatusUnauthorized || errMsg != "invalid management key" {
			t.Fatalf("unexpected auth failure at attempt %d: status=%d msg=%q", i+1, statusCode, errMsg)
		}
	}

	allowed, statusCode, errMsg := h.AuthenticateManagementKey("127.0.0.1", true, "test-secret")
	if allowed {
		t.Fatalf("expected correct key to be denied while banned")
	}
	if statusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden status while banned, got %d", statusCode)
	}
	if !strings.HasPrefix(errMsg, "IP banned due to too many failed attempts. Try again in") {
		t.Fatalf("unexpected banned message: %q", errMsg)
	}
}

func TestMiddlewareSetsSupportPluginHeader(t *testing.T) {

	h := &Handler{
		cfg:            &config.Config{},
		failedAttempts: make(map[string]*attemptInfo),
		envSecret:      "test-secret",
	}
	middleware := h.Middleware()

	t.Run("invalid key", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		c.Request.RemoteAddr = "127.0.0.1:12345"
		c.Request.Header.Set("X-Management-Key", "wrong-secret")

		middleware(c)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
		if got := rec.Header().Get("X-CPA-SUPPORT-PLUGIN"); got != pluginhost.SupportPluginHeaderValue() {
			t.Fatalf("X-CPA-SUPPORT-PLUGIN = %q, want %q", got, pluginhost.SupportPluginHeaderValue())
		}
	})

	t.Run("valid key", func(t *testing.T) {
		engine := gin.New()
		engine.GET("/v0/management/config", middleware, func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Management-Key", "test-secret")
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		if got := rec.Header().Get("X-CPA-SUPPORT-PLUGIN"); got != pluginhost.SupportPluginHeaderValue() {
			t.Fatalf("X-CPA-SUPPORT-PLUGIN = %q, want %q", got, pluginhost.SupportPluginHeaderValue())
		}
	})
}

func TestAutomationRouteAllowed(t *testing.T) {
	allow := []string{
		"GET /v8/management/supply/*",
		"POST /v8/management/supply/email/grab",
		"GET /v8/management/observability/logs",
		"",
		"   ",
	}

	tests := []struct {
		name   string
		method string
		route  string
		want   bool
	}{
		{"prefix covers a nested read", http.MethodGet, "/v8/management/supply/email/inbox", true},
		{"prefix needs its trailing segment", http.MethodGet, "/v8/management/supply", false},
		{"prefix does not match a sibling name", http.MethodGet, "/v8/management/supplies", false},
		{"exact entry covers its write", http.MethodPost, "/v8/management/supply/email/grab", true},
		{"exact entry is not a prefix", http.MethodGet, "/v8/management/observability/logs/abc", false},
		{"method must match the entry", http.MethodPost, "/v8/management/supply/email/inbox", false},
		{"configuration is never reachable", http.MethodGet, "/v8/management/config", false},
		{"secret store is never reachable", http.MethodGet, "/v8/management/secrets", false},
		{"unknown route is refused", http.MethodGet, "/v8/management/whatever", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := automationRouteAllowed(tc.method, tc.route, allow); got != tc.want {
				t.Fatalf("automationRouteAllowed(%q, %q) = %v, want %v", tc.method, tc.route, got, tc.want)
			}
		})
	}

	t.Run("empty list allows nothing", func(t *testing.T) {
		if automationRouteAllowed(http.MethodGet, "/v8/management/supply/pool", nil) {
			t.Fatal("an empty allow list must not admit any route")
		}
	})
}

// automationTestHandler builds a handler with both keys configured, so the
// middleware can be exercised the way production runs it.
func automationTestHandler(t *testing.T, automationKey string) *Handler {
	t.Helper()
	secretHash, errSecret := bcrypt.GenerateFromPassword([]byte("full-key"), bcrypt.MinCost)
	if errSecret != nil {
		t.Fatalf("hash full key: %v", errSecret)
	}
	automationHash, errAutomation := bcrypt.GenerateFromPassword([]byte(automationKey), bcrypt.MinCost)
	if errAutomation != nil {
		t.Fatalf("hash automation key: %v", errAutomation)
	}
	cfg := &config.Config{}
	cfg.RemoteManagement.SecretKey = string(secretHash)
	if automationKey != "" {
		cfg.RemoteManagement.AutomationKey = string(automationHash)
	}
	return &Handler{
		cfg:            cfg,
		failedAttempts: make(map[string]*attemptInfo),
	}
}

func TestMiddlewareAutomationKeyReachesOnlyAllowedRoutes(t *testing.T) {
	middleware := automationTestHandler(t, "automation-key").Middleware()

	engine := gin.New()
	engine.GET("/v8/management/supply/pool", middleware, func(c *gin.Context) {
		c.String(http.StatusOK, "pool")
	})
	engine.GET("/v8/management/config", middleware, func(c *gin.Context) {
		c.String(http.StatusOK, "config")
	})

	call := func(method, path, key string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Authorization", "Bearer "+key)
		engine.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("allowed route", func(t *testing.T) {
		if got := call(http.MethodGet, "/v8/management/supply/pool", "automation-key"); got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
	})

	t.Run("route outside the allow list", func(t *testing.T) {
		if got := call(http.MethodGet, "/v8/management/config", "automation-key"); got != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", got, http.StatusForbidden)
		}
	})

	t.Run("the full key keeps its reach", func(t *testing.T) {
		if got := call(http.MethodGet, "/v8/management/config", "full-key"); got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
	})

	t.Run("a wrong key is still rejected", func(t *testing.T) {
		if got := call(http.MethodGet, "/v8/management/supply/pool", "not-a-key"); got != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", got, http.StatusUnauthorized)
		}
	})
}

func TestMiddlewareAutomationKeyAbsentFallsBackToFullKey(t *testing.T) {
	// With no automation key configured, the same string is just a wrong
	// management key: the narrow path must not open a route by itself.
	h := automationTestHandler(t, "")
	middleware := h.Middleware()

	engine := gin.New()
	engine.GET("/v8/management/supply/pool", middleware, func(c *gin.Context) {
		c.String(http.StatusOK, "pool")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v8/management/supply/pool", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer full-key")
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
