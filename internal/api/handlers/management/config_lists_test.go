package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// newMapSettingsHandler builds a handler whose three map-valued settings are all
// populated, so every concurrent case below has something to read and rewrite.
func newMapSettingsHandler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{
		cfg: &config.Config{
			OAuthExcludedModels: map[string][]string{
				"codex":  {"hidden-model"},
				"claude": {"hidden-claude"},
			},
			OAuthModelAlias: map[string][]config.OAuthModelAlias{
				"codex": {{Name: "alias", Alias: "target"}},
			},
			OAuthRequestScopedErrors: map[string][]config.RequestScopedErrorRule{
				"codex": {{Status: http.StatusBadRequest, Match: []string{"invalid_request"}, Action: "stop"}},
			},
			// APIKeys lives on the embedded SDKConfig; Go 1.26's -lang (the
			// repository's go directive) rejects a promoted field in a composite
			// literal, so the embed is initialized explicitly.
			SDKConfig: config.SDKConfig{APIKeys: []string{"key-a", "key-b"}},
		},
		configFilePath: writeTestConfigFile(t),
	}
}

// callHandler runs one handler against a fresh test context and returns the
// recorded status, so a concurrency case can run the real HTTP entry points.
func callHandler(t *testing.T, h *Handler, handler func(*gin.Context), method, target, body string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	if reader != nil {
		c.Request = httptest.NewRequest(method, target, reader)
	} else {
		c.Request = httptest.NewRequest(method, target, nil)
	}
	c.Request.Header.Set("Content-Type", "application/json")
	handler(c)
	return rec.Code
}

// TestMapSettings_ConcurrentReadAndWrite runs the panel's map endpoints the way two
// browser tabs do: one rewrites the whole map while another reads it, and a third
// rewrites a different map. Before the handlers took h.mu this was a runtime fatal
// error ("concurrent map iteration and map write"), which recover cannot catch, so
// the old code did not fail an assertion here — the test process was gone.
func TestMapSettings_ConcurrentReadAndWrite(t *testing.T) {
	t.Parallel()

	h := newMapSettingsHandler(t)

	type endpoint struct {
		name    string
		method  string
		target  string
		body    string
		handler func(*gin.Context)
	}
	reads := []endpoint{
		{"get excluded", http.MethodGet, "/v0/management/oauth-excluded-models", "", h.GetOAuthExcludedModels},
		{"get alias", http.MethodGet, "/v0/management/oauth-model-alias", "", h.GetOAuthModelAlias},
		{"get scoped", http.MethodGet, "/v0/management/oauth-request-scoped-errors", "", h.GetOAuthRequestScopedErrors},
		{"get api keys", http.MethodGet, "/v0/management/api-keys", "", h.GetAPIKeys},
	}
	writes := []endpoint{
		{"put excluded", http.MethodPut, "/v0/management/oauth-excluded-models", `{"codex":["a","b"],"claude":["c"]}`, h.PutOAuthExcludedModels},
		{"patch excluded", http.MethodPatch, "/v0/management/oauth-excluded-models", `{"provider":"codex","models":["x"]}`, h.PatchOAuthExcludedModels},
		{"delete excluded", http.MethodDelete, "/v0/management/oauth-excluded-models?provider=claude", "", h.DeleteOAuthExcludedModels},
		{"put alias", http.MethodPut, "/v0/management/oauth-model-alias", `{"codex":[{"name":"n","alias":"a"}]}`, h.PutOAuthModelAlias},
		{"patch alias", http.MethodPatch, "/v0/management/oauth-model-alias", `{"channel":"codex","aliases":[{"name":"m","alias":"b"}]}`, h.PatchOAuthModelAlias},
		{"put scoped", http.MethodPut, "/v0/management/oauth-request-scoped-errors", `{"codex":[{"status":429,"match":["rate"],"action":"stop"}]}`, h.PutOAuthRequestScopedErrors},
		{"patch scoped", http.MethodPatch, "/v0/management/oauth-request-scoped-errors", `{"channel":"codex","rules":[{"status":500,"match":["boom"],"action":"continue"}]}`, h.PatchOAuthRequestScopedErrors},
		{"put api keys", http.MethodPut, "/v0/management/api-keys", `["k1","k2","k3"]`, h.PutAPIKeys},
		{"patch api keys", http.MethodPatch, "/v0/management/api-keys", `{"index":0,"value":"k9"}`, h.PatchAPIKeys},
	}

	const rounds = 12
	var wg sync.WaitGroup
	errs := make(chan string, 1024)

	run := func(e endpoint) {
		defer wg.Done()
		for range rounds {
			status := callHandler(t, h, e.handler, e.method, e.target, e.body)
			// 200 is the success path; 404 is the legitimate "this key is gone
			// because another goroutine deleted it" answer. Anything else means the
			// handler broke under concurrency.
			if status != http.StatusOK && status != http.StatusNotFound {
				errs <- e.name + " returned " + http.StatusText(status)
				return
			}
		}
	}

	wg.Add(len(reads) + len(writes))
	for _, e := range reads {
		go run(e)
	}
	for _, e := range writes {
		go run(e)
	}
	wg.Wait()
	close(errs)

	for message := range errs {
		t.Error(message)
	}

	// The settings must still be readable and well-formed after the storm.
	if got := len(h.cfg.APIKeys); got == 0 {
		t.Fatalf("api-keys is empty after concurrent writes")
	}
}
