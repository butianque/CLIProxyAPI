package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// newChannelHandler builds a handler whose supply state lives in a temp dir, so
// each test writes its own channel document.
func newChannelHandler(t *testing.T) *Handler {
	t.Helper()
	return &Handler{
		cfg:            &config.Config{},
		configFilePath: filepath.Join(t.TempDir(), "config.yaml"),
	}
}

// callChannelRoute runs one management call and returns the decoded body.
func callChannelRoute(t *testing.T, h *Handler, method, target, body, id string) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	ctx.Params = gin.Params{{Key: "id", Value: id}}
	switch method {
	case http.MethodGet:
		h.GetSupplyChannels(ctx)
	case http.MethodPost:
		h.PostSupplyChannel(ctx)
	case http.MethodDelete:
		h.DeleteSupplyChannel(ctx)
	}
	var payload map[string]any
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatalf("decode %s %s: %v (%s)", method, target, errDecode, recorder.Body.String())
	}
	return recorder.Code, payload
}

// listChannels returns the channels the surface reports for one kind.
func listChannels(t *testing.T, h *Handler, kind string) []map[string]any {
	t.Helper()
	code, payload := callChannelRoute(t, h, http.MethodGet, "/v8/management/supply/channels?kind="+kind, "", "")
	if code != http.StatusOK {
		t.Fatalf("list status = %d", code)
	}
	raw, _ := payload["channels"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if entry, ok := item.(map[string]any); ok {
			out = append(out, entry)
		}
	}
	return out
}

// A channel survives a create, is listed for its own kind only, and is gone
// after a delete.
func TestSupplyChannelsRoundTrip(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lockedStore(t)
	h := newChannelHandler(t)

	code, payload := callChannelRoute(t, h, http.MethodPost, "/v8/management/supply/channels",
		`{"kind":"email","label":"Ormnes Domain","nature":"imap","secret":"ormnes-imap"}`, "")
	if code != http.StatusOK {
		t.Fatalf("create status = %d, body = %v", code, payload)
	}
	created, _ := payload["channel"].(map[string]any)
	if created["id"] != "email-ormnes-domain" {
		t.Fatalf("id = %v, want email-ormnes-domain", created["id"])
	}
	if created["nature"] != "imap" || created["kind"] != "email" {
		t.Fatalf("created = %v", created)
	}
	// Only the name of a secret crosses this surface, never a value.
	if _, ok := created["secret_value"]; ok {
		t.Fatalf("create leaked a secret value: %v", created)
	}
	if created["secret_present"] != false {
		t.Fatalf("secret_present = %v, want false for an unwritten name", created["secret_present"])
	}

	emails := listChannels(t, h, "email")
	if len(emails) != 1 || emails[0]["id"] != "email-ormnes-domain" {
		t.Fatalf("email channels = %v", emails)
	}
	if phones := listChannels(t, h, "phone"); len(phones) != 0 {
		t.Fatalf("phone channels = %v, want none", phones)
	}

	id, _ := created["id"].(string)
	if code, _ := callChannelRoute(t, h, http.MethodDelete, "/v8/management/supply/channels/"+id, "", id); code != http.StatusOK {
		t.Fatalf("delete status = %d", code)
	}
	if emails := listChannels(t, h, "email"); len(emails) != 0 {
		t.Fatalf("channels after delete = %v", emails)
	}
}

// A nature that cannot serve the kind is refused at save time rather than
// failing later at the first call.
func TestSupplyChannelRejectsNatureForKind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lockedStore(t)
	h := newChannelHandler(t)

	code, payload := callChannelRoute(t, h, http.MethodPost, "/v8/management/supply/channels",
		`{"kind":"phone","label":"My Mailbox","nature":"imap"}`, "")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %v)", code, payload)
	}
	if channels := listChannels(t, h, "phone"); len(channels) != 0 {
		t.Fatalf("a refused channel was stored anyway: %v", channels)
	}
}

// Updating by id edits in place instead of creating a second channel.
func TestSupplyChannelUpdateInPlace(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lockedStore(t)
	h := newChannelHandler(t)

	_, payload := callChannelRoute(t, h, http.MethodPost, "/v8/management/supply/channels",
		`{"kind":"phone","label":"Haozhuma","nature":"api"}`, "")
	created, _ := payload["channel"].(map[string]any)
	id, _ := created["id"].(string)

	code, updated := callChannelRoute(t, h, http.MethodPost, "/v8/management/supply/channels",
		`{"id":"`+id+`","kind":"phone","label":"Haozhuma (main)","nature":"api","enabled":false}`, "")
	if code != http.StatusOK {
		t.Fatalf("update status = %d", code)
	}
	channel, _ := updated["channel"].(map[string]any)
	if channel["id"] != id || channel["label"] != "Haozhuma (main)" || channel["enabled"] != false {
		t.Fatalf("updated = %v", channel)
	}
	if channels := listChannels(t, h, "phone"); len(channels) != 1 {
		t.Fatalf("channels = %v, want the one updated in place", channels)
	}
}

// The panel must offer exactly the natures the host accepts per kind.
func TestSupplyChannelsReportNatureKinds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	lockedStore(t)
	h := newChannelHandler(t)

	_, payload := callChannelRoute(t, h, http.MethodGet, "/v8/management/supply/channels", "", "")
	natures, _ := payload["natures"].([]any)
	got := map[string][]string{}
	for _, item := range natures {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := entry["nature"].(string)
		kinds, _ := entry["kinds"].([]any)
		for _, kind := range kinds {
			text, _ := kind.(string)
			got[name] = append(got[name], text)
		}
	}
	if len(got["api"]) != 2 || len(got["imap"]) != 1 || len(got["web"]) != 1 {
		t.Fatalf("nature kinds = %v", got)
	}
	if got["imap"][0] != "email" || got["web"][0] != "phone" {
		t.Fatalf("nature kinds = %v", got)
	}
}
