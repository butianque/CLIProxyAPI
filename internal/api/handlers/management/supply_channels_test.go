package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

func setupChannelTest(t *testing.T) (*Handler, *gin.Engine) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("supply:\n  storage-dir: "+filepath.Join(dir, "supply")+"\n"), 0o600)
	os.MkdirAll(filepath.Join(dir, "supply"), 0o755)

	h := &Handler{configFilePath: cfgPath}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/supply/channels", h.GetSupplyChannels)
	r.POST("/supply/channels", h.PostSupplyChannel)
	r.DELETE("/supply/channels/:id", h.DeleteSupplyChannel)
	r.POST("/supply/channels/probe", h.PostSupplyChannelProbe)
	return h, r
}

// createChannel stores one channel through the surface the panel uses, so the
// probe tests exercise stored channels rather than hand-built ones.
func createChannel(t *testing.T, r *gin.Engine, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /supply/channels: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)
	channel, _ := resp["channel"].(map[string]any)
	id, _ := channel["id"].(string)
	if id == "" {
		t.Fatalf("created channel has no id: %s", rr.Body.String())
	}
	return id
}

// unlockedEmptyStore installs an initialized but empty store for the duration
// of a test. No credential is written: a probe for a name it does not hold must
// report unready without sending anything anywhere.
func unlockedEmptyStore(t *testing.T) {
	t.Helper()
	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	if errInitialize := store.Initialize("master"); errInitialize != nil {
		t.Fatalf("initialize store: %v", errInitialize)
	}
	if !store.Unlocked() {
		t.Fatal("a freshly initialized store is unlocked")
	}
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })
}

// probeStates is the closed set of states the probe contract allows.
var probeStates = []string{"online", "offline", "unready", "unsupported"}

// probeNatures posts a probe and returns each probed channel's natures block.
func probeNatures(t *testing.T, r *gin.Engine, body string) map[string]map[string]map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/supply/channels/probe", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /supply/channels/probe: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
		Probes []struct {
			ID      string                    `json:"id"`
			Natures map[string]map[string]any `json:"natures"`
		} `json:"probes"`
	}
	if errDecode := json.Unmarshal(rr.Body.Bytes(), &resp); errDecode != nil {
		t.Fatalf("decode probe response %s: %v", rr.Body.String(), errDecode)
	}
	if resp.Status != "ok" {
		t.Fatalf("status = %q, want ok", resp.Status)
	}
	out := make(map[string]map[string]map[string]any, len(resp.Probes))
	for _, probe := range resp.Probes {
		for nature, entry := range probe.Natures {
			state, _ := entry["state"].(string)
			if !slices.Contains(probeStates, state) {
				t.Fatalf("channel %s nature %s: state %q is outside the contract", probe.ID, nature, state)
			}
		}
		out[probe.ID] = probe.Natures
	}
	return out
}

// assertProbeState checks one nature's reported state.
func assertProbeState(t *testing.T, channelID, nature string, natures map[string]map[string]any, want string) {
	t.Helper()
	entry, ok := natures[nature]
	if !ok {
		t.Fatalf("channel %s: nature %q missing from %v", channelID, nature, natures)
	}
	if state, _ := entry["state"].(string); state != want {
		t.Fatalf("channel %s nature %s: state = %q (detail %v), want %q", channelID, nature, state, entry["detail"], want)
	}
}

// The probe answers with one state per declared nature and nothing else: an
// undeclared nature never appears, a phone nature whose credential name is not
// in the store is unready (never offline, and never a network call), and the
// email kind has no probe at all.
func TestSupplyChannelProbeReportsDeclaredNatures(t *testing.T) {
	_, r := setupChannelTest(t)
	unlockedEmptyStore(t)

	phoneID := createChannel(t, r, `{"label":"Phone","phone":{"enabled":true,"natures":["api"],"connections":{"api":{"endpoint":"https://api.example.com","secret":"hz-api"}}}}`)
	bothID := createChannel(t, r, `{"label":"Both","phone":{"enabled":true,"natures":["api","web"],"connections":{"api":{"secret":"hz-api"},"web":{"secret":"hz-web"}}},"email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"box@example.com","secret":"mail-key"}}}}`)

	// No body at all means "probe everything".
	probes := probeNatures(t, r, "")
	if len(probes) != 2 {
		t.Fatalf("probed %d channels, want 2: %v", len(probes), probes)
	}

	// The endpoint is set but the secret name is not in the store: the honest
	// answer is unready, because nothing was ever sent.
	assertProbeState(t, phoneID, "api", probes[phoneID], "unready")
	if len(probes[phoneID]) != 1 {
		t.Fatalf("channel %s: probed %v, want only the declared api nature", phoneID, probes[phoneID])
	}

	assertProbeState(t, bothID, "api", probes[bothID], "unready")
	assertProbeState(t, bothID, "web", probes[bothID], "unready")
	// IMAP has not landed in the base, so the email kind is unsupported.
	assertProbeState(t, bothID, "imap", probes[bothID], "unsupported")
	if len(probes[bothID]) != 3 {
		t.Fatalf("channel %s: probed %v, want the three declared natures", bothID, probes[bothID])
	}
}

// A locked store cannot name a credential either, so every phone nature is
// unready and no probe leaves the process.
func TestSupplyChannelProbeLockedStoreIsUnready(t *testing.T) {
	_, r := setupChannelTest(t)
	lockedStore(t)

	id := createChannel(t, r, `{"label":"Phone","phone":{"enabled":true,"natures":["api","web"],"connections":{"api":{"endpoint":"https://api.example.com","secret":"hz-api"},"web":{"secret":"hz-web"}}}}`)
	probes := probeNatures(t, r, `{"ids":["`+id+`"]}`)
	assertProbeState(t, id, "api", probes[id], "unready")
	assertProbeState(t, id, "web", probes[id], "unready")
}

// An id nobody has is skipped rather than reported as an error, and an empty
// ids list means "probe everything".
func TestSupplyChannelProbeSkipsUnknownIDs(t *testing.T) {
	_, r := setupChannelTest(t)
	unlockedEmptyStore(t)

	id := createChannel(t, r, `{"label":"Phone","phone":{"enabled":true,"natures":["api"],"connections":{"api":{"secret":"hz-api"}}}}`)
	if probes := probeNatures(t, r, `{"ids":["no-such-channel"]}`); len(probes) != 0 {
		t.Fatalf("unknown id produced %v, want nothing", probes)
	}
	if probes := probeNatures(t, r, `{"ids":[]}`); len(probes) != 1 {
		t.Fatalf("an empty ids list produced %v, want every channel", probes)
	}
	if probes := probeNatures(t, r, `{"ids":["`+id+`"]}`); len(probes) != 1 {
		t.Fatalf("named id produced %v, want that one channel", probes)
	}
}

// The probe's answer never repeats what it read. The connection's secret field
// is meant to hold a secret-store name, but a channel can be saved with a raw
// credential in it; the response must not become the one place that value
// escapes, and the same holds for anything the store does return.
func TestSupplyChannelProbeNeverEchoesTheCredential(t *testing.T) {
	_, r := setupChannelTest(t)
	unlockedEmptyStore(t)

	const stored = "sk-live-do-not-echo"
	id := createChannel(t, r, `{"label":"Phone","phone":{"enabled":true,"natures":["api"],"connections":{"api":{"secret":"`+stored+`"}}}}`)

	req := httptest.NewRequest(http.MethodPost, "/supply/channels/probe", bytes.NewBufferString(`{"ids":["`+id+`"]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("probe: %d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, stored) {
		t.Fatalf("the probe response echoed the stored value: %s", body)
	}
	if !strings.Contains(body, "unready") {
		t.Fatalf("body = %s, want the unready state", body)
	}
}

func TestSupplyChannelsRoundTrip(t *testing.T) {
	_, r := setupChannelTest(t)

	// Create a phone-only channel.
	body := `{"label":"Haozhuma","category":"third-party","phone":{"enabled":true,"natures":["api"],"connections":{"api":{"endpoint":"https://api.hz.com","secret":"hz-key"}}}}`
	req := httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rr.Code, rr.Body.String())
	}

	var postResp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &postResp)
	channel := postResp["channel"].(map[string]any)
	if channel["label"] != "Haozhuma" {
		t.Errorf("label = %v", channel["label"])
	}
	if channel["phone"] == nil {
		t.Fatal("phone block missing")
	}

	// List all.
	req = httptest.NewRequest(http.MethodGet, "/supply/channels", nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	var listResp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &listResp)
	channels := listResp["channels"].([]any)
	if len(channels) != 1 {
		t.Errorf("list: %d channels", len(channels))
	}

	// Delete.
	id := channel["id"].(string)
	req = httptest.NewRequest(http.MethodDelete, "/supply/channels/"+id, nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("DELETE: %d", rr.Code)
	}

	// List again — empty.
	req = httptest.NewRequest(http.MethodGet, "/supply/channels", nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	json.Unmarshal(rr.Body.Bytes(), &listResp)
	channels = listResp["channels"].([]any)
	if len(channels) != 0 {
		t.Errorf("after delete: %d", len(channels))
	}
}

func TestSupplyChannelBothKinds(t *testing.T) {
	_, r := setupChannelTest(t)

	body := `{"label":"Multi","phone":{"enabled":true,"natures":["api","web"],"connections":{"api":{"secret":"a"},"web":{"secret":"w"}}},"email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"me@qq.com","secret":"s","usage":"self-domain","domain":"ormnes.com"}}}}`
	req := httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)
	ch := resp["channel"].(map[string]any)
	if ch["phone"] == nil || ch["email"] == nil {
		t.Fatal("both kinds must be present")
	}

	// List by kind=phone — should include it.
	req = httptest.NewRequest(http.MethodGet, "/supply/channels?kind=phone", nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp["channels"].([]any)) != 1 {
		t.Error("phone list should have 1")
	}

	// List by kind=email — should include it.
	req = httptest.NewRequest(http.MethodGet, "/supply/channels?kind=email", nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp["channels"].([]any)) != 1 {
		t.Error("email list should have 1")
	}
}

func TestSupplyChannelRejectsInvalid(t *testing.T) {
	_, r := setupChannelTest(t)

	// No kind configured → 400.
	body := `{"label":"empty"}`
	req := httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("no-kind: %d, want 400", rr.Code)
	}

	// IMAP on phone → 400.
	body = `{"label":"bad","phone":{"enabled":true,"natures":["imap"],"connections":{"imap":{}}}}`
	req = httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("imap-phone: %d, want 400", rr.Code)
	}

	// Self-domain without domain → 400.
	body = `{"label":"bad","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"usage":"self-domain"}}}}`
	req = httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("self-domain-no-domain: %d, want 400", rr.Code)
	}
}
