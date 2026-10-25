package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
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
// undeclared nature never appears, and a nature whose credential name is not in
// the store is unready — never offline, and never a network call.
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
	// IMAP is a real probe now, and this channel names a credential that is not
	// in the store: unready, and nothing left the process.
	assertProbeState(t, bothID, "imap", probes[bothID], "unready")
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

// pooledOf reads one channel's pooled counts from the list surface.
func pooledOf(t *testing.T, r *gin.Engine, id string) (map[string]any, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/supply/channels", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /supply/channels: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Channels []map[string]any `json:"channels"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	for _, channel := range resp.Channels {
		if channel["id"] != id {
			continue
		}
		pooled, ok := channel["pooled"].(map[string]any)
		return pooled, ok
	}
	t.Fatalf("channel %s is not in the list", id)
	return nil, false
}

// A channel row carries the count of identities the pool holds from it, so the
// panel never joins the pool by itself. Zero is a counted answer; "no pool to
// count" is not, so the field is absent rather than zero in that case.
func TestSupplyChannelReportsPooledCounts(t *testing.T) {
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })
	supply.SetDefault(nil)

	_, r := setupChannelTest(t)
	id := createChannel(t, r, `{"label":"Box","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"box@example.com","secret":"mail-key"}}}}`)

	if _, present := pooledOf(t, r, id); present {
		t.Fatal("a channel must not report a count when no pool is installed")
	}

	registry := supply.NewRegistry()
	pool := supply.NewPool()
	registry.SetPool(pool)
	supply.SetDefault(registry)

	pooled, present := pooledOf(t, r, id)
	if !present {
		t.Fatal("an empty pool still counts: zero is an answer, not an absence")
	}
	if got := pooled["email"]; got != float64(0) {
		t.Fatalf("email pooled = %v, want 0", got)
	}

	pool.Register(supply.KindEmail, "1@example.com", id, "loomy", "loomy-1", "", "registered", 1)
	pooled, _ = pooledOf(t, r, id)
	if got := pooled["email"]; got != float64(1) {
		t.Fatalf("email pooled = %v, want 1", got)
	}
	if _, ok := pooled["phone"]; ok {
		t.Error("a channel that serves only email must not report a phone count")
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

	body := `{"label":"Multi","category":"self-built","phone":{"enabled":true,"natures":["api","web"],"connections":{"api":{"secret":"a"},"web":{"secret":"w"}}},"email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"me@qq.com","secret":"s","domain":"ormnes.com"}}}}`
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

// A phone connection that names no credential is stamped with the configured
// platform credential name, and nothing else about the connection is rewritten.
//
// The phone kind has one platform credential per surface and its secret-store
// name lives in configuration, so a channel that left it out used to be reported
// by the probe as "no credential is named" while the credential was stored.
func TestSupplyChannelStampsPhoneCredentialNames(t *testing.T) {
	h, r := setupChannelTest(t)

	id := createChannel(t, r, `{"label":"Phone","phone":{"enabled":true,"natures":["api","web"],"connections":{"api":{"endpoint":"https://api.example.com","account":"operator"},"web":{"endpoint":"https://web.example.com"}}}}`)
	channel := storedChannel(t, h, id)
	if channel.Phone == nil {
		t.Fatal("the stored channel has no phone block")
	}
	if got := channel.Phone.Connections[supply.NatureAPI].Secret; got != "haozhuma" {
		t.Fatalf("api secret = %q, want the configured name %q", got, "haozhuma")
	}
	if got := channel.Phone.Connections[supply.NatureWeb].Secret; got != "haozhuma-ck" {
		t.Fatalf("web secret = %q, want the configured name %q", got, "haozhuma-ck")
	}
	// Only the secret is the host's: the rest of the connection is the
	// operator's and must survive the stamp unchanged.
	api := channel.Phone.Connections[supply.NatureAPI]
	if api.Endpoint != "https://api.example.com" || api.Account != "operator" {
		t.Fatalf("stamping rewrote the connection: endpoint=%q account=%q", api.Endpoint, api.Account)
	}
}

// The email kind is not the phone kind: the host does not stamp its credential,
// because the entry is named after the mailbox. A name the document already
// carries is kept — it may point at an entry stored under an older rule — and a
// document without one gets the derived name, which is what the panel relies on.
func TestSupplyChannelLeavesEmailConnectionsAlone(t *testing.T) {
	h, r := setupChannelTest(t)

	id := createChannel(t, r, `{"label":"Multi","category":"self-built","phone":{"enabled":true,"natures":["api"],"connections":{"api":{}}},"email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"box@example.com","secret":"mail-key","domain":"ormnes.com"}}}}`)
	channel := storedChannel(t, h, id)
	if channel.Email == nil {
		t.Fatal("the stored channel has no email block")
	}
	imap := channel.Email.Connections[supply.NatureIMAP]
	if imap.Account != "box@example.com" || imap.Usage != "self-domain" || imap.Domain != "ormnes.com" {
		t.Fatalf("the email connection was rewritten: %+v", imap)
	}
	if imap.Secret != "mail-key" {
		t.Fatalf("the email connection names %q, want the name it was saved with", imap.Secret)
	}

	derived := createChannel(t, r, `{"label":"Derived","category":"self-built","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"Box@Example.com","domain":"ormnes.com"}}}}`)
	nameless := storedChannel(t, h, derived).Email.Connections[supply.NatureIMAP]
	if want := supply.EmailCredentialName("Box@Example.com"); nameless.Secret != want {
		t.Fatalf("the email connection names %q, want the derived %q", nameless.Secret, want)
	}
}

// A per-connection exit survives an edit that does not mention it.
//
// The asymmetry is the reason: an exit is a proxy URL and may carry a password,
// so it is redacted on read, which means the panel can never send the original
// value back. Without this rule every edit made from the panel would erase it.
func TestSupplyChannelKeepsOmittedEgress(t *testing.T) {
	h, r := setupChannelTest(t)

	const egress = "http://pxuser:pxpass@127.0.0.1:8899"
	id := createChannel(t, r, `{"label":"Exit","category":"self-built","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"box@example.com","domain":"ormnes.com","egress":"`+egress+`"}}}}`)
	if got := storedChannel(t, h, id).Email.Connections[supply.NatureIMAP].Egress; got != egress {
		t.Fatalf("stored egress = %q, want the submitted value", got)
	}

	// The panel reads the exit redacted, so its next submission leaves the field
	// out entirely.
	body := `{"id":"` + id + `","label":"Renamed","category":"self-built","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"box@example.com","domain":"ormnes.com"}}}}`
	req := httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", rr.Code, rr.Body.String())
	}

	kept := storedChannel(t, h, id)
	if kept.Label != "Renamed" {
		t.Fatalf("label = %q, want the edit to apply", kept.Label)
	}
	if got := kept.Email.Connections[supply.NatureIMAP].Egress; got != egress {
		t.Fatalf("omitted egress erased the stored one: %q", got)
	}

	// A read reports it redacted, never the password.
	req = httptest.NewRequest(http.MethodGet, "/supply/channels", nil)
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "pxpass") {
		t.Fatal("the channel list echoed the proxy password")
	}
	if !strings.Contains(rr.Body.String(), "redacted") {
		t.Fatal("the channel list does not show the configured exit at all")
	}
}

// The stamped name is the configured one, not the built-in default: an install
// that names its phone credentials differently must get those names.
func TestSupplyChannelStampsConfiguredCredentialNames(t *testing.T) {
	h, r := setupChannelTestWithConfig(t, config.SupplyConfig{Phone: config.SupplyPhoneConfig{APISecret: "hz2", CookieSecret: "hz2-ck"}})

	id := createChannel(t, r, `{"label":"Phone","phone":{"enabled":true,"natures":["api","web"],"connections":{"api":{},"web":{}}}}`)
	channel := storedChannel(t, h, id)
	if got := channel.Phone.Connections[supply.NatureAPI].Secret; got != "hz2" {
		t.Fatalf("api secret = %q, want the configured %q", got, "hz2")
	}
	if got := channel.Phone.Connections[supply.NatureWeb].Secret; got != "hz2-ck" {
		t.Fatalf("web secret = %q, want the configured %q", got, "hz2-ck")
	}
}

// A declared nature with no connection entry at all still gets one, so the
// nature names a credential instead of being saved as a nameless connection.
func TestSupplyChannelStampsCredentialNamesWithoutConnections(t *testing.T) {
	h, r := setupChannelTest(t)

	id := createChannel(t, r, `{"label":"Phone","phone":{"enabled":true,"natures":["api"]}}`)
	channel := storedChannel(t, h, id)
	api, ok := channel.Phone.Connections[supply.NatureAPI]
	if !ok {
		t.Fatalf("api connection missing: %v", channel.Phone.Connections)
	}
	if api.Secret != "haozhuma" {
		t.Fatalf("api secret = %q, want the configured name %q", api.Secret, "haozhuma")
	}
}

// storedChannel re-reads one channel from the on-disk store, so a test asserts
// what was persisted rather than what the response happened to echo.
func storedChannel(t *testing.T, h *Handler, id string) supply.Channel {
	t.Helper()
	store, errStore := h.supplyChannels()
	if errStore != nil {
		t.Fatalf("load channels: %v", errStore)
	}
	channel, ok := store.Get(id)
	if !ok {
		t.Fatalf("channel %s is not on disk", id)
	}
	return channel
}

// setupChannelTestWithConfig is setupChannelTest with a supply section written,
// so a test can drive the phone kind's configured credential names.
func setupChannelTestWithConfig(t *testing.T, supplyCfg config.SupplyConfig) (*Handler, *gin.Engine) {
	t.Helper()
	h, r := setupChannelTest(t)
	h.cfg = &config.Config{Supply: supplyCfg}
	return h, r
}

// setupPoolTest installs an empty identity pool for the duration of a test and
// wires the two pool routes, so a registration can be reported and then read
// back the way the panel reads it.
func setupPoolTest(t *testing.T) (*Handler, *gin.Engine) {
	t.Helper()
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })

	registry := supply.NewRegistry()
	registry.SetPool(supply.NewPool())
	supply.SetDefault(registry)

	h, r := setupChannelTest(t)
	r.GET("/supply/pool", h.GetSupplyPool)
	r.POST("/supply/pool/accounts", h.PostSupplyPoolAccount)
	r.DELETE("/supply/pool/accounts", h.DeleteSupplyPoolAccount)
	return h, r
}

// TestSupplyPoolAccountRoundTrip checks that a reported registration is stored
// under its identity and read back with the channel that produced it and the
// accounts it produced. The panel draws one row per identity and one strip entry
// per project, so both halves have to survive the round trip.
func TestSupplyPoolAccountRoundTrip(t *testing.T) {
	_, r := setupPoolTest(t)

	bodies := []string{
		`{"kind":"email","address":"1@ormnes.com","channel_id":"ormnes","target":"loomy","account":"loomy-16723433586","outcome":"registered"}`,
		`{"kind":"email","address":"1@ormnes.com","target":"zcode-zai","account":"zcode-zai-0f101ea3","outcome":"registered"}`,
	}
	for _, body := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/supply/pool/accounts", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("POST /supply/pool/accounts: %d %s", rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/supply/pool?kind=email", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /supply/pool: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Records []map[string]any `json:"records"`
	}
	if errUnmarshal := json.Unmarshal(rr.Body.Bytes(), &resp); errUnmarshal != nil {
		t.Fatalf("decode: %v", errUnmarshal)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("records = %d, want 1 (one identity, two registrations)", len(resp.Records))
	}
	record := resp.Records[0]
	if record["address"] != "1@ormnes.com" || record["channel_id"] != "ormnes" {
		t.Fatalf("record = %v, want the address and the channel that handed it out", record)
	}
	projects, _ := record["projects"].([]any)
	if len(projects) != 2 {
		t.Fatalf("projects = %v, want both registrations", record["projects"])
	}
	first, _ := projects[0].(map[string]any)
	if first["target"] != "loomy" || first["account"] != "loomy-16723433586" {
		t.Fatalf("first project = %v, want loomy with its account", first)
	}
}

// TestSupplyPoolAccountRejectsIncomplete checks the report is refused when it
// does not name an identity or a registration: a half-filled report would show
// up as an identity nobody can trace.
func TestSupplyPoolAccountRejectsIncomplete(t *testing.T) {
	_, r := setupPoolTest(t)

	bodies := map[string]string{
		"no kind":    `{"address":"1@ormnes.com","target":"loomy"}`,
		"no address": `{"kind":"email","target":"loomy"}`,
		"no target":  `{"kind":"email","address":"1@ormnes.com"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/supply/pool/accounts", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestSupplyPoolAccountDelete checks that one identity can be removed from the
// ledger, and that removing it touches nothing else: the row is gone from the
// next read, the other identities stay, and asking twice is not a silent
// success.
//
// The credential behind the row is deliberately not deleted here. The record
// only named it, so a removal is a cleanup of the supply history; destroying the
// credential is a separate action, and this test would fail loudly if the
// handler started to reach past the ledger.
func TestSupplyPoolAccountDelete(t *testing.T) {
	_, r := setupPoolTest(t)

	post := func(body string) {
		req := httptest.NewRequest(http.MethodPost, "/supply/pool/accounts", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("POST /supply/pool/accounts: %d %s", rr.Code, rr.Body.String())
		}
	}
	del := func(query string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/supply/pool/accounts"+query, nil))
		return rr
	}
	addresses := func() []string {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/supply/pool?kind=email", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET /supply/pool: %d %s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Records []map[string]any `json:"records"`
		}
		if errUnmarshal := json.Unmarshal(rr.Body.Bytes(), &resp); errUnmarshal != nil {
			t.Fatalf("decode: %v", errUnmarshal)
		}
		out := make([]string, 0, len(resp.Records))
		for _, record := range resp.Records {
			address, _ := record["address"].(string)
			out = append(out, address)
		}
		return out
	}

	// Two identities, so a delete that emptied the ledger would be caught.
	post(`{"kind":"email","address":"1@ormnes.com","target":"loomy","account":"loomy-1"}`)
	post(`{"kind":"email","address":"2@ormnes.com","target":"loomy","account":"loomy-2"}`)
	if got := addresses(); len(got) != 2 {
		t.Fatalf("records = %v, want both identities", got)
	}

	// A kind outside the contract, and a request naming no identity, are refused
	// before the ledger is touched.
	if rr := del("?kind=wechat&address=1@ormnes.com"); rr.Code != http.StatusBadRequest {
		t.Fatalf("kind=wechat: %d %s, want 400", rr.Code, rr.Body.String())
	}
	if rr := del("?kind=email"); rr.Code != http.StatusBadRequest {
		t.Fatalf("no address: %d %s, want 400", rr.Code, rr.Body.String())
	}
	if got := addresses(); len(got) != 2 {
		t.Fatalf("a refused request changed the ledger: %v", got)
	}

	rr := del("?kind=email&address=1@ormnes.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("DELETE: %d %s", rr.Code, rr.Body.String())
	}
	if got := addresses(); len(got) != 1 || got[0] != "2@ormnes.com" {
		t.Fatalf("after delete records = %v, want only 2@ormnes.com", got)
	}

	// The same identity again is not a silent success: the row is gone, and the
	// caller has to be able to tell that from "removed".
	again := del("?kind=email&address=1@ormnes.com")
	if again.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d %s, want 404", again.Code, again.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if errUnmarshal := json.Unmarshal(again.Body.Bytes(), &body); errUnmarshal != nil {
		t.Fatalf("decode: %v", errUnmarshal)
	}
	if body.Code != "unknown_identity" {
		t.Fatalf("code = %q, want unknown_identity", body.Code)
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

	// Self-hosted category without a domain → 400: the category says this mailbox
	// receives for a domain, and codes are matched by address on it.
	body = `{"label":"bad","category":"self-built","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"me@qq.com"}}}}`
	req = httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("self-hosted-no-domain: %d, want 400", rr.Code)
	}

	// A domain on a third-party category → 400 as well: the two answers disagree,
	// and dropping the domain quietly would leave a channel that looks configured.
	body = `{"label":"bad","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"account":"me@qq.com","domain":"ormnes.com"}}}}`
	req = httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("third-party-with-domain: %d, want 400", rr.Code)
	}
}

// A body is usually Chinese, so the preview cut has to land on a rune boundary:
// slicing a multi-byte rune in half leaves a replacement character at the end of
// every truncated preview, which reads like a decoding bug in the mail itself.
func TestPreviewTextCutsOnRuneBoundary(t *testing.T) {
	got := previewText(strings.Repeat("验证码", 100))
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("a long body must be marked as truncated, got %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("the cut split a rune: %q", got)
	}
	if len(got) > emailPreviewBytes+len("…") {
		t.Fatalf("preview is %d bytes, want at most %d", len(got), emailPreviewBytes+len("…"))
	}

	if got := previewText("short  body\n"); got != "short body" {
		t.Fatalf("whitespace collapse: got %q", got)
	}
	if got := previewText(" \n\t "); got != "" {
		t.Fatalf("blank body: got %q", got)
	}
}

// A token-based mailbox is not a channel: its credential belongs to the mailbox,
// which makes it one bought identity — a pool record. A channel is one connection
// that covers many addresses, so these are refused when written. Accepting them
// is what used to grow the channel table by one row per mailbox.
func TestSupplyChannelRejectsTokenMailboxNatures(t *testing.T) {
	_, r := setupChannelTest(t)

	bodies := map[string]string{
		"oauth2":                           `{"label":"oauth2","email":{"enabled":true,"natures":["oauth2"],"connections":{"oauth2":{"endpoint":"outlook.office365.com:993","account":"box@outlook.com","client_id":"app-123"}}}}`,
		"graph":                            `{"label":"graph","email":{"enabled":true,"natures":["graph"],"connections":{"graph":{"account":"box@outlook.com","client_id":"app-123"}}}}`,
		"the retired own-mailbox category": `{"label":"own","category":"self-owned","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"endpoint":"imap.qq.com:993","account":"box@qq.com"}}}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
			}
		})
	}
}

// A mailbox is read one way, and a protocol address must be a host, not a URL.
// Both are refused when the channel is written: saving them would produce a
// channel that looks configured and reads nothing.
func TestSupplyChannelRejectsUnusableMailbox(t *testing.T) {
	_, r := setupChannelTest(t)

	bodies := map[string]string{
		"url endpoint": `{"label":"url","email":{"enabled":true,"natures":["imap"],"connections":{"imap":{"endpoint":"https://imap.qq.com","account":"box@qq.com"}}}}`,
		"no natures":   `{"label":"empty","email":{"enabled":true,"natures":[],"connections":{}}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/supply/channels", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s, want 400", name, rr.Code, rr.Body.String())
			}
		})
	}
}

// An address that carries its own credential is probed by dialling the mailbox
// that receives it. The three outcomes are kept apart on purpose: a mailbox that
// refused the login cannot receive mail, a credential that could not be read was
// never tried, and an address no mailbox receives can never be used at all.
func TestAddressProbeViewSeparatesUntriedFromUnreachable(t *testing.T) {
	online := addressProbeView("a@outlook.com", "connected, 3 mailboxes", nil)
	if online["state"] != probeOnline || online["detail"] != "connected, 3 mailboxes" {
		t.Fatalf("online = %v", online)
	}

	// The mailbox answered and refused the credential: offline, with the reason.
	refused := addressProbeView("a@outlook.com", "", fmt.Errorf("%w: AUTHENTICATE failed", email.ErrLoginRejected))
	if refused["state"] != probeOffline {
		t.Fatalf("refused = %v, want offline", refused)
	}

	// A credential that could not be read was never sent anywhere, so the state
	// is unready — the panel must not turn that into "unreachable".
	unready := addressProbeView("a@outlook.com", "", fmt.Errorf("%w: the store is locked", email.ErrCredential))
	if unready["state"] != probeUnready {
		t.Fatalf("unready = %v, want unready", unready)
	}

	// No mailbox covers the address: it can never receive mail, which is a real
	// failure rather than an untried one.
	unknown := addressProbeView("x@elsewhere.com", "", fmt.Errorf("%w: none", supply.ErrUnknownIdentity))
	if unknown["state"] != probeOffline {
		t.Fatalf("unknown identity = %v, want offline", unknown)
	}
	if detail, _ := unknown["detail"].(string); !strings.Contains(detail, "no configured mailbox") {
		t.Fatalf("detail = %q, want the address's own reason", detail)
	}
}

// probeSession stands in for a live mailbox so the address probe can be
// exercised through the route without a server.
type probeSession struct{}

func (probeSession) Mailboxes(context.Context) ([]string, error) {
	return []string{"INBOX", "Junk"}, nil
}

func (probeSession) Recent(context.Context, string, time.Time, email.FolderPosition, int) ([]email.Mail, uint32, error) {
	return nil, 0, nil
}

func (probeSession) Close() error { return nil }

// The address probe route answers per address: one connection per mailbox, and
// the address no mailbox receives is reported as unusable rather than untried.
func TestSupplyEmailProbeAnswersPerAddress(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "supply")
	cfgPath := filepath.Join(dir, "config.yaml")
	if errWrite := os.WriteFile(cfgPath, []byte("supply:\n  storage-dir: "+stateDir+"\n"), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
	if errMkdir := os.MkdirAll(stateDir, 0o755); errMkdir != nil {
		t.Fatalf("create supply dir: %v", errMkdir)
	}
	channels := supply.ChannelDocument{Version: 1, Channels: []supply.Channel{{
		ID:       "ormnes",
		Label:    "Ormnes",
		Category: "self-built",
		Email: &supply.KindConfig{
			Enabled: true,
			Natures: []supply.Nature{supply.NatureIMAP},
			Connections: map[supply.Nature]supply.Connection{
				supply.NatureIMAP: {Endpoint: "imap.example.com:993", Account: "box@example.com", Domain: "ormnes.com"},
			},
		},
	}}}
	raw, errMarshal := json.Marshal(channels)
	if errMarshal != nil {
		t.Fatalf("marshal channels: %v", errMarshal)
	}
	if errWrite := os.WriteFile(supply.ChannelPath(stateDir), raw, 0o600); errWrite != nil {
		t.Fatalf("write channels: %v", errWrite)
	}

	provider, errNew := email.New(email.Config{
		ChannelsPath: supply.ChannelPath(stateDir),
		Credential:   func(name string) (string, error) { return "auth-code-for-" + name, nil },
		Dial: func(context.Context, email.Target) (email.Session, error) {
			return probeSession{}, nil
		},
	})
	if errNew != nil {
		t.Fatalf("email.New: %v", errNew)
	}
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })
	registry := supply.NewRegistry()
	if errRegister := registry.Register(provider); errRegister != nil {
		t.Fatalf("register provider: %v", errRegister)
	}
	supply.SetDefault(registry)

	h := &Handler{configFilePath: cfgPath}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/supply/email/probe", h.PostSupplyEmailProbe)

	req := httptest.NewRequest(http.MethodPost, "/supply/email/probe", bytes.NewBufferString(`{"addresses":["abc@ormnes.com","ABC@ormnes.com","x@elsewhere.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("probe: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Probes []map[string]any `json:"probes"`
	}
	if errDecode := json.Unmarshal(rr.Body.Bytes(), &resp); errDecode != nil {
		t.Fatalf("decode: %v", errDecode)
	}
	// The duplicate is collapsed: one address is one connection.
	if len(resp.Probes) != 2 {
		t.Fatalf("probes = %v, want the two distinct addresses", resp.Probes)
	}
	byAddress := map[string]map[string]any{}
	for _, probe := range resp.Probes {
		address, _ := probe["address"].(string)
		byAddress[address] = probe
	}
	if state, _ := byAddress["abc@ormnes.com"]["state"].(string); state != probeOnline {
		t.Fatalf("covered address = %v, want online", byAddress["abc@ormnes.com"])
	}
	if state, _ := byAddress["x@elsewhere.com"]["state"].(string); state != probeOffline {
		t.Fatalf("uncovered address = %v, want offline", byAddress["x@elsewhere.com"])
	}

	// No address at all is a refused request, not a cheerful "all fine".
	empty := httptest.NewRequest(http.MethodPost, "/supply/email/probe", bytes.NewBufferString(`{"addresses":[]}`))
	empty.Header.Set("Content-Type", "application/json")
	emptyRecorder := httptest.NewRecorder()
	r.ServeHTTP(emptyRecorder, empty)
	if emptyRecorder.Code != http.StatusBadRequest {
		t.Fatalf("empty request: %d, want 400", emptyRecorder.Code)
	}
}
