package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// egressPoolFixture is a handler wired to an empty supply directory and auth
// directory, plus the router the panel talks to.
type egressPoolFixture struct {
	handler  *Handler
	router   *gin.Engine
	supplyAt string
	authAt   string
}

func setupEgressPool(t *testing.T) egressPoolFixture {
	t.Helper()
	dir := t.TempDir()
	supplyAt := filepath.Join(dir, "supply")
	authAt := filepath.Join(dir, "auths")
	if err := os.MkdirAll(supplyAt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(authAt, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("supply:\n  storage-dir: "+supplyAt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Handler{configFilePath: cfgPath, cfg: &config.Config{AuthDir: authAt}}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/egress/pool", h.GetEgressPool)
	r.POST("/egress/pool", h.PostEgressPool)
	r.POST("/egress/pool/next", h.PostEgressPoolNext)
	r.PATCH("/egress/pool/:id", h.PatchEgressPool)
	r.DELETE("/egress/pool/:id", h.DeleteEgressPool)
	r.GET("/egress/pool/:id/members", h.GetEgressPoolMembers)
	r.POST("/egress/pool/:id/bind", h.PostEgressPoolBind)
	r.POST("/egress/unbind", h.PostEgressPoolUnbind)
	return egressPoolFixture{handler: h, router: r, supplyAt: supplyAt, authAt: authAt}
}

func (f egressPoolFixture) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	out := map[string]any{}
	if trimmed := strings.TrimSpace(rr.Body.String()); trimmed != "" {
		if err := json.Unmarshal([]byte(trimmed), &out); err != nil {
			t.Fatalf("%s %s returned non-JSON: %s", method, path, trimmed)
		}
	}
	return rr.Code, out
}

// (f) add stores one exit through the surface and returns its id.
func (f egressPoolFixture) add(t *testing.T, body string) int {
	t.Helper()
	status, out := f.do(t, http.MethodPost, "/egress/pool", body)
	if status != http.StatusOK {
		t.Fatalf("POST /egress/pool = %d %v", status, out)
	}
	entry, _ := out["entry"].(map[string]any)
	id, _ := entry["id"].(float64)
	if id == 0 {
		t.Fatalf("added entry has no id: %v", out)
	}
	return int(id)
}

// (f) stored reads the pool document back from disk, which is what proves a
// password survived an edit the panel only ever saw redacted.
func (f egressPoolFixture) stored(t *testing.T) supply.EgressPoolDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.supplyAt, "egress-pool.json"))
	if err != nil {
		t.Fatalf("read pool: %v", err)
	}
	var doc supply.EgressPoolDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode pool: %v", err)
	}
	return doc
}

const testEgressURL = "socks5://probeuser:probeSecret@10.0.0.1:1080"

// TestEgressPoolStartsEmpty pins that a fresh installation reports an empty
// list rather than a missing field: "nothing configured" is an answer.
func TestEgressPoolStartsEmpty(t *testing.T) {
	f := setupEgressPool(t)
	status, out := f.do(t, http.MethodGet, "/egress/pool", "")
	if status != http.StatusOK {
		t.Fatalf("GET /egress/pool = %d", status)
	}
	entries, ok := out["entries"].([]any)
	if !ok {
		t.Fatalf("entries is %T, want an empty array", out["entries"])
	}
	if len(entries) != 0 {
		t.Fatalf("empty pool listed %d entries", len(entries))
	}
	supplyView, _ := out["supply"].(map[string]any)
	if bound, _ := supplyView["bound"].(bool); bound {
		t.Fatal("an unconfigured supply exit was reported as bound")
	}
}

// TestEgressPoolNeverReturnsThePassword pins the one thing this surface must
// never do: hand a proxy password back to whoever can open the panel.
func TestEgressPoolNeverReturnsThePassword(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)

	status, out := f.do(t, http.MethodGet, "/egress/pool", "")
	if status != http.StatusOK {
		t.Fatalf("GET /egress/pool = %d", status)
	}
	encoded, _ := json.Marshal(out)
	if strings.Contains(string(encoded), "probeSecret") {
		t.Fatalf("the pool listing leaked the proxy password: %s", encoded)
	}
	entry, _ := out["entries"].([]any)[0].(map[string]any)
	if url, _ := entry["url"].(string); !strings.Contains(url, "redacted") {
		t.Fatalf("url = %q, want a redacted address", url)
	}
	if got, _ := entry["id"].(float64); int(got) != id {
		t.Fatalf("id = %v, want %d", entry["id"], id)
	}
}

// TestEgressPoolRejectsANonProxyAddress pins that the pool refuses an address it
// cannot route through, at the boundary rather than at the first request.
func TestEgressPoolRejectsANonProxyAddress(t *testing.T) {
	f := setupEgressPool(t)
	for _, body := range []string{`{"url":"direct"}`, `{"url":""}`, `{"url":"10.0.0.1:1080"}`} {
		status, out := f.do(t, http.MethodPost, "/egress/pool", body)
		if status != http.StatusBadRequest {
			t.Fatalf("POST %s = %d %v, want 400", body, status, out)
		}
	}
}

// TestEgressPoolEditKeepsThePassword pins the read/write asymmetry: the panel
// sees a redacted address, so an edit that echoes it (or leaves it out) must not
// replace the stored password with the literal "redacted".
func TestEgressPoolEditKeepsThePassword(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)

	for _, body := range []string{
		`{"label":"改了备注"}`,
		`{"label":"再改","url":"socks5://redacted@10.0.0.1:1080"}`,
		`{"label":"清空","url":""}`,
	} {
		status, out := f.do(t, http.MethodPatch, "/egress/pool/"+itoa(id), body)
		if status != http.StatusOK {
			t.Fatalf("PATCH %s = %d %v", body, status, out)
		}
	}
	doc := f.stored(t)
	if len(doc.Entries) != 1 {
		t.Fatalf("pool holds %d entries, want 1", len(doc.Entries))
	}
	if doc.Entries[0].URL != testEgressURL {
		t.Fatalf("url = %q, want the stored password to survive", doc.Entries[0].URL)
	}
	if doc.Entries[0].Label != "清空" {
		t.Fatalf("label = %q, want the last submitted one", doc.Entries[0].Label)
	}
}

// TestEgressPoolCountsBindings pins what the pool is for: saying which accounts
// and channels sit behind one exit, counting the ways a binding is written.
func TestEgressPoolCountsBindings(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)

	// One account names the exit by id, the other by the address itself: an
	// installation that predates the pool has addresses, and those are still
	// real bindings.
	if err := os.WriteFile(filepath.Join(f.authAt, "zcode-1.json"),
		[]byte(`{"type":"zcode","egress_id":`+itoa(id)+`,"proxy_url":"`+testEgressURL+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.authAt, "loomy-1.json"),
		[]byte(`{"type":"loomy","proxy_url":"`+testEgressURL+`/"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	channels := `{"version":1,"channels":[{"id":"mbx-1","label":"outlook-1","category":"third-party",
	  "email":{"enabled":true,"natures":["imap"],"connections":{"imap":{
	    "endpoint":"imap.example.com:993","account":"a@example.com","egress":"` + testEgressURL + `"}}}}]}`
	if err := os.WriteFile(filepath.Join(f.supplyAt, "channels.json"), []byte(channels), 0o600); err != nil {
		t.Fatal(err)
	}

	status, out := f.do(t, http.MethodGet, "/egress/pool", "")
	if status != http.StatusOK {
		t.Fatalf("GET /egress/pool = %d", status)
	}
	entry, _ := out["entries"].([]any)[0].(map[string]any)
	counts, _ := entry["counts"].(map[string]any)
	if got, _ := counts["account"].(float64); int(got) != 2 {
		t.Fatalf("accounts = %v, want 2 (one by id, one by address)", counts["account"])
	}
	if got, _ := counts["channel"].(float64); int(got) != 1 {
		t.Fatalf("channels = %v, want 1", counts["channel"])
	}
	if total, _ := entry["total"].(float64); int(total) != 3 {
		t.Fatalf("total = %v, want 3", entry["total"])
	}

	status, out = f.do(t, http.MethodGet, "/egress/pool/"+itoa(id)+"/members", "")
	if status != http.StatusOK {
		t.Fatalf("GET members = %d", status)
	}
	members, _ := out["members"].([]any)
	if len(members) != 3 {
		t.Fatalf("members = %v, want three", members)
	}
}

// TestEgressPoolCountsTheSupplyExitByID pins that the supply-wide exit is a
// binding too, and that naming it by id counts on that id rather than on the
// address a resolved copy would suggest.
func TestEgressPoolCountsTheSupplyExitByID(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)
	f.handler.cfg.Supply.EgressID = id

	status, out := f.do(t, http.MethodGet, "/egress/pool", "")
	if status != http.StatusOK {
		t.Fatalf("GET /egress/pool = %d", status)
	}
	entry, _ := out["entries"].([]any)[0].(map[string]any)
	counts, _ := entry["counts"].(map[string]any)
	if got, _ := counts["supply"].(float64); int(got) != 1 {
		t.Fatalf("supply = %v, want 1", counts["supply"])
	}

	status, _ = f.do(t, http.MethodDelete, "/egress/pool/"+itoa(id), "")
	if status != http.StatusConflict {
		t.Fatalf("DELETE of an exit supply traffic leaves through = %d, want 409", status)
	}
}

// TestEgressPoolCountsTheSupplyExit pins that the supply-wide exit is a binding
// too: it is the one an imported identity leaves through.
func TestEgressPoolCountsTheSupplyExit(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)
	f.handler.cfg.Supply.Egress = testEgressURL

	status, out := f.do(t, http.MethodGet, "/egress/pool", "")
	if status != http.StatusOK {
		t.Fatalf("GET /egress/pool = %d", status)
	}
	supplyView, _ := out["supply"].(map[string]any)
	if bound, _ := supplyView["bound"].(bool); !bound {
		t.Fatal("the configured supply exit was not reported as bound")
	}
	entry, _ := out["entries"].([]any)[0].(map[string]any)
	counts, _ := entry["counts"].(map[string]any)
	if got, _ := counts["supply"].(float64); int(got) != 1 {
		t.Fatalf("supply = %v, want 1", counts["supply"])
	}

	// Deleting an exit that supply traffic leaves through would take every
	// imported identity offline, so it is refused until it is moved.
	status, out = f.do(t, http.MethodDelete, "/egress/pool/"+itoa(id), "")
	if status != http.StatusConflict {
		t.Fatalf("DELETE of a bound exit = %d %v, want 409", status, out)
	}
}

// TestEgressPoolDeletesAnUnboundExit pins that an unused entry can go.
func TestEgressPoolDeletesAnUnboundExit(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)
	status, out := f.do(t, http.MethodDelete, "/egress/pool/"+itoa(id), "")
	if status != http.StatusOK {
		t.Fatalf("DELETE = %d %v", status, out)
	}
	if doc := f.stored(t); len(doc.Entries) != 0 {
		t.Fatalf("pool still holds %d entries", len(doc.Entries))
	}
}

// TestEgressPoolNextIsInspectable pins that the assignment rule can be asked
// before an account exists, and that a disabled exit is never chosen.
func TestEgressPoolNextIsInspectable(t *testing.T) {
	f := setupEgressPool(t)
	first := f.add(t, `{"url":"socks5://u:p@10.0.0.1:1080","label":"one"}`)
	second := f.add(t, `{"url":"socks5://u:p@10.0.0.2:1080","label":"two"}`)

	status, out := f.do(t, http.MethodPost, "/egress/pool/next", "")
	if status != http.StatusOK {
		t.Fatalf("POST next = %d", status)
	}
	entry, _ := out["entry"].(map[string]any)
	if got, _ := entry["id"].(float64); int(got) != first {
		t.Fatalf("next = %v, want #%d (tie broken by the lowest id)", entry["id"], first)
	}

	status, _ = f.do(t, http.MethodPatch, "/egress/pool/"+itoa(first), `{"enabled":false}`)
	if status != http.StatusOK {
		t.Fatalf("disable #%d = %d", first, status)
	}
	status, out = f.do(t, http.MethodPost, "/egress/pool/next", "")
	if status != http.StatusOK {
		t.Fatalf("POST next = %d", status)
	}
	entry, _ = out["entry"].(map[string]any)
	if got, _ := entry["id"].(float64); int(got) != second {
		t.Fatalf("next = %v, want #%d: a disabled exit must not be assigned", entry["id"], second)
	}
}

// TestEgressPoolRejectsABadID pins that a malformed path answers 400 instead of
// silently acting on id 0.
func TestEgressPoolRejectsABadID(t *testing.T) {
	f := setupEgressPool(t)
	for _, path := range []string{"/egress/pool/abc", "/egress/pool/0", "/egress/pool/-1"} {
		status, _ := f.do(t, http.MethodDelete, path, "")
		if status != http.StatusBadRequest {
			t.Fatalf("DELETE %s = %d, want 400", path, status)
		}
	}
	status, _ := f.do(t, http.MethodPatch, "/egress/pool/99", `{"label":"x"}`)
	if status != http.StatusNotFound {
		t.Fatalf("PATCH a missing id = %d, want 404", status)
	}
}

// TestEgressPoolCountsAChannelByID pins that a channel naming an exit by id is
// counted once, on that id — not also against whatever address happens to sit
// beside it in the document.
func TestEgressPoolCountsAChannelByID(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)
	other := f.add(t, `{"url":"socks5://u:p@10.0.0.2:1080","label":"香港 #2"}`)

	// The stored address is the one from #1, but the binding says #2. The id
	// wins, so #1 must not be credited with this channel.
	channels := `{"version":1,"channels":[{"id":"mbx-1","label":"outlook-1","category":"third-party",
	  "email":{"enabled":true,"natures":["imap"],"connections":{"imap":{
	    "endpoint":"imap.example.com:993","account":"a@example.com",
	    "egress":"` + testEgressURL + `","egress_id":` + itoa(other) + `}}}}]}`
	if err := os.WriteFile(filepath.Join(f.supplyAt, "channels.json"), []byte(channels), 0o600); err != nil {
		t.Fatal(err)
	}

	status, out := f.do(t, http.MethodGet, "/egress/pool", "")
	if status != http.StatusOK {
		t.Fatalf("GET /egress/pool = %d", status)
	}
	entries, _ := out["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("listed %d entries, want 2", len(entries))
	}
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		counts, _ := entry["counts"].(map[string]any)
		got, _ := counts["channel"].(float64)
		switch int(entry["id"].(float64)) {
		case id:
			if got != 0 {
				t.Fatalf("#%d counted %v channels, want 0: the channel names #%d", id, counts["channel"], other)
			}
		case other:
			if got != 1 {
				t.Fatalf("#%d counted %v channels, want 1", other, counts["channel"])
			}
		}
	}
}

// TestEgressPoolResolvesAChannelAddressForTheProbe pins that the probe reaches
// the pool's address rather than a stale one, and that a dangling id fails
// closed instead of probing from the host's own address.
func TestEgressPoolResolvesAChannelAddressForTheProbe(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)

	channel := supply.Channel{
		ID:    "mbx-1",
		Label: "outlook-1",
		Email: &supply.KindConfig{
			Enabled: true,
			Natures: []supply.Nature{supply.NatureIMAP},
			Connections: map[supply.Nature]supply.Connection{
				supply.NatureIMAP: {Endpoint: "imap.example.com:993", Account: "a@example.com", EgressID: id},
			},
		},
	}
	resolved := f.handler.applyEgressIDs(channel)
	if got := resolved.Email.Connections[supply.NatureIMAP].Egress; got != testEgressURL {
		t.Fatalf("resolved egress = %q, want the pool's address", got)
	}
	// The channel handed in is untouched: the store's own state must keep the
	// id, or the next save would replace the binding with an address.
	if got := channel.Email.Connections[supply.NatureIMAP].Egress; got != "" {
		t.Fatalf("applyEgressIDs mutated its input: egress = %q", got)
	}

	channel.Email.Connections[supply.NatureIMAP] = supply.Connection{
		Endpoint: "imap.example.com:993", Account: "a@example.com", EgressID: 99,
	}
	resolved = f.handler.applyEgressIDs(channel)
	if got := resolved.Email.Connections[supply.NatureIMAP].Egress; got != supply.UnresolvedEgress {
		t.Fatalf("dangling id resolved to %q, want %q", got, supply.UnresolvedEgress)
	}
}

// TestEgressPoolBindWritesTheIDOnly pins what a binding is: an id, never a copy
// of the address. A copy would make replacing an exit an N-place edit, which is
// the whole thing the pool exists to avoid.
func TestEgressPoolBindWritesTheIDOnly(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)

	channel := supply.Channel{
		ID:    "mbx-1",
		Label: "outlook-1",
		Email: &supply.KindConfig{
			Enabled: true,
			Natures: []supply.Nature{supply.NatureIMAP},
			Connections: map[supply.Nature]supply.Connection{
				supply.NatureIMAP: {Endpoint: "imap.example.com:993", Account: "a@example.com"},
			},
		},
	}
	store, errStore := supply.LoadChannels(supply.ChannelPath(f.supplyAt))
	if errStore != nil {
		t.Fatalf("LoadChannels: %v", errStore)
	}
	if _, errUpsert := store.Upsert(channel, 1); errUpsert != nil {
		t.Fatalf("Upsert: %v", errUpsert)
	}

	body := `{"kind":"channel","name":"mbx-1","supply_kind":"email","nature":"imap"}`
	status, out := f.do(t, http.MethodPost, "/egress/pool/"+itoa(id)+"/bind", body)
	if status != http.StatusOK {
		t.Fatalf("bind = %d %v", status, out)
	}

	stored, errLoad := supply.LoadChannels(supply.ChannelPath(f.supplyAt))
	if errLoad != nil {
		t.Fatalf("LoadChannels: %v", errLoad)
	}
	got, found := stored.Get("mbx-1")
	if !found {
		t.Fatal("channel disappeared")
	}
	connection := got.Email.Connections[supply.NatureIMAP]
	if connection.EgressID != id {
		t.Fatalf("egress_id = %d, want %d", connection.EgressID, id)
	}
	if connection.Egress != "" {
		t.Fatalf("bind copied the address into the channel: %q", connection.Egress)
	}

	// The pool now credits this channel to the exit.
	status, out = f.do(t, http.MethodGet, "/egress/pool", "")
	if status != http.StatusOK {
		t.Fatalf("GET /egress/pool = %d", status)
	}
	entry, _ := out["entries"].([]any)[0].(map[string]any)
	counts, _ := entry["counts"].(map[string]any)
	if got, _ := counts["channel"].(float64); int(got) != 1 {
		t.Fatalf("channels = %v, want 1", counts["channel"])
	}
}

// TestEgressPoolUnbindClearsTheStaleAddress pins that releasing a target does
// not leave it pointing at the exit it was just released from: an account that
// reads as "unbound" in the panel must not keep sending traffic from the burnt
// address on the wire.
func TestEgressPoolUnbindClearsTheStaleAddress(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)

	channel := supply.Channel{
		ID:    "mbx-1",
		Label: "outlook-1",
		Email: &supply.KindConfig{
			Enabled: true,
			Natures: []supply.Nature{supply.NatureIMAP},
			Connections: map[supply.Nature]supply.Connection{
				supply.NatureIMAP: {
					Endpoint: "imap.example.com:993",
					Account:  "a@example.com",
					Egress:   testEgressURL,
					EgressID: id,
				},
			},
		},
	}
	store, errStore := supply.LoadChannels(supply.ChannelPath(f.supplyAt))
	if errStore != nil {
		t.Fatalf("LoadChannels: %v", errStore)
	}
	if _, errUpsert := store.Upsert(channel, 1); errUpsert != nil {
		t.Fatalf("Upsert: %v", errUpsert)
	}

	status, out := f.do(t, http.MethodPost, "/egress/unbind", `{"kind":"channel","name":"mbx-1"}`)
	if status != http.StatusOK {
		t.Fatalf("unbind = %d %v", status, out)
	}

	stored, errLoad := supply.LoadChannels(supply.ChannelPath(f.supplyAt))
	if errLoad != nil {
		t.Fatalf("LoadChannels: %v", errLoad)
	}
	got, _ := stored.Get("mbx-1")
	connection := got.Email.Connections[supply.NatureIMAP]
	if connection.EgressID != 0 || connection.Egress != "" {
		t.Fatalf("after unbind the channel still names an exit: id=%d egress=%q", connection.EgressID, connection.Egress)
	}
}

// TestEgressPoolBindRejectsAnUnknownTarget pins that a typo answers 400 instead
// of silently doing nothing.
func TestEgressPoolBindRejectsAnUnknownTarget(t *testing.T) {
	f := setupEgressPool(t)
	id := f.add(t, `{"url":"`+testEgressURL+`","label":"香港 #1"}`)

	for _, body := range []string{
		`{"kind":"channel","name":"nope"}`,
		`{"kind":"account","name":"nope.json"}`,
		`{"kind":"","name":"x"}`,
		`{"kind":"exit","name":"x"}`,
	} {
		status, out := f.do(t, http.MethodPost, "/egress/pool/"+itoa(id)+"/bind", body)
		if status != http.StatusBadRequest {
			t.Fatalf("bind %s = %d %v, want 400", body, status, out)
		}
	}
	status, _ := f.do(t, http.MethodPost, "/egress/pool/99/bind", `{"kind":"channel","name":"x"}`)
	if status != http.StatusNotFound {
		t.Fatalf("bind to a missing exit = %d, want 404", status)
	}
}

// itoa avoids pulling strconv into every call site in this file.
func itoa(value int) string {
	return strconv.Itoa(value)
}
