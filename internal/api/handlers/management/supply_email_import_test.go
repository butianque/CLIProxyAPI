package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// setupImportTest wires the batch import route against a temporary supply
// directory and an empty pool, so every assertion reads what the route actually
// persisted.
func setupImportTest(t *testing.T) (*Handler, *gin.Engine, string) {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "supply")
	cfgPath := filepath.Join(dir, "config.yaml")
	if errWrite := os.WriteFile(cfgPath, []byte("supply:\n  storage-dir: "+stateDir+"\n"), 0o600); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
	if errMkdir := os.MkdirAll(stateDir, 0o755); errMkdir != nil {
		t.Fatalf("create supply dir: %v", errMkdir)
	}
	previous := supply.Default()
	t.Cleanup(func() { supply.SetDefault(previous) })
	registry := supply.NewRegistry()
	registry.SetPool(supply.NewPool())
	supply.SetDefault(registry)

	h := &Handler{configFilePath: cfgPath}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	attachTestSession(t, h, r)
	r.POST("/supply/email/import", h.PostSupplyEmailImport)
	return h, r, stateDir
}

// importMailboxes posts a paste and returns the decoded answer.
func importMailboxes(t *testing.T, r *gin.Engine, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/supply/email/import", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	var decoded map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &decoded)
	return rr.Code, decoded
}

// loadPool reads the pool document the route wrote.
func loadPool(t *testing.T, stateDir string) *supply.Pool {
	t.Helper()
	pool, errLoad := supply.LoadPool(supply.PoolPath(stateDir))
	if errLoad != nil {
		t.Fatalf("load pool: %v", errLoad)
	}
	return pool
}

// An imported mailbox is a pool identity, not a channel: a bought address owns
// exactly one mailbox and its own credential, while a channel is one connection
// that covers many addresses. Filing a batch as channels is what turned the
// channel table into an address book.
func TestImportMailboxesStoresIdentitiesInThePool(t *testing.T) {
	_, r, stateDir := setupImportTest(t)
	unlockedEmptyStore(t)

	paste := strings.Join([]string{
		"# seller header",
		"alice@outlook.com----pw1----11111111-1111-1111-1111-111111111111----tok-alpha",
		"bob@hotmail.com----pw2----22222222-2222-2222-2222-222222222222----tok-beta",
		"this line has no separator",
		"alice@outlook.com----pw1----11111111-1111-1111-1111-111111111111----tok-alpha-2",
	}, "\n")
	code, resp := importMailboxes(t, r, `{"text":`+quote(paste)+`,"probe":false}`)
	if code != http.StatusOK {
		t.Fatalf("import: %d %v", code, resp)
	}
	if resp["imported"] != float64(2) || resp["updated"] != float64(1) || resp["failed"] != float64(1) {
		t.Fatalf("counts = imported %v updated %v failed %v", resp["imported"], resp["updated"], resp["failed"])
	}

	// Nothing reaches the channel table: these are identities, not connections.
	channels, errLoad := supply.LoadChannels(supply.ChannelPath(stateDir))
	if errLoad != nil {
		t.Fatalf("load channels: %v", errLoad)
	}
	if len(channels.All()) != 0 {
		t.Fatalf("the import wrote %d channels, want none", len(channels.All()))
	}

	pool := loadPool(t, stateDir)
	records := pool.Mailboxes()
	if len(records) != 2 {
		t.Fatalf("pool mailboxes = %d, want 2", len(records))
	}
	for _, record := range records {
		box := record.Mailbox
		if box == nil {
			t.Fatalf("%s has no mailbox block", record.Address)
		}
		if box.Nature != supply.NatureOAuth2 {
			t.Fatalf("%s nature = %q, want oauth2", record.Address, box.Nature)
		}
		if box.Endpoint != defaultImportedMailboxHost {
			t.Fatalf("%s endpoint = %q", record.Address, box.Endpoint)
		}
		if box.ClientID == "" {
			t.Fatalf("%s lost the application id", record.Address)
		}
		if box.Secret != supply.EmailOAuth2CredentialName(record.Address) {
			t.Fatalf("%s credential entry = %q", record.Address, box.Secret)
		}
		if box.Password != supply.EmailPasswordCredentialName(record.Address) {
			t.Fatalf("%s password entry = %q", record.Address, box.Password)
		}
	}

	store := secretstore.Default()
	value, errGet := store.Get(supply.EmailOAuth2CredentialName("alice@outlook.com"))
	if errGet != nil {
		t.Fatalf("read stored token: %v", errGet)
	}
	// The re-import of the same mailbox rotates the token instead of adding a
	// second identity for it.
	if value != "tok-alpha-2" {
		t.Fatalf("stored token = %q, want the rotated one", value)
	}
	// The password is kept too: it is what a person signing in to the mailbox's
	// own web page needs, and Microsoft refuses it on every transport.
	if password, errPassword := store.Get(supply.EmailPasswordCredentialName("alice@outlook.com")); errPassword != nil || password != "pw1" {
		t.Fatalf("stored password = %q (err %v)", password, errPassword)
	}
}

// The answer is what the panel renders, so it must not carry a credential value.
func TestImportMailboxesNeverEchoesTheSecrets(t *testing.T) {
	_, r, _ := setupImportTest(t)
	unlockedEmptyStore(t)

	code, resp := importMailboxes(t, r,
		`{"text":"alice@outlook.com----pw-secret-value----11111111-1111-1111-1111-111111111111----tok-secret-value","probe":false}`)
	if code != http.StatusOK {
		t.Fatalf("import: %d %v", code, resp)
	}
	encoded, _ := json.Marshal(resp)
	if strings.Contains(string(encoded), "tok-secret-value") {
		t.Fatalf("the answer carries the refresh token: %s", encoded)
	}
	if strings.Contains(string(encoded), "pw-secret-value") {
		t.Fatalf("the answer carries the password: %s", encoded)
	}
}

// A locked store cannot take a credential, and the route must say so before it
// writes any identity.
func TestImportMailboxesRefusesALockedStore(t *testing.T) {
	_, r, stateDir := setupImportTest(t)

	store, errOpen := secretstore.Open(filepath.Join(t.TempDir(), "secrets.enc"))
	if errOpen != nil {
		t.Fatalf("open store: %v", errOpen)
	}
	if errInitialize := store.Initialize("master"); errInitialize != nil {
		t.Fatalf("initialize store: %v", errInitialize)
	}
	store.Lock()
	secretstore.Configure(store)
	t.Cleanup(func() { secretstore.Configure(nil) })

	body := `{"text":"alice@outlook.com----pw----11111111-1111-1111-1111-111111111111----tok","probe":false}`
	code, _ := importMailboxes(t, r, body)
	if code != http.StatusConflict {
		t.Fatalf("locked store: %d, want %d", code, http.StatusConflict)
	}
	if records := loadPool(t, stateDir).All(); len(records) != 0 {
		t.Fatalf("a refused import still wrote %d identities", len(records))
	}

	// Unlocking is the gate's job; once it is open the batch is still checked
	// against the passphrase the operator typed, so a stale value in the panel
	// cannot write a credential.
	if errUnlock := store.Unlock("master"); errUnlock != nil {
		t.Fatalf("unlock store: %v", errUnlock)
	}
	code, _ = importMailboxes(t, r, `{"text":"alice@outlook.com----pw----11111111-1111-1111-1111-111111111111----tok","probe":false,"passphrase":"wrong"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong passphrase: %d, want %d", code, http.StatusUnauthorized)
	}

	code, resp := importMailboxes(t, r, `{"text":"alice@outlook.com----pw----11111111-1111-1111-1111-111111111111----tok","probe":false,"passphrase":"master"}`)
	if code != http.StatusOK {
		t.Fatalf("unlocked with the right passphrase: %d %v", code, resp)
	}
}

// A batch pasted for Graph must be stored as a Graph identity: no endpoint (Graph
// has one fixed one), the application id kept, and the credential under the token
// entry — a Graph identity that stored its token under the password entry would be
// handed to an IMAP LOGIN that can never accept it.
func TestImportMailboxesStoresTheChosenReceivingMethod(t *testing.T) {
	_, r, stateDir := setupImportTest(t)
	unlockedEmptyStore(t)

	body := `{"text":"alice@outlook.com----pw----11111111-1111-1111-1111-111111111111----tok-graph","probe":false,"nature":"graph"}`
	code, resp := importMailboxes(t, r, body)
	if code != http.StatusOK {
		t.Fatalf("import: %d %v", code, resp)
	}
	if resp["nature"] != "graph" {
		t.Fatalf("answer nature = %v, want graph", resp["nature"])
	}

	records := loadPool(t, stateDir).Mailboxes()
	if len(records) != 1 {
		t.Fatalf("pool mailboxes = %d, want 1", len(records))
	}
	box := records[0].Mailbox
	if box == nil || box.Nature != supply.NatureGraph {
		t.Fatalf("mailbox = %+v, want a graph transport", box)
	}
	if box.Endpoint != "" {
		t.Fatalf("graph endpoint = %q, want none", box.Endpoint)
	}
	if box.ClientID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("graph application id = %q", box.ClientID)
	}
	if want := supply.EmailOAuth2CredentialName("alice@outlook.com"); box.Secret != want {
		t.Fatalf("graph credential entry = %q, want %q", box.Secret, want)
	}
}

// The receiving method is a decision the operator makes, so an unknown value is
// refused instead of silently falling back to IMAP.
func TestImportMailboxesRejectsAnUnknownReceivingMethod(t *testing.T) {
	_, r, stateDir := setupImportTest(t)
	unlockedEmptyStore(t)

	body := `{"text":"alice@outlook.com----pw----11111111-1111-1111-1111-111111111111----tok","probe":false,"nature":"carrier-pigeon"}`
	code, _ := importMailboxes(t, r, body)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown receiving method: %d, want %d", code, http.StatusBadRequest)
	}
	if records := loadPool(t, stateDir).All(); len(records) != 0 {
		t.Fatalf("a refused import wrote %d identities", len(records))
	}
}

// Re-importing the same mailbox with a different receiving method replaces the
// method instead of leaving two of them: one mailbox is read one way, and a stale
// second transport is a record nobody can reason about.
func TestImportMailboxesSwitchesTheReceivingMethodInPlace(t *testing.T) {
	_, r, stateDir := setupImportTest(t)
	unlockedEmptyStore(t)

	line := "alice@outlook.com----pw----11111111-1111-1111-1111-111111111111----tok"
	if code, resp := importMailboxes(t, r, `{"text":"`+line+`","probe":false,"nature":"graph"}`); code != http.StatusOK {
		t.Fatalf("graph import: %d %v", code, resp)
	}
	if code, resp := importMailboxes(t, r, `{"text":"`+line+`","probe":false,"nature":"oauth2"}`); code != http.StatusOK {
		t.Fatalf("imap import: %d %v", code, resp)
	}

	records := loadPool(t, stateDir).Mailboxes()
	if len(records) != 1 {
		t.Fatalf("pool mailboxes = %d, want 1", len(records))
	}
	box := records[0].Mailbox
	if box.Nature != supply.NatureOAuth2 {
		t.Fatalf("nature = %q, want oauth2", box.Nature)
	}
	if box.Endpoint != defaultImportedMailboxHost {
		t.Fatalf("endpoint = %q, want the IMAP host", box.Endpoint)
	}
}

func TestImportMailboxesRejectsAnEmptyPaste(t *testing.T) {
	_, r, _ := setupImportTest(t)
	unlockedEmptyStore(t)
	code, _ := importMailboxes(t, r, `{"text":"  \n# only a header\n","probe":false}`)
	if code != http.StatusBadRequest {
		t.Fatalf("empty paste: %d, want %d", code, http.StatusBadRequest)
	}
}

func TestLooksLikeClientID(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"11111111-1111-1111-1111-111111111111", true},
		{"AB12CD34-EF56-7890-ABCD-EF1234567890", true},
		{"111111111111111111111111111111111111", false},
		{"1111-1111-1111-1111", false},
		{"11111111-1111-1111-1111-11111111111z", false},
		{"", false},
	}
	for _, testCase := range cases {
		if got := looksLikeClientID(testCase.value); got != testCase.want {
			t.Errorf("looksLikeClientID(%q) = %v, want %v", testCase.value, got, testCase.want)
		}
	}
}

func TestParseMailboxLinesNamesTheBrokenPart(t *testing.T) {
	lines := parseMailboxLines(strings.Join([]string{
		"not-an-address----pw----11111111-1111-1111-1111-111111111111----tok",
		"a@b.com----pw----not-a-guid----tok",
		"a@b.com----pw----11111111-1111-1111-1111-111111111111----",
		"a@b.com----pw----11111111-1111-1111-1111-111111111111----tok",
	}, "\n"))
	if len(lines) != 4 {
		t.Fatalf("parsed %d lines, want 4", len(lines))
	}
	for index := 0; index < 3; index++ {
		if lines[index].Err == nil {
			t.Fatalf("line %d parsed without an error", index+1)
		}
	}
	if lines[3].Err != nil {
		t.Fatalf("valid line reported %v", lines[3].Err)
	}
	if lines[3].Account != "a@b.com" || lines[3].Refresh != "tok" {
		t.Fatalf("valid line parsed as %+v", lines[3])
	}
	// The password is parsed even though no transport spends it: it is what a
	// person signing in to the mailbox's own web page needs.
	if lines[3].Password != "pw" {
		t.Fatalf("password field = %q, want pw", lines[3].Password)
	}
}

// quote renders text as a JSON string literal without pulling encoding/json into
// the test's readable parts.
func quote(text string) string {
	encoded, _ := json.Marshal(text)
	return string(encoded)
}
