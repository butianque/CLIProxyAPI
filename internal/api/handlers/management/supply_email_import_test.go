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
// directory, so every assertion reads what the route actually persisted.
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
	h := &Handler{configFilePath: cfgPath}
	gin.SetMode(gin.TestMode)
	r := gin.New()
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

func TestImportMailboxesStoresTokensAndChannels(t *testing.T) {
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

	channels, errLoad := supply.LoadChannels(supply.ChannelPath(stateDir))
	if errLoad != nil {
		t.Fatalf("load channels: %v", errLoad)
	}
	emailChannels := channels.List(supply.KindEmail)
	if len(emailChannels) != 2 {
		t.Fatalf("email channels = %d, want 2", len(emailChannels))
	}
	for _, channel := range emailChannels {
		if channel.Category != "third-party" {
			t.Fatalf("%s category = %q", channel.Label, channel.Category)
		}
		connection, ok := channel.Email.Connections[supply.NatureOAuth2]
		if !ok {
			t.Fatalf("%s has no oauth2 connection", channel.Label)
		}
		if connection.Endpoint != defaultImportedMailboxHost {
			t.Fatalf("%s endpoint = %q", channel.Label, connection.Endpoint)
		}
		if connection.ClientID == "" {
			t.Fatalf("%s lost the application id", channel.Label)
		}
		if connection.Usage != "personal" {
			t.Fatalf("%s usage = %q, want personal", channel.Label, connection.Usage)
		}
	}

	store := secretstore.Default()
	value, errGet := store.Get(supply.EmailOAuth2CredentialName("alice@outlook.com"))
	if errGet != nil {
		t.Fatalf("read stored token: %v", errGet)
	}
	// The re-import of the same mailbox rotates the token instead of adding a
	// second channel for it.
	if value != "tok-alpha-2" {
		t.Fatalf("stored token = %q, want the rotated one", value)
	}
}

// The answer is what the panel renders, so it must not carry a credential value.
func TestImportMailboxesNeverEchoesTheToken(t *testing.T) {
	_, r, _ := setupImportTest(t)
	unlockedEmptyStore(t)

	code, resp := importMailboxes(t, r,
		`{"text":"alice@outlook.com----pw----11111111-1111-1111-1111-111111111111----tok-secret-value","probe":false}`)
	if code != http.StatusOK {
		t.Fatalf("import: %d %v", code, resp)
	}
	encoded, _ := json.Marshal(resp)
	if strings.Contains(string(encoded), "tok-secret-value") {
		t.Fatalf("the answer carries the refresh token: %s", encoded)
	}
}

// A locked store cannot take a credential, and the route must say so before it
// writes any channel.
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
	channels, errLoad := supply.LoadChannels(supply.ChannelPath(stateDir))
	if errLoad != nil {
		t.Fatalf("load channels: %v", errLoad)
	}
	if len(channels.All()) != 0 {
		t.Fatalf("a refused import still wrote %d channels", len(channels.All()))
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
}

// quote renders text as a JSON string literal without pulling encoding/json into
// the test's readable parts.
func quote(text string) string {
	encoded, _ := json.Marshal(text)
	return string(encoded)
}
