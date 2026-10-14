package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
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
	return h, r
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
