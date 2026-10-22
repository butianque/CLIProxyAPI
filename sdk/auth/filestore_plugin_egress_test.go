package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// pluginEchoStorage behaves like a plugin's token storage: it keeps the
// provider's own payload and lays the host's metadata over it when saving.
type pluginEchoStorage struct {
	raw  []byte
	meta map[string]any
}

func (s *pluginEchoStorage) SetMetadata(meta map[string]any) { s.meta = meta }

func (s *pluginEchoStorage) SaveTokenToFile(path string) error {
	out := make(map[string]any)
	if len(s.raw) > 0 {
		if errUnmarshal := json.Unmarshal(s.raw, &out); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	for key, value := range s.meta {
		out[key] = value
	}
	raw, errMarshal := json.Marshal(out)
	if errMarshal != nil {
		return errMarshal
	}
	return os.WriteFile(path, raw, 0o600)
}

// pluginNarrowParser mirrors a plugin that republishes only the fields it
// models: the session it owns and the account facts it derived.
type pluginNarrowParser struct{}

func (pluginNarrowParser) ParseAuth(_ context.Context, req pluginapi.AuthParseRequest) (*cliproxyauth.Auth, bool, error) {
	var storage struct {
		Session  string `json:"session"`
		OpenedAt string `json:"opened_at"`
	}
	if errUnmarshal := json.Unmarshal(req.RawJSON, &storage); errUnmarshal != nil || storage.Session == "" {
		return nil, false, nil
	}
	raw, errMarshal := json.Marshal(storage)
	if errMarshal != nil {
		return nil, true, errMarshal
	}
	metadata := map[string]any{"type": "loomy"}
	if storage.OpenedAt != "" {
		metadata["opened_at"] = storage.OpenedAt
	}
	return &cliproxyauth.Auth{
		Provider: "loomy",
		ID:       req.FileName,
		FileName: req.FileName,
		Storage:  &pluginEchoStorage{raw: raw, meta: metadata},
		Metadata: metadata,
	}, true, nil
}

func registerNarrowPluginParser(t *testing.T) {
	t.Helper()
	RegisterPluginAuthParser(pluginNarrowParser{})
	t.Cleanup(func() { RegisterPluginAuthParser(nil) })
}

func registerEgressTwo(t *testing.T) {
	t.Helper()
	SetEgressResolver(func(id int) (string, error) {
		if id != 2 {
			t.Fatalf("resolver asked for #%d, want #2", id)
		}
		return "socks5://user:pass@10.0.0.2:1080", nil
	})
	t.Cleanup(func() { SetEgressResolver(nil) })
}

// TestFileTokenStoreList_PluginAuthKeepsEgressBinding pins that a plugin-owned
// credential keeps the exit it names when it is loaded from disk.
//
// The plugin republishes only the fields it models, so the reference is only in
// the file. A loader that keeps the plugin's narrow metadata loses it: the
// panel then reports the credential as unbound, and the next save — which writes
// the metadata back over the file — deletes the reference for good.
func TestFileTokenStoreList_PluginAuthKeepsEgressBinding(t *testing.T) {
	registerEgressTwo(t)
	registerNarrowPluginParser(t)

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)

	content := []byte(`{
		"type": "loomy",
		"session": "session-token",
		"opened_at": "2026-01-02T03:04:05Z",
		"egress_id": 2
	}`)
	if errWrite := os.WriteFile(filepath.Join(dir, "loomy-1.json"), content, 0o600); errWrite != nil {
		t.Fatalf("write auth file: %v", errWrite)
	}

	auths, errList := store.List(context.Background())
	if errList != nil {
		t.Fatalf("List error: %v", errList)
	}
	if len(auths) != 1 {
		t.Fatalf("got %d auths, want 1", len(auths))
	}
	auth := auths[0]
	if got := auth.ProxyURL; got != "socks5://user:pass@10.0.0.2:1080" {
		t.Fatalf("ProxyURL = %q, want the pool's address for #2", got)
	}
	if id, ok := EgressIDFromMetadata(auth.Metadata); !ok || id != 2 {
		t.Fatalf("loaded egress id = %d/%t, want 2/true: the panel reads this field", id, ok)
	}

	if _, errSave := store.Save(context.Background(), auth); errSave != nil {
		t.Fatalf("Save error: %v", errSave)
	}
	saved, errRead := os.ReadFile(filepath.Join(dir, "loomy-1.json"))
	if errRead != nil {
		t.Fatalf("read saved auth file: %v", errRead)
	}
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(saved, &payload); errUnmarshal != nil {
		t.Fatalf("decode saved auth file: %v", errUnmarshal)
	}
	if id, ok := EgressIDFromMetadata(payload); !ok || id != 2 {
		t.Fatalf("saved egress id = %d/%t, want 2/true: a save must not unbind the credential", id, ok)
	}
}
