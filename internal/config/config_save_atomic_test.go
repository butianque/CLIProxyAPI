package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// TestSaveConfigKeepsBackupAndLeavesNoTempFiles pins the two invariants the
// atomic write establishes. os.WriteFile truncated the target in place, so a
// crash between the truncate and the write left a half-written config.yaml and
// there was nothing to restore from.
func TestSaveConfigKeepsBackupAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("# operator comment\nhost: \"127.0.0.1\"\nport: 8317\n")
	if errWrite := os.WriteFile(path, original, 0o600); errWrite != nil {
		t.Fatalf("seed config: %v", errWrite)
	}

	cfg, errLoad := LoadConfig(path)
	if errLoad != nil {
		t.Fatalf("LoadConfig: %v", errLoad)
	}
	cfg.Port = 9000
	if errSave := SaveConfigPreserveComments(path, cfg); errSave != nil {
		t.Fatalf("SaveConfigPreserveComments: %v", errSave)
	}

	saved, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read saved config: %v", errRead)
	}
	if !strings.Contains(string(saved), "9000") {
		t.Fatalf("saved config does not carry the new port:\n%s", saved)
	}
	if !strings.Contains(string(saved), "# operator comment") {
		t.Fatalf("saved config lost the comment:\n%s", saved)
	}

	backup, errBackup := os.ReadFile(path + ".bak")
	if errBackup != nil {
		t.Fatalf("backup file missing: %v", errBackup)
	}
	if string(backup) != string(original) {
		t.Fatalf("backup = %q, want the previous document %q", backup, original)
	}

	entries, errDir := os.ReadDir(dir)
	if errDir != nil {
		t.Fatalf("read dir: %v", errDir)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".config-") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary file %q was left behind", entry.Name())
		}
	}

	// The rewritten document must still be a loadable config.
	if _, errReload := LoadConfig(path); errReload != nil {
		t.Fatalf("reload saved config: %v", errReload)
	}
}

// TestHashManagementKeyWarnsWhenRewriteFails covers the startup migration of a
// plaintext management key. The in-memory value is hashed either way, so a
// failure to write the hash back used to leave the plaintext key on disk with no
// trace in the log. Startup must still succeed: refusing to boot over an
// unwritable config would lock the operator out of the panel that could fix it.
func TestHashManagementKeyWarnsWhenRewriteFails(t *testing.T) {
	logger := log.StandardLogger()
	previousHooks := logger.ReplaceHooks(make(log.LevelHooks))
	previousLevel := logger.GetLevel()
	hook := logtest.NewLocal(logger)
	logger.SetLevel(log.WarnLevel)
	t.Cleanup(func() {
		logger.ReplaceHooks(previousHooks)
		logger.SetLevel(previousLevel)
	})

	// A config file inside a directory that does not exist: the read the rewrite
	// starts with fails, which is the same failure an unwritable file produces.
	missing := filepath.Join(t.TempDir(), "gone", "config.yaml")
	field := "plaintext-management-key"
	document := []byte("management:\n  secret-key: plaintext-management-key\n")

	if errHash := hashManagementKey(missing, document, &field, "secret-key"); errHash != nil {
		t.Fatalf("hashManagementKey returned %v; startup must continue", errHash)
	}
	if !looksLikeBcrypt(field) {
		t.Fatalf("in-memory key = %q, want a bcrypt hash", field)
	}

	warned := false
	for _, entry := range hook.AllEntries() {
		if entry.Level == log.WarnLevel && strings.Contains(entry.Message, "secret-key") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("a failed rewrite of the plaintext key must be logged at warn level")
	}
}
