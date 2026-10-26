package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Only dynamic libraries inside a watched plugin directory are plugin events.
// Anything else in that directory, and any library outside it, is noise the host
// must not be woken up for.
func TestIsPluginLibraryEvent(t *testing.T) {
	root := t.TempDir()
	pluginsDir := filepath.Join(root, "plugins")
	archDir := filepath.Join(pluginsDir, "linux", "amd64")
	w := &Watcher{}
	w.WatchPlugins([]string{archDir, pluginsDir}, nil)

	cases := []struct {
		name string
		path string
		op   fsnotify.Op
		want bool
	}{
		{name: "written library", path: filepath.Join(pluginsDir, "alpha-v1.0.0.so"), op: fsnotify.Write, want: true},
		{name: "created library", path: filepath.Join(pluginsDir, "alpha-v1.0.0.so"), op: fsnotify.Create, want: true},
		{name: "renamed library", path: filepath.Join(pluginsDir, "alpha-v1.0.0.dylib"), op: fsnotify.Rename, want: true},
		{name: "removed library", path: filepath.Join(pluginsDir, "alpha-v1.0.0.dll"), op: fsnotify.Remove, want: true},
		{name: "library in the platform subdirectory", path: filepath.Join(archDir, "alpha-v1.0.0.so"), op: fsnotify.Write, want: true},
		{name: "chmod is not a content change", path: filepath.Join(pluginsDir, "alpha-v1.0.0.so"), op: fsnotify.Chmod, want: false},
		{name: "non library file", path: filepath.Join(pluginsDir, "notes.txt"), op: fsnotify.Write, want: false},
		{name: "library outside the plugin directory", path: filepath.Join(root, "alpha-v1.0.0.so"), op: fsnotify.Write, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := w.isPluginLibraryEvent(w.normalizeAuthPath(tc.path), tc.op); got != tc.want {
				t.Fatalf("isPluginLibraryEvent(%s, %s) = %v, want %v", tc.path, tc.op, got, tc.want)
			}
		})
	}
}

func TestIsPluginLibraryEventWithoutPluginWatch(t *testing.T) {
	w := &Watcher{}
	if w.isPluginLibraryEvent(w.normalizeAuthPath(filepath.Join(t.TempDir(), "alpha.so")), fsnotify.Write) {
		t.Fatal("expected no plugin event when no plugin directory is watched")
	}
}

// A library dropped into a plugin directory has to reach the callback, or the
// host keeps serving the old library until the next restart. The library goes
// into the platform subdirectory because that is the layout the host scans first
// and the one a nested watch would miss.
func TestWatchPluginsReportsLibraryChanges(t *testing.T) {
	tmpDir := t.TempDir()
	authDir := filepath.Join(tmpDir, "auth")
	if errMkdirAll := os.MkdirAll(authDir, 0o755); errMkdirAll != nil {
		t.Fatalf("MkdirAll(%s) error = %v", authDir, errMkdirAll)
	}
	pluginsDir := filepath.Join(tmpDir, "plugins")
	archDir := filepath.Join(pluginsDir, runtime.GOOS, runtime.GOARCH)
	if errMkdirAll := os.MkdirAll(archDir, 0o755); errMkdirAll != nil {
		t.Fatalf("MkdirAll(%s) error = %v", archDir, errMkdirAll)
	}
	configPath := filepath.Join(tmpDir, "config.yaml")
	if errWriteFile := os.WriteFile(configPath, []byte("auth_dir: "+authDir+"\n"), 0o644); errWriteFile != nil {
		t.Fatalf("WriteFile(%s) error = %v", configPath, errWriteFile)
	}

	w, errNewWatcher := NewWatcher(configPath, authDir, nil)
	if errNewWatcher != nil {
		t.Fatalf("NewWatcher() error = %v", errNewWatcher)
	}
	t.Cleanup(func() {
		if errStop := w.Stop(); errStop != nil {
			t.Logf("Stop() error = %v", errStop)
		}
	})
	w.SetConfig(&config.Config{AuthDir: authDir})

	changes := make(chan struct{}, 4)
	w.WatchPlugins([]string{archDir, pluginsDir}, func() { changes <- struct{}{} })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if errStart := w.Start(ctx); errStart != nil {
		t.Fatalf("Start() error = %v", errStart)
	}

	libraryPath := filepath.Join(archDir, "alpha-v1.0.0"+pluginExtensionForTest())
	if errWriteFile := os.WriteFile(libraryPath, []byte("library"), 0o644); errWriteFile != nil {
		t.Fatalf("WriteFile(%s) error = %v", libraryPath, errWriteFile)
	}

	select {
	case <-changes:
	case <-time.After(15 * time.Second):
		t.Fatal("plugin library change was never reported")
	}
}

func pluginExtensionForTest() string {
	switch runtime.GOOS {
	case "darwin":
		return ".dylib"
	case "windows":
		return ".dll"
	default:
		return ".so"
	}
}
