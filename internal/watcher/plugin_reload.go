// plugin_reload.go implements the debounced plugin library change notification.
//
// The plugin host keeps loaded libraries in memory and only re-reads the plugin
// directory when it is told to, so a replaced .so has to be announced. The
// debounce exists because a copied library produces a burst of events and must
// not be loaded while it is still being written.
package watcher

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
)

const pluginReloadDebounce = 1 * time.Second

// isPluginLibraryEvent reports whether the event is a dynamic library change in
// one of the watched plugin directories.
func (w *Watcher) isPluginLibraryEvent(normalizedPath string, op fsnotify.Op) bool {
	if op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) == 0 {
		return false
	}
	w.clientsMutex.RLock()
	_, inPluginDir := w.pluginDirSet[filepath.Dir(normalizedPath)]
	w.clientsMutex.RUnlock()
	if !inPluginDir {
		return false
	}
	switch strings.ToLower(filepath.Ext(normalizedPath)) {
	case ".so", ".dylib", ".dll":
		return true
	default:
		return false
	}
}

func (w *Watcher) stopPluginReloadTimer() {
	w.pluginReloadMu.Lock()
	if w.pluginReloadTimer != nil {
		w.pluginReloadTimer.Stop()
		w.pluginReloadTimer = nil
	}
	w.pluginReloadMu.Unlock()
}

func (w *Watcher) schedulePluginReload() {
	w.pluginReloadMu.Lock()
	defer w.pluginReloadMu.Unlock()
	if w.pluginReloadTimer != nil {
		w.pluginReloadTimer.Stop()
	}
	w.pluginReloadTimer = time.AfterFunc(pluginReloadDebounce, func() {
		w.pluginReloadMu.Lock()
		w.pluginReloadTimer = nil
		w.pluginReloadMu.Unlock()
		if w.stopped.Load() {
			return
		}
		w.clientsMutex.RLock()
		onChange := w.pluginChangeCallback
		w.clientsMutex.RUnlock()
		if onChange == nil {
			return
		}
		log.Info("plugin library changed, re-applying plugin runtime")
		onChange()
	})
}
