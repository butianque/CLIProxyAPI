package pluginhost

import (
	"sort"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type capabilityRecord struct {
	id       string
	path     string
	version  string
	priority int
	meta     pluginapi.Metadata
	plugin   pluginapi.Plugin
}

type Snapshot struct {
	enabled                   bool
	records                   []capabilityRecord
	quotaSupportedProvidersMu sync.RWMutex
	quotaSupportedProviders   map[string][]string
}

// RegisteredPluginInfo describes a plugin that is active in the current runtime snapshot.
type RegisteredPluginInfo struct {
	ID            string
	Priority      int
	Metadata      pluginapi.Metadata
	SupportsOAuth bool
	OAuthProvider string
	// OAuthProviders lists the login entries this plugin contributes. It is the
	// set management clients should render, which is the declared provider-key
	// set when the plugin declares one and the AuthProvider identifier
	// otherwise. It never carries the identifier as an extra alias.
	OAuthProviders []string
	// OAuthProviderLabels maps each entry in OAuthProviders to the plugin-owned
	// user-facing label. It is empty when the plugin declares no labels.
	OAuthProviderLabels map[string]string
	SupportsQuota       bool
	QuotaProvider       string
	// SupportsFingerprintBrowser reports that this plugin's login reads the
	// fingerprint_browser flag, so the panel may offer the choice. It says
	// nothing about whether a fingerprint browser is configured: that stays a
	// runtime decision the plugin makes.
	SupportsFingerprintBrowser bool
	Menus                      []RegisteredPluginMenu
}

// RegisteredPluginMenu describes a plugin-owned resource menu entry.
type RegisteredPluginMenu struct {
	Path        string
	Menu        string
	Description string
}

func emptySnapshot() *Snapshot {
	return &Snapshot{
		quotaSupportedProviders: make(map[string][]string),
	}
}

func (h *Host) activeRecords() []capabilityRecord {
	return h.activeRecordsFromSnapshot(h.Snapshot())
}

func (h *Host) activeRecordsFromSnapshot(snap *Snapshot) []capabilityRecord {
	if snap == nil || len(snap.records) == 0 {
		return nil
	}
	out := make([]capabilityRecord, 0, len(snap.records))
	for _, record := range snap.records {
		if h.recordCurrent(record) {
			out = append(out, record)
		}
	}
	return out
}

// RegisteredPlugins returns a stable copy of plugin metadata in the current runtime snapshot.
func (h *Host) RegisteredPlugins() []RegisteredPluginInfo {
	records := h.activeRecords()
	if len(records) == 0 {
		return nil
	}
	menusByPlugin := h.registeredPluginMenus()
	out := make([]RegisteredPluginInfo, 0, len(records))
	for _, record := range records {
		authProvider := record.plugin.Capabilities.AuthProvider
		oauthProvider := ""
		oauthProviders := []string(nil)
		if authProvider != nil && !h.isPluginFused(record.id) {
			if identifier, okIdentifier := h.callAuthProviderIdentifier(record.id, authProvider); okIdentifier {
				oauthProvider = identifier
			}
			// The panel-facing entry set is the declared provider-key set when
			// one exists, so the AuthProvider identifier alias stays out of it.
			if declared := declaredProviderKeys(record); len(declared) > 0 {
				oauthProviders = declared
			} else if oauthProvider != "" {
				oauthProviders = []string{oauthProvider}
			}
		}
		quotaProvider := record.plugin.Capabilities.QuotaProvider
		quotaIdentifier := ""
		if quotaProvider != nil && !h.isPluginFused(record.id) {
			if identifier, okIdentifier := h.callQuotaIdentifier(record.id, quotaProvider); okIdentifier {
				quotaIdentifier = identifier
			}
		}
		out = append(out, RegisteredPluginInfo{
			ID:                  record.id,
			Priority:            record.priority,
			Metadata:            clonePluginMetadata(record.meta),
			SupportsOAuth:       authProvider != nil,
			OAuthProvider:       oauthProvider,
			OAuthProviders:      oauthProviders,
			OAuthProviderLabels: cloneStringMap(record.plugin.Capabilities.ProviderLabels),
			SupportsQuota:       quotaProvider != nil,
			QuotaProvider:       quotaIdentifier,
			// The choice only makes sense for a plugin that reads the flag. The
			// panel must not offer a toggle for a login that ignores it.
			SupportsFingerprintBrowser: authProvider != nil && record.plugin.Capabilities.FingerprintBrowser,
			Menus:                      menusByPlugin[record.id],
		})
	}
	return out
}

// PluginRegistered reports whether a plugin is active in the current runtime snapshot.
func (h *Host) PluginRegistered(id string) bool {
	if h == nil {
		return false
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	for _, record := range h.activeRecords() {
		if record.id == id {
			return true
		}
	}
	return false
}

func (h *Host) registeredPluginMenus() map[string][]RegisteredPluginMenu {
	out := make(map[string][]RegisteredPluginMenu)
	if h == nil {
		return out
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, record := range h.resourceRoutes {
		menu := strings.TrimSpace(record.route.Menu)
		if menu == "" {
			continue
		}
		out[record.pluginID] = append(out[record.pluginID], RegisteredPluginMenu{
			Path:        strings.TrimSpace(record.route.Path),
			Menu:        menu,
			Description: strings.TrimSpace(record.route.Description),
		})
	}
	for pluginID := range out {
		sort.SliceStable(out[pluginID], func(i, j int) bool {
			return out[pluginID][i].Path < out[pluginID][j].Path
		})
	}
	return out
}

func sortRecords(records []capabilityRecord) {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].priority == records[j].priority {
			return records[i].id < records[j].id
		}
		return records[i].priority > records[j].priority
	})
}

func clonePluginMetadata(meta pluginapi.Metadata) pluginapi.Metadata {
	if len(meta.ConfigFields) == 0 {
		return meta
	}
	meta.ConfigFields = cloneConfigFields(meta.ConfigFields)
	return meta
}

func cloneConfigFields(fields []pluginapi.ConfigField) []pluginapi.ConfigField {
	if len(fields) == 0 {
		return nil
	}
	out := make([]pluginapi.ConfigField, len(fields))
	copy(out, fields)
	for index := range out {
		out[index].EnumValues = append([]string(nil), fields[index].EnumValues...)
	}
	return out
}
