package pluginhost

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

// pluginLogFields describes a plugin file. The version it carries is the one
// parsed from the filename, which is the version the operator chose to keep on
// disk; it is not necessarily the version the library reports about itself.
func pluginLogFields(id, name, version, path string) log.Fields {
	fields := log.Fields{
		"plugin_id": strings.TrimSpace(id),
	}
	if name = strings.TrimSpace(name); name != "" {
		fields["plugin_name"] = name
	}
	if version = strings.TrimSpace(version); version != "" {
		fields["file_version"] = version
	}
	if path = strings.TrimSpace(path); path != "" {
		fields["path"] = path
	}
	return fields
}

// pluginLogFieldsFromMetadata describes a registered plugin. It reports the
// version the plugin declares alongside the filename version, so a library that
// does not match the name it ships under is visible in one line.
func pluginLogFieldsFromMetadata(id string, meta pluginapi.Metadata, fileVersion, path string) log.Fields {
	fields := pluginLogFields(id, meta.Name, fileVersion, path)
	if version := strings.TrimSpace(meta.Version); version != "" {
		fields["plugin_version"] = version
	}
	return fields
}

func pluginHotReloadLogFields(id, activeVersion, activePath, retiredVersion, retiredPath string) log.Fields {
	fields := log.Fields{
		"plugin_id": strings.TrimSpace(id),
	}
	if activeVersion = strings.TrimSpace(activeVersion); activeVersion != "" {
		fields["active_version"] = activeVersion
	}
	if activePath = strings.TrimSpace(activePath); activePath != "" {
		fields["active_path"] = activePath
	}
	if retiredVersion = strings.TrimSpace(retiredVersion); retiredVersion != "" {
		fields["retired_version"] = retiredVersion
	}
	if retiredPath = strings.TrimSpace(retiredPath); retiredPath != "" {
		fields["retired_path"] = retiredPath
	}
	return fields
}
