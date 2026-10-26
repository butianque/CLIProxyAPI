package pluginhost

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// A registered plugin reports two versions that are easy to confuse: the one in
// its filename and the one it declares. They must not share a field name.
func TestPluginLogFieldsSeparatesFileAndPluginVersions(t *testing.T) {
	fields := pluginLogFieldsFromMetadata("sample", pluginapi.Metadata{
		Name:    "Sample Provider",
		Version: "0.2.0",
	}, "0.1.0", "/tmp/plugins/sample-v0.1.0.dll")

	if fields["plugin_id"] != "sample" {
		t.Fatalf("plugin_id = %v, want sample", fields["plugin_id"])
	}
	if fields["plugin_name"] != "Sample Provider" {
		t.Fatalf("plugin_name = %v, want Sample Provider", fields["plugin_name"])
	}
	if fields["file_version"] != "0.1.0" {
		t.Fatalf("file_version = %v, want 0.1.0", fields["file_version"])
	}
	if fields["plugin_version"] != "0.2.0" {
		t.Fatalf("plugin_version = %v, want 0.2.0", fields["plugin_version"])
	}
	if _, ok := fields["version"]; ok {
		t.Fatalf("version = %v, want no ambiguous key", fields["version"])
	}
	if fields["path"] != "/tmp/plugins/sample-v0.1.0.dll" {
		t.Fatalf("path = %v, want /tmp/plugins/sample-v0.1.0.dll", fields["path"])
	}
}

func TestPluginLogFieldsOmitsEmptyName(t *testing.T) {
	fields := pluginLogFields("sample", "", "0.2.0", "")
	if _, ok := fields["plugin_name"]; ok {
		t.Fatalf("plugin_name = %v, want omitted", fields["plugin_name"])
	}
}

func TestPluginHotReloadLogFieldsIncludesActiveAndRetiredIdentity(t *testing.T) {
	fields := pluginHotReloadLogFields(
		"sample",
		"0.1.0",
		"/tmp/plugins/sample-v0.1.0.dll",
		"0.2.0",
		"/tmp/plugins/sample-v0.2.0.dll",
	)

	for key, want := range map[string]string{
		"plugin_id":       "sample",
		"active_version":  "0.1.0",
		"active_path":     "/tmp/plugins/sample-v0.1.0.dll",
		"retired_version": "0.2.0",
		"retired_path":    "/tmp/plugins/sample-v0.2.0.dll",
	} {
		if fields[key] != want {
			t.Fatalf("%s = %v, want %s", key, fields[key], want)
		}
	}
}
