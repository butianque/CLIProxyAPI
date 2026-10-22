package registry

import "testing"

// A provider-level plugin registration outlives every credential that could
// serve it. Advertising such a model makes the proxy promise something it
// cannot deliver: the client picks it, and the request fails with
// auth_not_found on a model the proxy itself listed.
func TestAvailableModelsHideProvidersWithoutCredentials(t *testing.T) {
	r := newTestModelRegistry()
	r.RegisterClient("plugin:zcode:zcode-bigmodel:executor", "zcode-bigmodel", []*ModelInfo{{ID: "glm-5.3", OwnedBy: "zcode"}})
	r.RegisterClient("plugin:zcode:zcode-zai:executor", "zcode-zai", []*ModelInfo{{ID: "glm-5.3", OwnedBy: "zcode"}})
	r.RegisterClient("workbuddy-auth", "workbuddy", []*ModelInfo{{ID: "glm-5.3-flash", OwnedBy: "workbuddy"}})

	// Warm the cache while the filter is disabled. The filter must not be
	// defeated by a snapshot built before credentials changed.
	if got := r.GetAvailableModels("openai"); len(got) != 2 {
		t.Fatalf("unfiltered catalog = %v, want both models", got)
	}

	available := []string{"workbuddy"}
	r.SetProviderAvailability(func() []string { return available })

	got := r.GetAvailableModels("openai")
	if len(got) != 1 || got[0]["id"] != "glm-5.3-flash" {
		t.Fatalf("catalog = %v, want only the model a credential can serve", got)
	}
	if infos := r.GetAvailableModelInfos(); len(infos) != 1 || infos[0].ID != "glm-5.3-flash" {
		t.Fatalf("metadata catalog = %v, want only the servable model", infos)
	}

	// One credential for one of the two providers is enough to serve the model.
	available = []string{"workbuddy", "zcode-bigmodel"}
	if got := r.GetAvailableModels("openai"); len(got) != 2 {
		t.Fatalf("catalog = %v, want the model back once a provider has a credential", got)
	}

	// No credentials at all means nothing can be served.
	available = nil
	if got := r.GetAvailableModels("openai"); len(got) != 0 {
		t.Fatalf("catalog = %v, want an empty list when no provider has a credential", got)
	}

	// Removing the source restores the unfiltered view.
	r.SetProviderAvailability(nil)
	if got := r.GetAvailableModels("openai"); len(got) != 2 {
		t.Fatalf("catalog = %v, want both models after the filter is removed", got)
	}
}
