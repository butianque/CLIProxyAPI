package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type testQuotaProvider struct {
	identifier string
	describeFn func(context.Context, pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error)
	fetchFn    func(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error)
	resetFn    func(context.Context, pluginapi.QuotaResetRequest) (pluginapi.QuotaResetResponse, error)
}

func (p *testQuotaProvider) Identifier() string {
	return p.identifier
}

func (p *testQuotaProvider) DescribeQuota(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
	if p.describeFn != nil {
		return p.describeFn(ctx, req)
	}
	return pluginapi.QuotaDescribeResponse{
		SupportedProviders: []string{p.identifier},
		DisplayName:        "Test Quota Provider",
		SupportsReset:      true,
	}, nil
}

func (p *testQuotaProvider) FetchQuota(ctx context.Context, req pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
	if p.fetchFn != nil {
		return p.fetchFn(ctx, req)
	}
	return pluginapi.QuotaFetchResponse{
		Subscription: &pluginapi.QuotaSubscription{
			Plan:     "Pro",
			TierName: "Pro Tier",
			TierID:   "pro-1",
		},
		ServerTimeOffsetMs: 50,
		Groups: []pluginapi.QuotaGroup{
			{
				DisplayName: "Rolling Limits",
				Buckets: []pluginapi.QuotaBucket{
					{
						Window:            "daily",
						RemainingFraction: 0.75,
						ResetTime:         "2026-09-13T00:00:00Z",
						Description:       "75% remaining",
					},
				},
			},
		},
	}, nil
}

func (p *testQuotaProvider) ResetQuota(ctx context.Context, req pluginapi.QuotaResetRequest) (pluginapi.QuotaResetResponse, error) {
	if p.resetFn != nil {
		return p.resetFn(ctx, req)
	}
	return pluginapi.QuotaResetResponse{
		Success: true,
		Message: "quota reset successful",
	}, nil
}

func TestQuotaProviderCapability_Direct(t *testing.T) {
	provider := &testQuotaProvider{identifier: "opencode-go"}
	host := newHostWithRecords(capabilityRecord{
		id: "opencode-go-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: provider,
			},
		},
	})

	if !host.HasQuotaProvider("opencode-go") {
		t.Fatal("expected host to have quota provider for opencode-go")
	}

	resp, handled, errFetch := host.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{
		Provider:  "opencode-go",
		AuthIndex: "auth-123",
	})
	if errFetch != nil {
		t.Fatalf("unexpected fetch error: %v", errFetch)
	}
	if !handled {
		t.Fatal("expected fetch to be handled")
	}
	if resp.Subscription == nil || resp.Subscription.Plan != "Pro" {
		t.Fatalf("unexpected subscription: %+v", resp.Subscription)
	}
	if len(resp.Groups) != 1 || len(resp.Groups[0].Buckets) != 1 {
		t.Fatalf("unexpected groups: %+v", resp.Groups)
	}
	if resp.Groups[0].Buckets[0].RemainingFraction != 0.75 {
		t.Fatalf("unexpected remaining fraction: %f", resp.Groups[0].Buckets[0].RemainingFraction)
	}
}

func TestQuotaProviderCapability_Reset(t *testing.T) {
	provider := &testQuotaProvider{identifier: "opencode-go"}
	host := newHostWithRecords(capabilityRecord{
		id: "opencode-go-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: provider,
			},
		},
	})

	resp, handled, errReset := host.ResetQuota(context.Background(), pluginapi.QuotaResetRequest{
		Provider:  "opencode-go",
		AuthIndex: "auth-123",
	})
	if errReset != nil {
		t.Fatalf("unexpected reset error: %v", errReset)
	}
	if !handled || !resp.Success {
		t.Fatalf("expected reset handled successfully, got handled=%v, resp=%+v", handled, resp)
	}
}

func TestQuotaProviderCapability_Describe(t *testing.T) {
	provider := &testQuotaProvider{identifier: "opencode-go"}
	host := newHostWithRecords(capabilityRecord{
		id: "opencode-go-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: provider,
			},
		},
	})

	desc, handled, errDesc := host.DescribeQuota(context.Background(), "opencode-go-plugin")
	if errDesc != nil {
		t.Fatalf("unexpected describe error: %v", errDesc)
	}
	if !handled || desc.DisplayName != "Test Quota Provider" {
		t.Fatalf("unexpected describe response: %+v", desc)
	}
}

func TestQuotaProviderCapability_RegisteredPlugins(t *testing.T) {
	provider := &testQuotaProvider{identifier: "opencode-go"}
	host := newHostWithRecords(capabilityRecord{
		id: "opencode-go-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: provider,
			},
		},
	})

	plugins := host.RegisteredPlugins()
	if len(plugins) != 1 {
		t.Fatalf("expected 1 registered plugin, got %d", len(plugins))
	}
	if !plugins[0].SupportsQuota {
		t.Fatal("expected SupportsQuota to be true")
	}
	if plugins[0].QuotaProvider != "opencode-go" {
		t.Fatalf("expected QuotaProvider to be opencode-go, got %q", plugins[0].QuotaProvider)
	}
}

func TestQuotaProviderCapability_PanicFusing(t *testing.T) {
	provider := &testQuotaProvider{
		identifier: "panic-provider",
		fetchFn: func(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
			panic("boom")
		},
	}
	host := newHostWithRecords(capabilityRecord{
		id: "panic-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: provider,
			},
		},
	})

	_, handled, errFetch := host.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{
		Provider: "panic-provider",
	})
	if errFetch == nil {
		t.Fatal("expected error after panic")
	}
	if handled {
		t.Fatal("expected handled to be false after panic")
	}
	if !host.isPluginFused("panic-plugin") {
		t.Fatal("expected plugin to be fused after panic")
	}
}

func TestQuotaProviderCapability_RPC(t *testing.T) {
	provider := &testQuotaProvider{identifier: "rpc-quota-provider"}
	plugin := validTestPlugin("rpc-quota-plugin")
	plugin.Capabilities.QuotaProvider = provider

	lookup := newTestSymbolLookup(&testPlugin{
		registerResult: plugin,
	})

	host := New()
	registered, errRegister := registerRPCPlugin(context.Background(), host, "rpc-quota-plugin", lookup, pluginabi.MethodPluginRegister, nil)
	if errRegister != nil {
		t.Fatalf("registerRPCPlugin() error = %v", errRegister)
	}
	if registered.Capabilities.QuotaProvider == nil {
		t.Fatal("expected registered plugin to have QuotaProvider capability")
	}

	hostWithRPC := newHostWithRecords(capabilityRecord{
		id:     "rpc-quota-plugin",
		plugin: registered,
	})

	if !hostWithRPC.HasQuotaProvider("rpc-quota-provider") {
		t.Fatal("expected host to recognize rpc-quota-provider")
	}

	fetchResp, handled, errFetch := hostWithRPC.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{
		Provider:  "rpc-quota-provider",
		AuthIndex: "auth-rpc-1",
	})
	if errFetch != nil {
		t.Fatalf("unexpected rpc fetch error: %v", errFetch)
	}
	if !handled || fetchResp.Subscription == nil || fetchResp.Subscription.Plan != "Pro" {
		t.Fatalf("unexpected rpc fetch response: %+v", fetchResp)
	}
}

func TestValidPlugin_QuotaProviderOnly(t *testing.T) {
	plugin := pluginapi.Plugin{
		Metadata: pluginapi.Metadata{
			Name:             "quota-only",
			Version:          "1.0.0",
			Author:           "author",
			GitHubRepository: "https://github.com/example/quota-only",
		},
		Capabilities: pluginapi.Capabilities{
			QuotaProvider: &testQuotaProvider{identifier: "quota-only-provider"},
		},
	}

	if !validPlugin(plugin) {
		t.Fatal("expected validPlugin to return true for plugin with only QuotaProvider capability")
	}
}

func TestQuotaProvider_MultipleSupportedProviders(t *testing.T) {
	provider := &testQuotaProvider{
		identifier: "multi-quota",
		describeFn: func(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			return pluginapi.QuotaDescribeResponse{
				SupportedProviders: []string{"provider-alpha", "provider-beta"},
				DisplayName:        "Multi Quota Provider",
			}, nil
		},
	}

	host := newHostWithRecords(capabilityRecord{
		id: "multi-quota-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: provider,
			},
		},
	})

	if !host.HasQuotaProvider("provider-alpha") {
		t.Fatal("expected host to recognize supported provider-alpha")
	}
	if !host.HasQuotaProvider("provider-beta") {
		t.Fatal("expected host to recognize supported provider-beta")
	}

	resp, handled, errFetch := host.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{
		Provider: "provider-alpha",
	})
	if errFetch != nil || !handled || resp.Subscription == nil || resp.Subscription.Plan != "Pro" {
		t.Fatalf("fetch failed for provider-alpha: handled=%v err=%v resp=%+v", handled, errFetch, resp)
	}
}

func TestQuotaProvider_VersionReloadInvalidatesCache(t *testing.T) {
	providerV1 := &testQuotaProvider{
		identifier: "dynamic-quota",
		describeFn: func(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			return pluginapi.QuotaDescribeResponse{
				SupportedProviders: []string{"provider-v1"},
			}, nil
		},
	}

	host := New()
	setHostSnapshotForTest(host, true, capabilityRecord{
		id:      "dynamic-plugin",
		path:    "plugins/dynamic",
		version: "1.0.0",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: providerV1,
			},
		},
	})

	if !host.HasQuotaProvider("provider-v1") {
		t.Fatal("expected host to recognize provider-v1")
	}
	if host.HasQuotaProvider("provider-v2") {
		t.Fatal("expected host not to recognize provider-v2 before upgrade")
	}

	// Reload with version 2.0.0 supporting provider-v2 instead
	providerV2 := &testQuotaProvider{
		identifier: "dynamic-quota",
		describeFn: func(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			return pluginapi.QuotaDescribeResponse{
				SupportedProviders: []string{"provider-v2"},
			}, nil
		},
	}
	setHostSnapshotForTest(host, true, capabilityRecord{
		id:      "dynamic-plugin",
		path:    "plugins/dynamic",
		version: "2.0.0",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: providerV2,
			},
		},
	})

	if !host.HasQuotaProvider("provider-v2") {
		t.Fatal("expected host to recognize provider-v2 after version upgrade")
	}
	if host.HasQuotaProvider("provider-v1") {
		t.Fatal("expected host not to recognize provider-v1 after version upgrade")
	}
}

func TestQuotaProvider_CrossHostIndependence(t *testing.T) {
	providerA := &testQuotaProvider{
		identifier: "isolated-quota",
		describeFn: func(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			return pluginapi.QuotaDescribeResponse{
				SupportedProviders: []string{"provider-only-on-host-a"},
			}, nil
		},
	}

	hostA := newHostWithRecords(capabilityRecord{
		id: "plugin-a",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: providerA,
			},
		},
	})

	hostB := newHostWithRecords(capabilityRecord{
		id: "plugin-b",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{},
		},
	})

	if !hostA.HasQuotaProvider("provider-only-on-host-a") {
		t.Fatal("hostA should recognize provider-only-on-host-a")
	}
	if hostB.HasQuotaProvider("provider-only-on-host-a") {
		t.Fatal("hostB must not leak or share quota cache with hostA")
	}
}

func TestQuotaProvider_ContextCancellation(t *testing.T) {
	host := newHostWithRecords(capabilityRecord{
		id: "cancel-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: &testQuotaProvider{identifier: "cancel-provider"},
			},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Searching for unknown provider with canceled context should terminate promptly without error
	if host.HasQuotaProviderContext(ctx, "non-existent-provider") {
		t.Fatal("expected false for canceled context search")
	}
}

func TestQuotaProvider_InterleavedReloadDiscardStaleCache(t *testing.T) {
	describeStarted := make(chan struct{})
	allowDescribeFinish := make(chan struct{})
	goroutineDone := make(chan struct{})

	providerV1 := &testQuotaProvider{
		identifier: "interleaved-provider",
		describeFn: func(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			select {
			case <-describeStarted:
			default:
				close(describeStarted)
			}
			<-allowDescribeFinish
			return pluginapi.QuotaDescribeResponse{
				SupportedProviders: []string{"stale-provider"},
			}, nil
		},
	}

	host := New()
	setHostSnapshotForTest(host, true, capabilityRecord{
		id:      "interleaved-plugin",
		path:    "plugins/interleaved",
		version: "1.0.0",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: providerV1,
			},
		},
	})

	// Run Describe in goroutine
	go func() {
		defer close(goroutineDone)
		_ = host.HasQuotaProvider("stale-provider")
	}()

	// Wait for describe to start
	<-describeStarted

	// Trigger reload of same plugin with version 1.0.0 supporting "fresh-provider", incrementing generation
	providerV2 := &testQuotaProvider{
		identifier: "interleaved-provider",
		describeFn: func(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
			return pluginapi.QuotaDescribeResponse{
				SupportedProviders: []string{"fresh-provider"},
			}, nil
		},
	}
	setHostSnapshotForTest(host, true, capabilityRecord{
		id:      "interleaved-plugin",
		path:    "plugins/interleaved",
		version: "1.0.0",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{
				QuotaProvider: providerV2,
			},
		},
	})

	// Allow the old DescribeQuota call to finally return
	close(allowDescribeFinish)
	// Wait for old goroutine to fully finish
	<-goroutineDone

	// Verify that the stale-provider is NOT cached on host because generation changed
	if host.HasQuotaProvider("stale-provider") {
		t.Fatal("stale-provider should not be cached after generation change")
	}
	if !host.HasQuotaProvider("fresh-provider") {
		t.Fatal("fresh-provider should be recognized for new generation")
	}
}

func TestRegisterRPCPlugin_ContextCancellation(t *testing.T) {
	plugin := validTestPlugin("cancel-register-plugin")
	plugin.Capabilities.QuotaProvider = &testQuotaProvider{identifier: "cancel-reg-provider"}

	lookup := newTestSymbolLookup(&testPlugin{
		registerResult: plugin,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled context

	host := New()
	_, err := registerRPCPlugin(ctx, host, "cancel-register-plugin", lookup, pluginabi.MethodPluginRegister, nil)
	if err == nil {
		t.Fatal("expected error when registering with canceled context")
	}
}

func TestQuotaSnapshotCache_RecordsFetchFailureAndReset(t *testing.T) {
	failFetch := false
	provider := &testQuotaProvider{
		identifier: "snapshot-provider",
		fetchFn: func(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
			if failFetch {
				return pluginapi.QuotaFetchResponse{}, errors.New("probe failed")
			}
			return pluginapi.QuotaFetchResponse{
				Subscription: &pluginapi.QuotaSubscription{Plan: "Pro"},
			}, nil
		},
	}
	host := newHostWithRecords(capabilityRecord{
		id: "snapshot-plugin",
		plugin: pluginapi.Plugin{
			Capabilities: pluginapi.Capabilities{QuotaProvider: provider},
		},
	})

	if _, ok := host.CachedQuota("snapshot-provider", "auth-1"); ok {
		t.Fatal("expected no snapshot before the first fetch")
	}

	resp, handled, errFetch := host.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{
		Provider:  "snapshot-provider",
		AuthIndex: "auth-1",
	})
	if errFetch != nil || !handled {
		t.Fatalf("unexpected fetch result: handled=%v err=%v", handled, errFetch)
	}
	// The host stamps the reading, so an expired snapshot cannot pass for a live
	// balance.
	if resp.FetchedAt == "" {
		t.Fatal("expected the host to stamp FetchedAt on the fetch response")
	}
	cached, ok := host.CachedQuota("snapshot-provider", "auth-1")
	if !ok || cached.Failed || !cached.Fetched {
		t.Fatalf("unexpected cached snapshot: %+v ok=%v", cached, ok)
	}
	if cached.FetchedAt.IsZero() || cached.Response.FetchedAt != resp.FetchedAt {
		t.Fatalf("cached snapshot lost its timestamp: %+v", cached)
	}

	// A failed probe is recorded as a failure and keeps the last good reading,
	// so a reader can still say when the credential was last known to have quota.
	failFetch = true
	if _, handled, errFetch = host.FetchQuota(context.Background(), pluginapi.QuotaFetchRequest{
		Provider:  "snapshot-provider",
		AuthIndex: "auth-1",
	}); errFetch == nil || !handled {
		t.Fatalf("expected the failing probe to be handled: handled=%v err=%v", handled, errFetch)
	}
	cached, ok = host.CachedQuota("snapshot-provider", "auth-1")
	if !ok || !cached.Failed || !cached.Fetched {
		t.Fatalf("expected a failed snapshot that keeps the last reading: %+v", cached)
	}

	// A reset drops the reading it just invalidated.
	if _, handled, errReset := host.ResetQuota(context.Background(), pluginapi.QuotaResetRequest{
		Provider:  "snapshot-provider",
		AuthIndex: "auth-1",
	}); errReset != nil || !handled {
		t.Fatalf("unexpected reset result: handled=%v err=%v", handled, errReset)
	}
	if _, ok := host.CachedQuota("snapshot-provider", "auth-1"); ok {
		t.Fatal("expected the reset to drop the cached snapshot")
	}
}

// TestQuotaSnapshotCacheExpiresAndEvicts pins the two deadlines of a recorded
// reading: a reading past its freshness window is still served but marked stale,
// and a record past its retention is dropped so the store tracks live
// credentials instead of every credential ever probed.
func TestQuotaSnapshotCacheExpiresAndEvicts(t *testing.T) {
	base := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	now := base
	host := New()
	host.quotaNow = func() time.Time { return now }

	host.rememberQuotaSnapshot("snapshot-provider", "auth-1", pluginapi.QuotaFetchResponse{
		Subscription: &pluginapi.QuotaSubscription{Plan: "Pro"},
		Channels:     []pluginapi.QuotaChannel{{Key: "api-key", Label: "API Key"}},
	})

	cached, ok := host.CachedQuota("snapshot-provider", "auth-1")
	if !ok || cached.Stale || !cached.Fetched {
		t.Fatalf("fresh snapshot = %+v ok=%v, want a current reading", cached, ok)
	}

	// Past the freshness window the reading is still served: the plan and the
	// channel list it carries are facts about the credential that a failing
	// probe must not destroy.
	now = base.Add(quotaSnapshotFreshFor + time.Second)
	cached, ok = host.CachedQuota("snapshot-provider", "auth-1")
	if !ok || !cached.Stale || !cached.Fetched {
		t.Fatalf("stale snapshot = %+v ok=%v, want a stale reading", cached, ok)
	}
	if cached.Response.Subscription == nil || cached.Response.Subscription.Plan != "Pro" || len(cached.Response.Channels) != 1 {
		t.Fatalf("a stale reading must keep its plan and channels: %+v", cached.Response)
	}

	// Past retention the record is gone, not merely hidden.
	now = base.Add(quotaSnapshotRetainFor + time.Second)
	if _, ok = host.CachedQuota("snapshot-provider", "auth-1"); ok {
		t.Fatal("expected the record to be dropped once its retention passed")
	}
	host.quotaMu.Lock()
	_, retained := host.quotaSnapshots[quotaSnapshotKey("snapshot-provider", "auth-1")]
	host.quotaMu.Unlock()
	if retained {
		t.Fatal("expected the expired record to be deleted from the store, not only hidden")
	}

	// A failure after expiry refreshes retention but must not make the old
	// reading look current again.
	now = base
	host.rememberQuotaSnapshot("snapshot-provider", "auth-2", pluginapi.QuotaFetchResponse{})
	now = base.Add(quotaSnapshotFreshFor + time.Second)
	host.rememberQuotaSnapshotFailure("snapshot-provider", "auth-2")
	cached, ok = host.CachedQuota("snapshot-provider", "auth-2")
	if !ok || !cached.Failed || !cached.Stale {
		t.Fatalf("failure after expiry = %+v ok=%v, want failed and still stale", cached, ok)
	}

	// A record that only ever recorded a failure is evicted too, so one failed
	// sweep cannot leave a permanent entry behind for every credential.
	now = base
	host.rememberQuotaSnapshotFailure("snapshot-provider", "auth-failed")
	now = base.Add(quotaSnapshotRetainFor + time.Second)
	if _, ok = host.CachedQuota("snapshot-provider", "auth-failed"); ok {
		t.Fatal("expected a failure-only record to be evicted once its retention passed")
	}

	// The store is capped, and the record nearest eviction goes first.
	now = base
	capped := New()
	capped.quotaNow = func() time.Time { return now }
	for i := range maxQuotaSnapshots + 1 {
		now = base.Add(time.Duration(i) * time.Second)
		capped.rememberQuotaSnapshot("snapshot-provider", fmt.Sprintf("auth-%d", i), pluginapi.QuotaFetchResponse{})
	}
	capped.quotaMu.Lock()
	size := len(capped.quotaSnapshots)
	_, oldestKept := capped.quotaSnapshots[quotaSnapshotKey("snapshot-provider", "auth-0")]
	capped.quotaMu.Unlock()
	if size > maxQuotaSnapshots {
		t.Fatalf("snapshot store size = %d, want at most %d", size, maxQuotaSnapshots)
	}
	if oldestKept {
		t.Fatal("expected the record nearest eviction to be dropped first")
	}
}
