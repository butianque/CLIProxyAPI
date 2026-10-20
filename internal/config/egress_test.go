package config

import "testing"

// TestEffectiveProxyURLPrefersThePoolDefault pins the precedence that makes the
// proxy pool the one place an exit is configured: while the pool designates a
// default, the address spelled out in the config file is not used.
//
// The pool's answer is asked for on every call rather than copied once, which is
// what lets a replaced exit take effect without a restart.
func TestEffectiveProxyURLPrefersThePoolDefault(t *testing.T) {
	cases := []struct {
		name   string
		typed  string
		pool   string
		poolOK bool
		want   string
	}{
		{name: "nothing configured", want: ""},
		{name: "hand-written only", typed: "http://typed:8080", want: "http://typed:8080"},
		{name: "pool default wins", typed: "http://typed:8080", pool: "socks5://u:p@10.0.0.1:1080", poolOK: true, want: "socks5://u:p@10.0.0.1:1080"},
		{name: "pool default alone", pool: "socks5://u:p@10.0.0.1:1080", poolOK: true, want: "socks5://u:p@10.0.0.1:1080"},
		// An unresolvable default is passed on as-is so the transport rejects it.
		// Falling back to the typed address would hide a retired exit.
		{name: "dangling default fails closed", typed: "http://typed:8080", pool: "unresolved:egress-id", poolOK: true, want: "unresolved:egress-id"},
	}

	previous := egressDefault.Load()
	t.Cleanup(func() { egressDefault.Store(previous) })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool, poolOK := tc.pool, tc.poolOK
			SetEgressDefaultResolver(func() (string, bool) { return pool, poolOK })

			cfg := &Config{SDKConfig: SDKConfig{ProxyURL: tc.typed}}
			if got := cfg.EffectiveProxyURL(); got != tc.want {
				t.Fatalf("EffectiveProxyURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEffectiveProxyURLWithoutAPoolResolver pins that an installation which never
// opened the pool keeps behaving exactly as before.
func TestEffectiveProxyURLWithoutAPoolResolver(t *testing.T) {
	previous := egressDefault.Load()
	t.Cleanup(func() { egressDefault.Store(previous) })
	egressDefault.Store(nil)

	cfg := &Config{SDKConfig: SDKConfig{ProxyURL: " http://typed:8080 "}}
	if got := cfg.EffectiveProxyURL(); got != "http://typed:8080" {
		t.Fatalf("EffectiveProxyURL() = %q, want the trimmed address", got)
	}

	var nilConfig *Config
	if got := nilConfig.EffectiveProxyURL(); got != "" {
		t.Fatalf("EffectiveProxyURL() on a nil config = %q, want empty", got)
	}
}
