package management

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestDescribeEgress(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		display    string
		direct     bool
	}{
		{name: "empty inherits", configured: "", display: "", direct: true},
		{name: "whitespace only", configured: "   ", display: "", direct: true},
		{name: "explicit direct", configured: "direct", display: "", direct: true},
		{name: "explicit none", configured: "NONE", display: "", direct: true},
		{
			name:       "proxy hides the password",
			configured: "socks5://user:secretpw@127.0.0.1:1080",
			display:    "socks5://redacted@127.0.0.1:1080",
			direct:     false,
		},
		{
			name:       "proxy without credentials",
			configured: "http://127.0.0.1:8080",
			display:    "http://127.0.0.1:8080",
			direct:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			display, direct := describeEgress(tc.configured)
			if display != tc.display || direct != tc.direct {
				t.Fatalf("describeEgress(%q) = (%q, %v), want (%q, %v)",
					tc.configured, display, direct, tc.display, tc.direct)
			}
		})
	}
}

// The probe has to resolve the exit the same way the server does, or the panel
// would test an address no traffic ever uses. Supply traffic inherits the host
// proxy unless it names its own.
func TestSupplyExitInheritsHostProxy(t *testing.T) {
	cases := []struct {
		name      string
		supply    string
		hostProxy string
		want      string
	}{
		{name: "nothing configured", want: ""},
		{name: "inherits host proxy", hostProxy: "http://127.0.0.1:7890", want: "http://127.0.0.1:7890"},
		{
			name:      "own exit wins",
			supply:    "socks5://127.0.0.1:1080",
			hostProxy: "http://127.0.0.1:7890",
			want:      "socks5://127.0.0.1:1080",
		},
		{name: "blank supply inherits", supply: "   ", hostProxy: "direct", want: "direct"},
		{name: "whitespace is trimmed", supply: " http://a:1 ", want: "http://a:1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &Handler{cfg: &config.Config{SDKConfig: config.SDKConfig{ProxyURL: tc.hostProxy}}}
			handler.cfg.Supply.Egress = tc.supply
			if got := handler.supplyExit(); got != tc.want {
				t.Fatalf("supplyExit() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The echo services report the network in three incompatible shapes. Each case
// below is a real payload shape, so a rename at one service empties one field
// instead of silently emptying the whole answer.
func TestNormalizeEcho(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    egressEcho
	}{
		{
			name: "nested connection block",
			payload: map[string]any{
				"ip":           "16.106.25.128",
				"country":      "Hong Kong",
				"country_code": "HK",
				"region":       "Hong Kong",
				"city":         "Hong Kong",
				"connection": map[string]any{
					"asn": float64(16509),
					"org": "Amazon.com, Inc.",
				},
			},
			want: egressEcho{
				IP:          "16.106.25.128",
				Country:     "Hong Kong",
				CountryCode: "HK",
				Region:      "Hong Kong",
				City:        "Hong Kong",
				ASN:         "AS16509",
				Org:         "Amazon.com, Inc.",
			},
		},
		{
			name: "flat asn_organization",
			payload: map[string]any{
				"ip":               "16.106.25.128",
				"country":          "Hong Kong",
				"country_code":     "HK",
				"region":           "Kowloon",
				"city":             "Hong Kong",
				"asn":              float64(16509),
				"asn_organization": "Amazon.com, Inc.",
				"organization":     "Amazon.com",
				"isp":              "Amazon.com",
			},
			want: egressEcho{
				IP:          "16.106.25.128",
				Country:     "Hong Kong",
				CountryCode: "HK",
				Region:      "Kowloon",
				City:        "Hong Kong",
				ASN:         "AS16509",
				Org:         "Amazon.com, Inc.",
			},
		},
		{
			name: "network folded into org",
			payload: map[string]any{
				"ip":      "96.62.1.2",
				"country": "HK",
				"org":     "AS9009 M247 Europe SRL",
			},
			want: egressEcho{
				IP:      "96.62.1.2",
				Country: "HK",
				ASN:     "AS9009",
				Org:     "M247 Europe SRL",
			},
		},
		{
			name:    "address only",
			payload: map[string]any{"ip": "203.0.113.9"},
			want:    egressEcho{IP: "203.0.113.9"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeEcho(tc.payload)
			if got != tc.want {
				t.Fatalf("normalizeEcho() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestNormalizeNetwork(t *testing.T) {
	cases := []struct {
		asn, org         string
		wantASN, wantOrg string
	}{
		{asn: "", org: "", wantASN: "", wantOrg: ""},
		{asn: "16509", org: "Amazon.com", wantASN: "AS16509", wantOrg: "Amazon.com"},
		{asn: "as16509", org: "Amazon.com", wantASN: "AS16509", wantOrg: "Amazon.com"},
		{asn: "", org: "AS9009 M247 Europe SRL", wantASN: "AS9009", wantOrg: "M247 Europe SRL"},
		{asn: "", org: "M247 Europe SRL", wantASN: "", wantOrg: "M247 Europe SRL"},
	}
	for _, tc := range cases {
		asn, org := normalizeNetwork(tc.asn, tc.org)
		if asn != tc.wantASN || org != tc.wantOrg {
			t.Fatalf("normalizeNetwork(%q, %q) = (%q, %q), want (%q, %q)",
				tc.asn, tc.org, asn, org, tc.wantASN, tc.wantOrg)
		}
	}
}
