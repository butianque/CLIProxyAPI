package phone

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// This file is the platform exit: the one place that turns an egress setting
// into the HTTP client every platform call uses.
//
// Why it matters here: renting a number is one half of a registration, and the
// platform that is being registered on sees the other half. A number rented from
// one address while the signup runs from another is the split that fraud scoring
// looks for, so the exit belongs to the supply layer rather than to whatever
// route the host process happens to have.
//
// The setting is a proxy URL (http, https, socks5, socks5h), "direct" to force a
// bypass, or empty to inherit the environment. proxyutil parses it, so one
// spelling works for both supply kinds and the model path.

// platformTimeout bounds one platform call. It is the value the provider has
// always used, kept here so the client built from an egress behaves exactly
// like the default one.
const platformTimeout = 20 * time.Second

// egressClients pools one client per egress string: a platform poll repeats
// every few seconds while a code is awaited, and rebuilding the connection pool
// each time would be wasteful. A client is safe for concurrent use.
var egressClients struct {
	mu    sync.Mutex
	byKey map[string]*http.Client
}

// clientForEgress returns the client a platform call exits through. An empty
// egress yields the plain client the provider has always built.
//
// A malformed setting is an error rather than a silent fallback: renting through
// an exit the operator did not ask for would only show up later, as a platform
// refusing the account.
func clientForEgress(egress string) (*http.Client, error) {
	trimmed := strings.TrimSpace(egress)
	if trimmed == "" {
		return &http.Client{Timeout: platformTimeout}, nil
	}
	egressClients.mu.Lock()
	defer egressClients.mu.Unlock()
	if client, ok := egressClients.byKey[trimmed]; ok {
		return client, nil
	}
	transport, mode, errBuild := proxyutil.BuildHTTPTransport(trimmed)
	if errBuild != nil {
		return nil, errBuild
	}
	client := &http.Client{Timeout: platformTimeout}
	if transport != nil && (mode == proxyutil.ModeProxy || mode == proxyutil.ModeDirect) {
		client.Transport = transport
	}
	if egressClients.byKey == nil {
		egressClients.byKey = map[string]*http.Client{}
	}
	egressClients.byKey[trimmed] = client
	return client, nil
}
