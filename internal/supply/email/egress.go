package email

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/proxy"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// This file is the mailbox's exit: the one place that turns a channel's egress
// setting into a transport.
//
// Why it exists at all: a mailbox is read on behalf of an account that is being
// registered, and the platform judging that registration sees two addresses —
// the one that fetched the mail and the one that ran the signup. Reading mail
// from a different address than the signup is exactly the split fraud scoring
// looks for, so the exit has to be configurable per mailbox rather than
// inherited from whatever the host process happens to have.
//
// The setting is a plain proxy URL (http, https, socks5, socks5h), "direct" to
// force a bypass, or empty to inherit the environment. It is parsed by
// proxyutil, which the model path already uses, so one spelling works
// everywhere.

// egressClients pools one HTTP client per egress string.
//
// The pool exists because a mailbox is read repeatedly (a poll every few
// seconds while a code is awaited) and a transport per read would rebuild the
// connection pool each time. A client is safe for concurrent use, so sharing it
// across mailboxes that name the same exit is intended.
var egressClients struct {
	mu    sync.Mutex
	byKey map[string]*http.Client
}

// clientForEgress returns the HTTP client a mailbox exits through.
//
// An empty egress returns the package default, which is what a caller with no
// setting has always used. A malformed setting is an error rather than a silent
// fallback: reading mail through an exit the operator did not ask for would
// hide the mistake until the platform refused the account.
func clientForEgress(egress string) (*http.Client, error) {
	trimmed := strings.TrimSpace(egress)
	if trimmed == "" {
		return graphHTTPClient, nil
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
	client := &http.Client{Timeout: dialTimeout}
	if transport != nil && (mode == proxyutil.ModeProxy || mode == proxyutil.ModeDirect) {
		client.Transport = transport
	}
	if egressClients.byKey == nil {
		egressClients.byKey = map[string]*http.Client{}
	}
	egressClients.byKey[trimmed] = client
	return client, nil
}

// clientOr returns the first non-nil client, so a caller can pass an optional
// per-mailbox exit without repeating the fallback at every request.
func clientOr(fallback, client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return fallback
}

// firstNonEmpty returns the first value that carries a setting. A channel's own
// exit wins over the supply-wide one, which is what lets two sources of
// identities stay on separate addresses.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// dialForEgress returns the TCP dialer an IMAP session opens through.
//
// IMAP is a raw TLS connection, not HTTP, so it needs the connection-layer
// dialer rather than an HTTP transport. "direct" and an empty setting both
// yield a plain dialer; only a concrete proxy changes the route.
func dialForEgress(egress string) (func(ctx context.Context, network, address string) (net.Conn, error), error) {
	trimmed := strings.TrimSpace(egress)
	plain := (&net.Dialer{Timeout: dialTimeout}).DialContext
	if trimmed == "" || strings.EqualFold(trimmed, "direct") || strings.EqualFold(trimmed, "none") {
		return plain, nil
	}
	dialer, mode, errBuild := proxyutil.BuildDialer(trimmed)
	if errBuild != nil {
		return nil, errBuild
	}
	if mode != proxyutil.ModeProxy || dialer == nil {
		return plain, nil
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("email: the egress proxy does not support context cancellation")
	}
	return contextDialer.DialContext, nil
}
