package email

import (
	"context"
	"strings"
	"sync"
)

// Defaults for how many mailboxes may be open at once.
//
// The limits exist because a mailbox is a connection, not a function call: a
// provider throttles or blocks an address that opens many sessions at once, and
// an unbounded reader turns one busy script into a lockout for every other. The
// numbers are deliberately low — a verification poll needs one session, not
// fifty — and they are per process, not per caller.
const (
	// DefaultMaxOpen bounds all mailboxes opened at once.
	DefaultMaxOpen = 8
	// DefaultMaxPerHost bounds the mailboxes opened at once against one server.
	// A provider sees one client address, so the per-host limit is what keeps a
	// fan-out from looking like an attack to it.
	DefaultMaxPerHost = 4
)

// dialGate bounds how many mailbox sessions are open at once.
//
// A waiter is not rejected: it waits, because a caller that asked for mail would
// rather be answered a second later than be told to come back. It waits only
// until its own context ends, which is the caller's own bound.
type dialGate struct {
	total   chan struct{}
	maxHost int

	mu      sync.Mutex
	perHost map[string]chan struct{}
}

// newDialGate builds a gate. A non-positive limit means "no bound", which is what
// an operator configuring zero asked for.
func newDialGate(maxTotal, maxHost int) *dialGate {
	gate := &dialGate{maxHost: maxHost, perHost: make(map[string]chan struct{})}
	if maxTotal > 0 {
		gate.total = make(chan struct{}, maxTotal)
	}
	return gate
}

// acquire takes one slot for host and returns the release that gives it back.
//
// The release is idempotent, so a caller can defer it and also call it on an
// error path without taking a second slot away from anyone.
func (g *dialGate) acquire(ctx context.Context, host string) (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	if g.total != nil {
		select {
		case g.total <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || g.maxHost <= 0 {
		return func() {
			if g.total != nil {
				<-g.total
			}
		}, nil
	}
	slots := g.hostSlots(host)
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		if g.total != nil {
			<-g.total
		}
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-slots
			if g.total != nil {
				<-g.total
			}
		})
	}, nil
}

// hostSlots returns the slot channel for one server, creating it on first use.
// The map is bounded by the number of distinct servers, which is the number of
// configured mailboxes, so it is never cleaned up.
func (g *dialGate) hostSlots(host string) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	slots, ok := g.perHost[host]
	if !ok {
		slots = make(chan struct{}, g.maxHost)
		g.perHost[host] = slots
	}
	return slots
}

// gateKey names the server a target connects to, for the per-host bound. A Graph
// mailbox has no host of its own — every one of them is served by the same
// endpoint — so it is grouped by that endpoint rather than by account, which is
// what the provider actually sees.
func gateKey(target Target) string {
	if host := strings.TrimSpace(target.Host); host != "" {
		return host
	}
	if target.Auth == AuthGraph {
		return "graph.microsoft.com"
	}
	return ""
}
