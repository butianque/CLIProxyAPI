package auth

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync/atomic"
)

// This file lets a credential name its exit by pool id instead of by address.
//
// Why an id: an exit is a bought address that gets replaced. When it is, every
// account on it has to move together, and an address copied into each auth file
// would mean editing N files with no way to answer "who is on #1". The pool owns
// the address; the credential only remembers which entry it belongs to.
//
// The resolution has to happen here, at load time, because this is where an auth
// file's proxy_url is read. The pool itself lives behind the host (it is a supply
// state document), so the host installs a resolver once at startup rather than
// this package reaching into it.

// EgressResolver turns a proxy-pool id into the address it names.
type EgressResolver func(id int) (string, error)

// UnresolvedEgress is what a credential falls back to when it names a pool id
// that cannot be resolved.
//
// It is deliberately not a valid proxy address: the transport builder rejects
// it, so a dangling reference fails loudly instead of quietly leaving from the
// host's own address. A silent direct connection is the one outcome this design
// must never produce, because it puts an identity on an address nobody chose.
const UnresolvedEgress = "unresolved:egress-id"

// egressResolver is installed by the host at startup. Nil means none was
// installed, which is not a licence to connect directly: an id then fails
// closed, the same as an id the pool cannot resolve.
var egressResolver atomic.Pointer[EgressResolver]

// SetEgressResolver installs the function that resolves proxy-pool ids.
//
// Passing nil uninstalls it, which is what a test that does not want the pool in
// the way wants.
func SetEgressResolver(resolver EgressResolver) {
	if resolver == nil {
		egressResolver.Store(nil)
		return
	}
	egressResolver.Store(&resolver)
}

// ResolveEgressID turns a stored id into the address it names.
//
// Exported because the management surface needs the same answer when an
// operator edits an account: the address it stores beside the id has to agree
// with the pool at the moment of the edit.
func ResolveEgressID(id int) string {
	resolver := egressResolver.Load()
	if resolver == nil {
		return UnresolvedEgress
	}
	url, errResolve := (*resolver)(id)
	if errResolve != nil || strings.TrimSpace(url) == "" {
		return UnresolvedEgress
	}
	return url
}

// EgressIDFromMetadata reads the pool id an auth document carries.
//
// It accepts the shapes a hand-written or panel-written file can produce: a JSON
// number, a string, or a value that survived a round trip through a generic map.
// A zero or negative id is not a reference, so it is reported as absent rather
// than as a dangling one.
func EgressIDFromMetadata(metadata map[string]any) (int, bool) {
	if metadata == nil {
		return 0, false
	}
	raw, ok := metadata["egress_id"]
	if !ok {
		return 0, false
	}
	var id int
	switch typed := raw.(type) {
	case float64:
		id = int(typed)
	case int:
		id = typed
	case int64:
		id = int(typed)
	case json.Number:
		parsed, errParse := typed.Int64()
		if errParse != nil {
			return 0, false
		}
		id = int(parsed)
	case string:
		parsed, errParse := strconv.Atoi(strings.TrimSpace(typed))
		if errParse != nil {
			return 0, false
		}
		id = parsed
	default:
		return 0, false
	}
	// A non-positive id is not a reference at all, so it is reported as absent
	// rather than handed back as a value a caller might use.
	if id <= 0 {
		return 0, false
	}
	return id, true
}
