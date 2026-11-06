// Package credentialpools holds the resolved credential-pools table and the
// single scope-matching rule that credential selection and the model catalogue
// both apply.
//
// The rule used to live in two copies — one in the auth manager (selection) and
// one in the model registry (catalogue) — each claiming to mirror the other.
// They drifted: selection honoured a pool name from a hand-written
// credential-pools entry, the catalogue did not. Keeping one implementation here
// removes the possibility of a second drift.
package credentialpools

import (
	"strings"
	"sync/atomic"
)

// snapshot maps a pool name to the set of credential names it contains. Pool
// keys and member names are stored lowercased and trimmed so comparisons are
// case-insensitive and ignore surrounding whitespace.
type snapshot map[string]map[string]struct{}

var current atomic.Pointer[snapshot]

// Publish replaces the resolved credential-pools table from configuration. A nil
// or empty table clears it, so nothing matches and a scoped key falls back to its
// other scope forms.
func Publish(pools map[string][]string) {
	if len(pools) == 0 {
		current.Store(nil)
		return
	}
	resolved := make(snapshot, len(pools))
	for pool, names := range pools {
		pool = normalize(pool)
		if pool == "" {
			continue
		}
		members := make(map[string]struct{}, len(names))
		for _, name := range names {
			if name = normalize(name); name != "" {
				members[name] = struct{}{}
			}
		}
		if len(members) > 0 {
			resolved[pool] = members
		}
	}
	if len(resolved) == 0 {
		current.Store(nil)
		return
	}
	current.Store(&resolved)
}

// Contains reports whether the named credential belongs to pool.
func Contains(pool, name string) bool {
	snap := current.Load()
	if snap == nil || normalize(name) == "" {
		return false
	}
	members, ok := (*snap)[normalize(pool)]
	if !ok {
		return false
	}
	_, found := members[normalize(name)]
	return found
}

// MatchesScope reports whether one credential falls inside a caller's scope. A
// scope entry matches by provider (the account category), by the credential's own
// name, or by naming a pool the credential belongs to.
//
// An empty scope matches nothing: whether "no scope" means "unrestricted" is the
// caller's decision, not the matcher's.
func MatchesScope(scope []string, provider, name string) bool {
	provider = normalize(provider)
	name = normalize(name)
	for _, entry := range scope {
		if entry = normalize(entry); entry == "" {
			continue
		}
		if (provider != "" && entry == provider) || (name != "" && entry == name) {
			return true
		}
		if Contains(entry, name) {
			return true
		}
	}
	return false
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
