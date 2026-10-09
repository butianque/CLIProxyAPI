package auth

import (
	"strings"
	"sync/atomic"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// credentialPoolSnapshot is the resolved credential-pools table: a pool name
// maps to the set of credential file base names it contains.
//
// Membership is declared explicitly in configuration rather than inferred from a
// credential's provider. The table is published as a package-level snapshot so
// every selection path — including the scheduler, which has no access to the
// Manager — enforces the same rule from the same source.
type credentialPoolSnapshot map[string]map[string]struct{}

var credentialPools atomic.Pointer[credentialPoolSnapshot]

// setCredentialPools publishes the resolved credential-pools table from config.
// A nil or empty map clears it, which restores unrestricted selection for every
// scoped key (nothing can match an empty table).
func setCredentialPools(pools map[string][]string) {
	if len(pools) == 0 {
		credentialPools.Store(nil)
		return
	}
	resolved := make(credentialPoolSnapshot, len(pools))
	for pool, names := range pools {
		pool = strings.ToLower(strings.TrimSpace(pool))
		if pool == "" {
			continue
		}
		members := make(map[string]struct{}, len(names))
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			members[name] = struct{}{}
		}
		if len(members) > 0 {
			resolved[pool] = members
		}
	}
	if len(resolved) == 0 {
		credentialPools.Store(nil)
		return
	}
	credentialPools.Store(&resolved)
}

// credentialContains reports whether the named credential belongs to pool.
func credentialContains(pool, name string) bool {
	snapshot := credentialPools.Load()
	if snapshot == nil || name == "" {
		return false
	}
	members, ok := (*snapshot)[strings.ToLower(strings.TrimSpace(pool))]
	if !ok {
		return false
	}
	_, found := members[name]
	return found
}

// resolveCredentialPools derives the pool table from a config snapshot. It is the
// single place configuration becomes the runtime table, so the Manager and any
// other publisher agree on the shape.
func resolveCredentialPools(cfg *internalconfig.Config) map[string][]string {
	if cfg == nil {
		return nil
	}
	return cfg.CredentialPools
}
