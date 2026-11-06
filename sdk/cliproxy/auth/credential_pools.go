package auth

import (
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialpools"
)

// setCredentialPools publishes the resolved credential-pools table from config.
// A nil or empty map clears it, which restores unrestricted selection for every
// scoped key (nothing can match an empty table).
func setCredentialPools(pools map[string][]string) {
	credentialpools.Publish(pools)
}

// credentialContains reports whether the named credential belongs to pool.
func credentialContains(pool, name string) bool {
	return credentialpools.Contains(pool, name)
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
