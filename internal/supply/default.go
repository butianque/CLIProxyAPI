package supply

import (
	"fmt"
	"sync"
)

// defaultState holds the process-wide supply service. It is built once at
// startup from configuration and replaced when that configuration changes, so
// a call in flight and a call after a reload never observe a torn value.
var defaultState struct {
	mu      sync.RWMutex
	service Supply
}

// Default returns the process-wide supply service, or nil when no supply kind
// is configured. Callers must treat nil as "not set up" rather than an error.
func Default() Supply {
	defaultState.mu.RLock()
	defer defaultState.mu.RUnlock()
	return defaultState.service
}

// SetDefault installs the process-wide supply service. Passing nil clears it.
// It is called by startup and by configuration reload.
func SetDefault(service Supply) {
	defaultState.mu.Lock()
	defer defaultState.mu.Unlock()
	defaultState.service = service
}

// ProviderFor returns the provider serving kind from the process-wide service.
// It reports ErrUnavailable when no service is installed, when the service does
// not route by kind, or when the kind has no provider — all of which mean "this
// kind is not configured", which is a normal state rather than an error.
func ProviderFor(kind Kind) (Provider, error) {
	service := Default()
	if service == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, kind)
	}
	lookup, ok := service.(KindLookup)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, kind)
	}
	return lookup.Provider(kind)
}

// DefaultLedger returns the process-wide cross-kind identity ledger, or nil when
// no supply service is installed. It is the one document every kind shares.
func DefaultLedger() *Ledger {
	service := Default()
	if service == nil {
		return nil
	}
	provider, ok := service.(LedgerProvider)
	if !ok {
		return nil
	}
	return provider.Ledger()
}
