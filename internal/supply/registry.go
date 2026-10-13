package supply

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrUnavailable reports that a supply kind has no configured implementation.
// It is distinct from a transport failure so a caller can tell "not set up"
// from "tried and failed".
var ErrUnavailable = errors.New("supply: kind is not configured")

// ErrNoStock reports that no identity of the requested kind is currently
// available. It is fatal for one acquisition attempt: retrying immediately
// would hit the same shortage.
var ErrNoStock = errors.New("supply: no identity available")

// Provider is one implementation able to serve a single kind. A provider is
// selected when the service is built; the registry routes each call to the
// provider registered for its kind.
type Provider interface {
	// Kind names the supply kind this provider serves.
	Kind() Kind
	// Status reports this provider's readiness. It never returns a credential
	// value.
	Status(ctx context.Context) (Status, error)
	// Grab hands out one identity.
	Grab(ctx context.Context, opts GrabOptions) (Identity, error)
	// Read reads one identity's inbox once.
	Read(ctx context.Context, purpose, address string) (Message, error)
	// Link associates an identity with the account it registered. Providers
	// without a ledger may treat it as a no-op.
	Link(ctx context.Context, address, account, authIndex string) error
	// Release returns an identity to its source when the kind has a pool.
	Release(ctx context.Context, address, outcome string) error
}

// KindLookup exposes one kind's provider. A supply service that can route by
// kind implements it, so a kind-specific management surface can reach its own
// implementation without asserting on a concrete service type (the shared
// Supply contract stays free of management-only methods, and a decorated
// service does not break the lookup).
type KindLookup interface {
	Provider(kind Kind) (Provider, error)
}

// Registry routes supply calls to the provider registered for each kind.
//
// Registration happens once at startup. A kind with no provider is a normal
// state (the operator simply has not configured that kind), so the registry
// reports it as ErrUnavailable rather than panicking.
type Registry struct {
	mu        sync.RWMutex
	providers map[Kind]Provider
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{providers: map[Kind]Provider{}}
}

// Register installs the provider for its kind, replacing any previous one.
// Replacing is deliberate: a configuration change rebuilds the registry.
func (r *Registry) Register(provider Provider) error {
	if provider == nil {
		return errors.New("supply: provider is nil")
	}
	kind := provider.Kind()
	if !kind.Valid() {
		return fmt.Errorf("supply: provider declares unknown kind %q", kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[kind] = provider
	return nil
}

// providerFor returns the provider serving kind.
func (r *Registry) providerFor(kind Kind) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	provider, ok := r.providers[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, kind)
	}
	return provider, nil
}

// Provider returns the provider registered for kind, so a kind-specific
// management surface can reach its own implementation without the shared
// contract having to grow management-only methods.
func (r *Registry) Provider(kind Kind) (Provider, error) {
	return r.providerFor(kind)
}

// Status reports the aggregate readiness across every registered kind.
func (r *Registry) Status(ctx context.Context) (Status, error) {
	r.mu.RLock()
	providers := make([]Provider, 0, len(r.providers))
	for _, provider := range r.providers {
		providers = append(providers, provider)
	}
	r.mu.RUnlock()

	status := Status{Kinds: make([]Kind, 0, len(providers))}
	for _, provider := range providers {
		one, errStatus := provider.Status(ctx)
		if errStatus != nil {
			// One broken provider must not hide the others; it is reported as
			// not-ready instead of failing the whole status.
			continue
		}
		status.Enabled = status.Enabled || one.Enabled
		status.Locked = status.Locked || one.Locked
		if one.Enabled {
			status.Kinds = append(status.Kinds, provider.Kind())
		}
	}
	return status, nil
}

// Grab hands out one identity of the requested kind.
func (r *Registry) Grab(ctx context.Context, kind Kind, opts GrabOptions) (Identity, error) {
	provider, errProvider := r.providerFor(kind)
	if errProvider != nil {
		return Identity{}, errProvider
	}
	return provider.Grab(ctx, opts)
}

// Read reads one identity's inbox once.
func (r *Registry) Read(ctx context.Context, kind Kind, purpose, address string) (Message, error) {
	provider, errProvider := r.providerFor(kind)
	if errProvider != nil {
		return Message{}, errProvider
	}
	return provider.Read(ctx, purpose, address)
}

// Link associates an identity with the account it registered.
func (r *Registry) Link(ctx context.Context, kind Kind, address, account, authIndex string) error {
	provider, errProvider := r.providerFor(kind)
	if errProvider != nil {
		return errProvider
	}
	return provider.Link(ctx, address, account, authIndex)
}

// Release returns an identity to its source. A kind whose provider has no pool
// is a no-op rather than an error.
func (r *Registry) Release(ctx context.Context, kind Kind, address, outcome string) error {
	provider, errProvider := r.providerFor(kind)
	if errProvider != nil {
		return errProvider
	}
	return provider.Release(ctx, address, outcome)
}

// Registry implements Supply.
var _ Supply = (*Registry)(nil)

// Registry implements KindLookup.
var _ KindLookup = (*Registry)(nil)