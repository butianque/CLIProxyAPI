// Package plugincatalog answers one question for a plugin: what models does
// THIS credential serve?
//
// Every platform answers it differently — one wants the session in a "token"
// header, another in "Bearer", a third has no per-credential endpoint at all —
// so the HTTP exchange stays with the plugin. What does not differ is everything
// around it, and those are the parts that go wrong quietly:
//
//   - The answer belongs to one credential. Entitlements are per account, so a
//     cache keyed by provider, plan or realm hands one account's catalogue to
//     another. Cache by credential.
//
//   - A platform that answers HTTP 200 with a business code turns "this session
//     died" into a parse error, and a parse error looks like a plugin bug. Mark
//     that case with LoggedOut and it is handled as what it is.
//
//   - A failed probe is not "this credential serves nothing". Publishing an
//     empty list makes the host unregister the credential from routing, so a
//     transient timeout would silently take an account out of service. Resolver
//     keeps the last good answer instead.
//
// None of this needs the concrete platform, which is why it lives here rather
// than in one plugin.
package plugincatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Model is one catalogue entry, holding the values that reach a client.
//
// A plugin fills in what its platform reports and leaves the rest zero. Zero
// means "this platform did not say", which is honest; inventing a number makes
// every model look the same and hides the ones that really are different.
type Model struct {
	ID   string
	Name string
	// Type is the capability family the platform uses ("chat", "image", ...).
	// Empty defaults to "chat".
	Type             string
	Created          int64
	ContextLength    int64
	MaxOutputTokens  int64
	InputModalities  []string
	OutputModalities []string
	FunctionCalling  bool
	Streaming        bool
	Reasoning        bool
}

// Infos renders models as the catalogue the host publishes.
//
// Entries without an id are dropped, a repeated id keeps its first entry, and
// the fields a client needs are defaulted from the id rather than from another
// model's metadata.
func Infos(owner string, models []Model) []pluginapi.ModelInfo {
	out := make([]pluginapi.ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		id := strings.TrimSpace(model.ID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		name := strings.TrimSpace(model.Name)
		if name == "" {
			name = id
		}
		modelType := strings.TrimSpace(model.Type)
		if modelType == "" {
			modelType = "chat"
		}
		out = append(out, pluginapi.ModelInfo{
			ID:          id,
			Object:      "model",
			Created:     model.Created,
			OwnedBy:     owner,
			Type:        modelType,
			DisplayName: name,
			Name:        id,
			// Every entry here is served over the chat-completions route; an
			// image model differs in what it produces, not in how it is called.
			SupportedGenerationMethods: []string{"chat"},
			ContextLength:              model.ContextLength,
			MaxCompletionTokens:        model.MaxOutputTokens,
			SupportedInputModalities:   modalityList(model.InputModalities, "text"),
			SupportedOutputModalities:  modalityList(model.OutputModalities, "text"),
			UserDefined:                true,
		})
	}
	return out
}

func modalityList(modalities []string, fallback string) []string {
	if len(modalities) == 0 {
		return []string{fallback}
	}
	out := make([]string, 0, len(modalities))
	for _, modality := range modalities {
		if trimmed := strings.TrimSpace(modality); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return []string{fallback}
	}
	return out
}

// Cache is a per-credential catalogue cache with a fixed lifetime and a bound.
//
// The lifetime is the plugin's freshness trade: a short one costs one upstream
// call per credential per interval, a long one keeps a retired model visible.
// The bound only matters when many credentials are asked about inside one
// lifetime; expired entries are dropped on every write, so it is a backstop, not
// the mechanism.
type Cache struct {
	mu       sync.Mutex
	ttl      time.Duration
	capacity int
	now      func() time.Time
	entries  map[string]cacheEntry
}

type cacheEntry struct {
	models    []Model
	expiresAt time.Time
}

// NewCache builds a cache. A non-positive ttl caches nothing, and a non-positive
// capacity means unbounded (expired entries are still dropped).
func NewCache(ttl time.Duration, capacity int) *Cache {
	return &Cache{ttl: ttl, capacity: capacity, now: time.Now}
}

// Get returns a copy of the cached catalogue for key.
func (c *Cache) Get(key string) ([]Model, bool) {
	if c == nil || c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, okEntry := c.entries[key]
	if !okEntry || len(entry.models) == 0 || !c.now().Before(entry.expiresAt) {
		return nil, false
	}
	return cloneModels(entry.models), true
}

// Put stores models for key, dropping anything that has expired.
func (c *Cache) Put(key string, models []Model) {
	if c == nil || c.ttl <= 0 || len(models) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]cacheEntry)
	}
	now := c.now()
	for cachedKey, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, cachedKey)
		}
	}
	if c.capacity > 0 && len(c.entries) >= c.capacity {
		// Everything live in here is a live account's answer, and this one is
		// the newest; starting over costs one probe per credential rather than
		// evicting a still-needed catalogue.
		c.entries = make(map[string]cacheEntry)
	}
	c.entries[key] = cacheEntry{models: cloneModels(models), expiresAt: now.Add(c.ttl)}
}

// Drop forgets key. It is what a logged-out credential needs: serving the
// previous answer would advertise models to an account that can no longer use
// them.
func (c *Cache) Drop(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func cloneModels(models []Model) []Model {
	out := make([]Model, len(models))
	for i, model := range models {
		model.InputModalities = append([]string(nil), model.InputModalities...)
		model.OutputModalities = append([]string(nil), model.OutputModalities...)
		out[i] = model
	}
	return out
}

// Resolver turns "ask the platform" into "report a catalogue", with the failure
// policy that keeps a bad answer from being worse than no answer:
//
//   - a cached answer is served until it expires;
//   - a successful probe replaces it;
//   - a transient failure keeps the previous answer and reports the error, so
//     the caller can log it once and still publish something true;
//   - a LoggedOut failure drops the previous answer, because that one is now
//     false.
type Resolver struct {
	Cache *Cache
	// Fetch asks the platform for key. Returning a LoggedOut error means the
	// credential itself is dead, not the probe.
	Fetch func(ctx context.Context, key string) ([]Model, error)
	// Logf, when set, receives one line per failure per LogInterval. A probe
	// that fails for every account must not fill the log with one line each.
	Logf func(format string, args ...any)
	// LogInterval bounds how often the same key logs. Zero means a minute.
	LogInterval time.Duration

	mu       sync.Mutex
	lastLog  map[string]time.Time
	lastGood map[string][]Model
}

// Resolve returns the catalogue for key, asking the platform when the cache has
// nothing fresh.
//
// A non-nil error means "no catalogue could be produced for this credential".
// When a previous answer exists it is returned alongside the error, so a caller
// that has a static fallback can still choose the better of the two.
func (r *Resolver) Resolve(ctx context.Context, key string) ([]Model, error) {
	if models, okCache := r.Cache.Get(key); okCache {
		r.remember(key, models)
		return models, nil
	}
	models, errFetch := r.Fetch(ctx, key)
	switch {
	case errFetch == nil && len(models) == 0:
		// The platform answered and named nothing. That is a real answer about
		// this credential, but it is indistinguishable from a broken probe at
		// the call site, so it is reported and the previous answer is dropped.
		r.Cache.Drop(key)
		r.forget(key)
		r.logf(key, "no models were returned for this credential")
		return nil, nil
	case errFetch != nil:
		if IsLoggedOut(errFetch) {
			r.Cache.Drop(key)
			r.forget(key)
			r.logf(key, "credential is no longer logged in: %v", errFetch)
			return nil, errFetch
		}
		r.logf(key, "catalogue probe failed: %v", errFetch)
		if previous, okPrevious := r.previous(key); okPrevious {
			return previous, errFetch
		}
		return nil, errFetch
	}
	r.Cache.Put(key, models)
	r.remember(key, models)
	return models, nil
}

func (r *Resolver) previous(key string) ([]Model, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	models, okPrevious := r.lastGood[key]
	if !okPrevious || len(models) == 0 {
		return nil, false
	}
	return cloneModels(models), true
}

func (r *Resolver) remember(key string, models []Model) {
	if len(models) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastGood == nil {
		r.lastGood = make(map[string][]Model)
	}
	r.lastGood[key] = cloneModels(models)
}

func (r *Resolver) forget(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.lastGood, key)
}

func (r *Resolver) logf(key, format string, args ...any) {
	if r.Logf == nil {
		return
	}
	interval := r.LogInterval
	if interval <= 0 {
		interval = time.Minute
	}
	now := time.Now()
	r.mu.Lock()
	if r.lastLog == nil {
		r.lastLog = make(map[string]time.Time)
	}
	if last, seen := r.lastLog[key]; seen && now.Sub(last) < interval {
		r.mu.Unlock()
		return
	}
	if len(r.lastLog) > 4*len(r.lastGood)+64 {
		r.lastLog = make(map[string]time.Time)
	}
	r.lastLog[key] = now
	r.mu.Unlock()
	r.Logf(format, args...)
}

// loggedOutError marks an error as a dead credential rather than a failed probe.
type loggedOutError struct {
	err error
}

func (e *loggedOutError) Error() string { return e.err.Error() }

func (e *loggedOutError) Unwrap() error { return e.err }

// LoggedOut marks err as "this credential is no longer usable". It keeps the
// original message and error chain, so a caller can still inspect the platform's
// own code or status.
func LoggedOut(err error) error {
	if err == nil || IsLoggedOut(err) {
		return err
	}
	return &loggedOutError{err: err}
}

// IsLoggedOut reports whether err was marked with LoggedOut.
func IsLoggedOut(err error) bool {
	var marked *loggedOutError
	return errors.As(err, &marked)
}

// ErrNoCredential is the error a Fetch function returns when the credential
// carries nothing to authenticate with. It is a LoggedOut error: without a
// credential there is nothing to ask about.
var ErrNoCredential = LoggedOut(fmt.Errorf("the credential carries no session"))
