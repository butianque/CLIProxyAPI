package plugincatalog

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// A catalogue cached for one credential must never be handed to another: two
// accounts on the same platform can be entitled to different models.
func TestCacheKeepsCredentialsApart(t *testing.T) {
	cache := NewCache(time.Minute, 0)
	cache.Put("account-a", []Model{{ID: "model-a"}})
	cache.Put("account-b", []Model{{ID: "model-b"}})

	a, okA := cache.Get("account-a")
	if !okA || len(a) != 1 || a[0].ID != "model-a" {
		t.Fatalf("account-a = %v, %v", a, okA)
	}
	b, okB := cache.Get("account-b")
	if !okB || len(b) != 1 || b[0].ID != "model-b" {
		t.Fatalf("account-b = %v, %v", b, okB)
	}
}

// The caller gets a copy, so a mutation cannot corrupt what the cache will serve
// to the next caller.
func TestCacheHandsOutCopies(t *testing.T) {
	cache := NewCache(time.Minute, 0)
	cache.Put("account", []Model{{ID: "model", InputModalities: []string{"text"}}})

	first, _ := cache.Get("account")
	first[0].ID = "mutated"
	first[0].InputModalities[0] = "audio"

	second, _ := cache.Get("account")
	if second[0].ID != "model" || second[0].InputModalities[0] != "text" {
		t.Fatalf("cache served a mutated entry: %+v", second[0])
	}
}

func TestCacheExpiresAndDrops(t *testing.T) {
	cache := NewCache(time.Minute, 0)
	now := time.Unix(1_800_000_000, 0)
	cache.now = func() time.Time { return now }
	cache.Put("account", []Model{{ID: "model"}})
	if _, okCache := cache.Get("account"); !okCache {
		t.Fatal("a fresh entry must be served")
	}
	now = now.Add(2 * time.Minute)
	if _, okCache := cache.Get("account"); okCache {
		t.Fatal("an expired entry must not be served")
	}

	cache.Put("account", []Model{{ID: "model"}})
	cache.Drop("account")
	if _, okCache := cache.Get("account"); okCache {
		t.Fatal("a dropped entry must not be served")
	}
}

// Without a lifetime there is no cache at all: a plugin that configures zero
// must not silently serve stale answers.
func TestCacheWithNoTTLCachesNothing(t *testing.T) {
	cache := NewCache(0, 0)
	cache.Put("account", []Model{{ID: "model"}})
	if _, okCache := cache.Get("account"); okCache {
		t.Fatal("a zero ttl must not cache")
	}
}

func TestInfosDefaultsAndDeduplicates(t *testing.T) {
	infos := Infos("plugin", []Model{
		{ID: " chat-model ", Name: "Chat Model", ContextLength: 1000, MaxOutputTokens: 100},
		{ID: "chat-model"},
		{ID: "   "},
		{ID: "image-model", Type: "image", OutputModalities: []string{"image"}},
		{ID: "no-modalities"},
	})
	if len(infos) != 3 {
		t.Fatalf("infos = %d, want 3: %+v", len(infos), infos)
	}
	chat := infos[0]
	if chat.ID != "chat-model" || chat.DisplayName != "Chat Model" || chat.Type != "chat" {
		t.Errorf("chat entry = %+v", chat)
	}
	if chat.ContextLength != 1000 || chat.MaxCompletionTokens != 100 {
		t.Errorf("chat limits = %d/%d", chat.ContextLength, chat.MaxCompletionTokens)
	}
	if got := strings.Join(chat.SupportedOutputModalities, ","); got != "text" {
		t.Errorf("chat output modalities = %q", got)
	}
	image := infos[1]
	if image.Type != "image" || image.DisplayName != "image-model" {
		t.Errorf("image entry = %+v", image)
	}
	if got := strings.Join(image.SupportedOutputModalities, ","); got != "image" {
		t.Errorf("image output modalities = %q", got)
	}
	// An entry with no limits keeps zero, rather than borrowing another model's.
	if infos[2].ContextLength != 0 || infos[2].MaxCompletionTokens != 0 {
		t.Errorf("sparse entry = %+v, want zero limits", infos[2])
	}
}

// A transient failure must not take an account out of service: the previous
// catalogue is still the best answer available.
func TestResolverKeepsTheLastGoodCatalogueOnFailure(t *testing.T) {
	fresh := true
	resolver := &Resolver{
		Cache: NewCache(time.Minute, 0),
		Fetch: func(context.Context, string) ([]Model, error) {
			if fresh {
				return []Model{{ID: "model"}}, nil
			}
			return nil, errors.New("upstream timeout")
		},
	}
	models, errResolve := resolver.Resolve(context.Background(), "account")
	if errResolve != nil || len(models) != 1 {
		t.Fatalf("first resolve = %v, %v", models, errResolve)
	}
	// Expire the cache so the next call really probes again.
	resolver.Cache.now = func() time.Time { return time.Now().Add(time.Hour) }
	fresh = false
	models, errResolve = resolver.Resolve(context.Background(), "account")
	if errResolve == nil {
		t.Fatal("a failed probe must be reported")
	}
	if len(models) != 1 || models[0].ID != "model" {
		t.Fatalf("previous catalogue = %v, want the last good one", models)
	}
}

// A dead credential is different: the previous answer is now false, so it must
// not be served again.
func TestResolverForgetsTheCatalogueWhenLoggedOut(t *testing.T) {
	resolver := &Resolver{
		Cache: NewCache(time.Minute, 0),
		Fetch: func(context.Context, string) ([]Model, error) {
			return []Model{{ID: "model"}}, nil
		},
	}
	if _, errResolve := resolver.Resolve(context.Background(), "account"); errResolve != nil {
		t.Fatalf("first resolve: %v", errResolve)
	}
	resolver.Fetch = func(context.Context, string) ([]Model, error) {
		return nil, LoggedOut(errors.New("session expired"))
	}
	resolver.Cache.now = func() time.Time { return time.Now().Add(time.Hour) }
	models, errResolve := resolver.Resolve(context.Background(), "account")
	if !IsLoggedOut(errResolve) {
		t.Fatalf("error = %v, want a logged-out error", errResolve)
	}
	if len(models) != 0 {
		t.Fatalf("models = %v, want none for a dead credential", models)
	}
	if _, okCache := resolver.Cache.Get("account"); okCache {
		t.Fatal("the dead credential's catalogue must be dropped from the cache")
	}
}

// An empty answer is a real answer: it must not be cached as if it were, and it
// must not be reported as a failure the caller should retry against a static
// list.
func TestResolverReportsAnEmptyAnswerWithoutCachingIt(t *testing.T) {
	calls := 0
	resolver := &Resolver{
		Cache: NewCache(time.Minute, 0),
		Fetch: func(context.Context, string) ([]Model, error) {
			calls++
			return nil, nil
		},
	}
	models, errResolve := resolver.Resolve(context.Background(), "account")
	if errResolve != nil || len(models) != 0 {
		t.Fatalf("resolve = %v, %v", models, errResolve)
	}
	if _, errResolve := resolver.Resolve(context.Background(), "account"); errResolve != nil {
		t.Fatalf("second resolve: %v", errResolve)
	}
	if calls != 2 {
		t.Fatalf("fetch calls = %d, want 2: an empty answer must not be cached", calls)
	}
}

// One line per credential per interval: a probe that fails for every account
// must not turn into one log line per account per pass.
func TestResolverThrottlesRepeatedFailures(t *testing.T) {
	var mu sync.Mutex
	logged := 0
	resolver := &Resolver{
		Cache: &Cache{},
		Fetch: func(context.Context, string) ([]Model, error) {
			return nil, errors.New("boom")
		},
		Logf: func(string, ...any) {
			mu.Lock()
			logged++
			mu.Unlock()
		},
		LogInterval: time.Hour,
	}
	for range 5 {
		if _, errResolve := resolver.Resolve(context.Background(), "account"); errResolve == nil {
			t.Fatal("want the failure reported")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if logged != 1 {
		t.Fatalf("logged %d lines, want 1 inside one interval", logged)
	}
}

func TestLoggedOutMarkerKeepsTheChain(t *testing.T) {
	original := fmt.Errorf("business code 100002: %w", errors.New("缺少 token"))
	marked := LoggedOut(original)
	if !IsLoggedOut(marked) {
		t.Fatal("a marked error must report as logged out")
	}
	if marked.Error() != original.Error() {
		t.Errorf("message = %q, want %q", marked.Error(), original.Error())
	}
	if !errors.Is(marked, original) && !errors.Is(errors.Unwrap(marked), original) {
		t.Errorf("marked error lost its cause: %v", errors.Unwrap(marked))
	}
	if IsLoggedOut(errors.New("timeout")) {
		t.Fatal("an unmarked error must not report as logged out")
	}
	if LoggedOut(marked) != marked {
		t.Fatal("marking twice must be idempotent")
	}
	if !IsLoggedOut(ErrNoCredential) {
		t.Fatal("a credential with no session is logged out")
	}
}
