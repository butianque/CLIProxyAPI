package phone

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
)

// fakeJoiner is a marketplace whose joined set starts empty and grows as the
// service joins channels, so the auto-join path can be tested deterministically.
type fakeJoiner struct {
	fakeProvider
	project   ProjectRef
	all       []Quote
	joined    map[string]bool
	paused    map[string]bool
	joinCalls [][]string
	joinErr   error
	openCalls []openCall
	openErr   error
}

// openCall records one SetChannelOpen invocation.
type openCall struct {
	action string
	uids   []string
}

func newFakeJoiner(all []Quote) *fakeJoiner {
	return &fakeJoiner{
		fakeProvider: fakeProvider{phone: "13900000000"},
		project:      ProjectRef{Name: "【21614】讯飞", ID: "21614", Hash: "hash21614"},
		all:          all,
		joined:       map[string]bool{},
		paused:       map[string]bool{},
	}
}

func (f *fakeJoiner) FindProject(_ context.Context, projectID, keyword string) (ProjectRef, error) {
	if keyword != "" && !strings.Contains(f.project.Name, keyword) {
		return ProjectRef{}, errors.New("no such project")
	}
	return f.project, nil
}

func (f *fakeJoiner) AllChannels(context.Context, string) ([]Quote, error) {
	out := append([]Quote(nil), f.all...)
	SortQuotes(out)
	return out, nil
}

func (f *fakeJoiner) JoinChannels(_ context.Context, uids []string) ([]string, error) {
	if f.joinErr != nil {
		return nil, f.joinErr
	}
	f.joinCalls = append(f.joinCalls, append([]string(nil), uids...))
	for _, uid := range uids {
		f.joined[uid] = true
	}
	return uids, nil
}

func (f *fakeJoiner) Channels(context.Context) ([]Quote, error) {
	out := make([]Quote, 0, len(f.all))
	for _, quote := range f.all {
		if f.joined[quote.UID] {
			quote.Paused = f.paused[quote.UID]
			out = append(out, quote)
		}
	}
	SortQuotes(out)
	return out, nil
}

// SetChannelOpen flips the fake's per-channel switch, so the guardrail's effect
// on the platform's enabled set is observable.
func (f *fakeJoiner) SetChannelOpen(_ context.Context, action string, uids []string) ([]string, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	f.openCalls = append(f.openCalls, openCall{action: action, uids: append([]string(nil), uids...)})
	for _, uid := range uids {
		if action == "recover" {
			f.paused[uid] = false
		} else {
			f.paused[uid] = true
		}
	}
	return uids, nil
}

// Nothing joined: the service must join every affordable channel before it can
// rent, and only the affordable ones.
func TestEnsureChannelsJoinsAffordableOnly(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 4},
		{UID: "21614-mid", Price: 0.33, Stock: 10},
		{UID: "21614-over", Price: 0.88, Stock: 50},
		{UID: "58562-other", Price: 0.18, Stock: 100},
	})
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})
	// newTestService seeded a cache; clear it so the join path is exercised.
	service.ReplaceChannels("21614", nil, 1)

	count, errEnsure := service.EnsureChannels(context.Background(), "21614", "讯飞")
	if errEnsure != nil {
		t.Fatalf("EnsureChannels: %v", errEnsure)
	}
	if count != 2 {
		t.Fatalf("channel count = %d, want the two affordable 讯飞 channels", count)
	}
	var joined []string
	for uid := range joiner.joined {
		joined = append(joined, uid)
	}
	sort.Strings(joined)
	want := []string{"21614-cheap", "21614-mid"}
	if len(joined) != len(want) {
		t.Fatalf("joined = %v, want %v", joined, want)
	}
	for i := range want {
		if joined[i] != want[i] {
			t.Fatalf("joined = %v, want %v", joined, want)
		}
	}

	// The cache must hold the affordable channels, cheapest first.
	cheapest := service.Channels().Cheapest(0)
	if len(cheapest) != 2 || cheapest[0].UID != "21614-cheap" {
		t.Fatalf("cache = %+v, want the affordable channels cheapest first", cheapest)
	}
}

// Acquire joins on demand when nothing is cached, then rents the cheapest.
func TestAcquireJoinsWhenEmpty(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-mid", Price: 0.33, Stock: 5},
		{UID: "21614-cheap", Price: 0.13, Stock: 2},
	})
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})
	service.ReplaceChannels("21614", nil, 1)

	number, entry, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Code != "21614-cheap" {
		t.Fatalf("rented %q, want the cheapest joined channel", number.Code)
	}
	if entry.Price != 0.13 {
		t.Fatalf("price = %v, want 0.13", entry.Price)
	}
	if len(joiner.joinCalls) == 0 {
		t.Fatalf("expected the service to join channels before renting")
	}
}

// A join failure is not fatal to Acquire when a cached channel can still serve.
func TestAcquireUsesCacheWhenJoinFails(t *testing.T) {
	joiner := newFakeJoiner([]Quote{{UID: "21614-cached", Price: 0.2, Stock: 3}})
	joiner.joinErr = errors.New("web session expired")
	service := newTestService(t, joiner, []Quote{{UID: "21614-cached", Price: 0.2, Stock: 3}}, Budget{})

	number, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Code != "21614-cached" {
		t.Fatalf("rented %q, want the cached channel", number.Code)
	}
}

// A pinned channel bypasses the join path entirely.
func TestAcquirePinnedSkipsJoin(t *testing.T) {
	joiner := newFakeJoiner(nil)
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})
	service.ReplaceChannels("21614", nil, 1)

	number, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614", Code: "21614-pinned"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Code != "21614-pinned" {
		t.Fatalf("rented %q, want the pinned channel", number.Code)
	}
	if len(joiner.joinCalls) != 0 {
		t.Fatalf("a pinned rental must not trigger a join: %v", joiner.joinCalls)
	}
}

// The guardrail must switch off every joined channel above the ceiling or out of
// stock, and switch back on every affordable in-stock one, so a blind rental can
// only land on a cheap channel.
func TestGuardChannelsPausesExpensiveAndOutOfStock(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 5},
		{UID: "21614-mid", Price: 0.33, Stock: 8},
		{UID: "21614-over", Price: 0.55, Stock: 50},
		{UID: "21614-empty", Price: 0.18, Stock: 0},
	})
	// Everything starts joined and enabled.
	for _, quote := range joiner.all {
		joiner.joined[quote.UID] = true
	}
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})

	if _, errGuard := service.GuardChannels(context.Background(), "21614"); errGuard != nil {
		t.Fatalf("GuardChannels: %v", errGuard)
	}

	if !joiner.paused["21614-over"] {
		t.Fatalf("channel above the ceiling was not paused: %+v", joiner.paused)
	}
	if !joiner.paused["21614-empty"] {
		t.Fatalf("out-of-stock channel was not paused: %+v", joiner.paused)
	}
	if joiner.paused["21614-cheap"] || joiner.paused["21614-mid"] {
		t.Fatalf("affordable in-stock channels must stay enabled: %+v", joiner.paused)
	}

	// The cache must reflect it: only the two affordable in-stock channels are
	// selectable.
	usable := service.Channels().Cheapest(0)
	if len(usable) != 2 || usable[0].UID != "21614-cheap" || usable[1].UID != "21614-mid" {
		t.Fatalf("usable channels = %+v, want only the two affordable in-stock ones", usable)
	}
}

// The guardrail must never switch off the cheapest in-stock channel, so a pass
// cannot leave the account with nothing to rent from.
func TestGuardChannelsKeepsCheapestUsable(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-only", Price: 0.55, Stock: 3},
		{UID: "21614-empty", Price: 0.18, Stock: 0},
	})
	for _, quote := range joiner.all {
		joiner.joined[quote.UID] = true
	}
	// A ceiling below every priced channel: without the keep rule the account
	// would be left with nothing enabled.
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})

	if _, errGuard := service.GuardChannels(context.Background(), "21614"); errGuard != nil {
		t.Fatalf("GuardChannels: %v", errGuard)
	}
	if joiner.paused["21614-only"] {
		t.Fatalf("the only in-stock channel was paused, leaving nothing to rent from")
	}
	// The out-of-stock channel is still paused; it has no numbers anyway.
	if !joiner.paused["21614-empty"] {
		t.Fatalf("an out-of-stock channel should still be paused: %+v", joiner.paused)
	}
}

// A channel the guardrail earlier switched off, and which now has stock, must be
// switched back on.
func TestGuardChannelsRecoversAffordable(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 5},
		{UID: "21614-refilled", Price: 0.18, Stock: 4},
	})
	for _, quote := range joiner.all {
		joiner.joined[quote.UID] = true
	}
	joiner.paused["21614-refilled"] = true
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})

	if _, errGuard := service.GuardChannels(context.Background(), "21614"); errGuard != nil {
		t.Fatalf("GuardChannels: %v", errGuard)
	}
	if joiner.paused["21614-refilled"] {
		t.Fatalf("a refilled affordable channel was not recovered: %+v", joiner.paused)
	}
}

// The guardrail route builds a service and calls GuardChannels directly, so a
// pass can be the first use of a fresh service whose on-disk documents have not
// been loaded yet. The cache must be loaded internally rather than dereferenced
// while nil, which used to panic and abort the request.
func TestGuardChannelsOnFreshServiceLoadsState(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 5},
		{UID: "21614-over", Price: 0.55, Stock: 5},
	})
	for _, quote := range joiner.all {
		joiner.joined[quote.UID] = true
	}
	// Deliberately no newTestService: the cache is not pre-seeded or loaded.
	service := NewService(joiner, Store{Dir: t.TempDir()}, Budget{MaxPerNumberCNY: 0.5})

	if _, errGuard := service.GuardChannels(context.Background(), "21614"); errGuard != nil {
		t.Fatalf("GuardChannels on a fresh service: %v", errGuard)
	}
	if !joiner.paused["21614-over"] {
		t.Fatalf("channel above the ceiling was not paused: %+v", joiner.paused)
	}
	if service.Channels() == nil {
		t.Fatalf("the cache was not loaded")
	}
}
