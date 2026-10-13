package phone

import (
	"context"
	"testing"
)

// An untried channel must carry no reliability penalty, so a cheap unknown is
// still explored rather than being starved by a channel that merely has history.
func TestStrategyLeavesUntriedChannelUnpenalised(t *testing.T) {
	strategy := DefaultStrategy()
	quote := Quote{UID: "21614-new", Price: 0.2, Stock: 5}

	score := strategy.Score(quote, ChannelStat{}, false)
	if want := strategy.PriceWeight * 0.2; score != want {
		t.Fatalf("score = %v, want %v (price only)", score, want)
	}
}

// A channel with a run of failures must score worse than an identically priced
// channel with none, which is what makes the next rental prefer the healthy one.
func TestStrategyDemotesFailingChannel(t *testing.T) {
	strategy := DefaultStrategy()
	healthy := Quote{UID: "21614-ok", Price: 0.2, Stock: 5}
	failing := Quote{UID: "21614-bad", Price: 0.2, Stock: 5}
	badStat := ChannelStat{Timeouts: 2, Delivered: 1, ConsecutiveFails: 2}

	if strategy.Score(failing, badStat, false) <= strategy.Score(healthy, ChannelStat{}, false) {
		t.Fatalf("a channel with consecutive failures must score worse than a healthy one")
	}
}

// A cheap but chronically failing channel must yield to a slightly dearer one
// that delivers: reliability is allowed to cost money, which is the stated
// preference.
func TestRankPrefersReliableOverCheapest(t *testing.T) {
	strategy := DefaultStrategy()
	health := NewChannelHealth()
	health.Record("21614-cheap", OutcomeTimeout, 0.13, 1)
	health.Record("21614-cheap", OutcomeTimeout, 0.13, 2)
	health.Record("21614-cheap", OutcomeTimeout, 0.13, 3)
	health.Record("21614-solid", OutcomeDelivered, 0.30, 4)

	ranked := strategy.Rank([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 5},
		{UID: "21614-solid", Price: 0.30, Stock: 5},
	}, health, nil)

	if ranked[0].UID != "21614-solid" {
		t.Fatalf("ranked first = %q, want the channel that delivers", ranked[0].UID)
	}
}

// A just-failed channel must be pushed behind the rest for one attempt, so a
// retry does not land on the same channel that just timed out.
func TestRankDefersCoolingChannel(t *testing.T) {
	strategy := DefaultStrategy()
	ranked := strategy.Rank([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 5},
		{UID: "21614-next", Price: 0.30, Stock: 5},
	}, NewChannelHealth(), map[string]bool{"21614-cheap": true})

	if ranked[0].UID != "21614-next" {
		t.Fatalf("ranked first = %q, want the channel that is not cooling", ranked[0].UID)
	}
}

// A delivery must clear the failure run, so a channel that recovers is not
// punished forever.
func TestHealthRecordDeliveryClearsFailureRun(t *testing.T) {
	health := NewChannelHealth()
	health.Record("21614-x", OutcomeTimeout, 0.13, 1)
	health.Record("21614-x", OutcomeTimeout, 0.13, 2)

	health.Record("21614-x", OutcomeDelivered, 0.13, 3)

	stat, _ := health.Stat("21614-x")
	if stat.ConsecutiveFails != 0 {
		t.Fatalf("consecutive fails = %d, want 0 after a delivery", stat.ConsecutiveFails)
	}
	if stat.Delivered != 1 || stat.Timeouts != 2 {
		t.Fatalf("delivered/timeouts = %d/%d, want 1/2", stat.Delivered, stat.Timeouts)
	}
}

// A release carries no verdict, so it must not count against a channel's
// success rate — otherwise a cancelled rental would look like a failure.
func TestHealthRecordReleasedIsNotAVerdict(t *testing.T) {
	health := NewChannelHealth()
	health.Record("21614-x", OutcomeReleased, 0.13, 1)

	stat, _ := health.Stat("21614-x")
	if stat.Verdicts() != 0 {
		t.Fatalf("verdicts = %d, want 0 for a released rental", stat.Verdicts())
	}
	if stat.SuccessRate() != 1 {
		t.Fatalf("success rate = %v, want 1 with no verdicts", stat.SuccessRate())
	}
}

// Acquire must remember which channel produced the number, so a later timeout
// can be counted against that channel.
func TestAcquireRecordsAttemptAgainstChannel(t *testing.T) {
	provider := &fakeProvider{phone: "13800000123"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 4},
	}, Budget{})

	if _, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"}); errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}

	stat, ok := service.Health().Stat("21614-cheap")
	if !ok || stat.Attempts != 1 {
		t.Fatalf("channel stat = %+v, ok=%v, want one attempt", stat, ok)
	}
}

// A timeout must be counted against the channel that produced the number, and it
// must put that channel into cool-down so the next attempt tries another one.
func TestReleaseUnusedTimeoutCountsAgainstChannel(t *testing.T) {
	provider := &fakeProvider{phone: "13800000456"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 4},
	}, Budget{})
	service.CoolDownSeconds = 300

	number, entry, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if errRelease := service.ReleaseUnused(context.Background(), Project{SID: "21614"}, number.Phone, entry.Price, OutcomeTimeout); errRelease != nil {
		t.Fatalf("ReleaseUnused: %v", errRelease)
	}

	stat, _ := service.Health().Stat("21614-cheap")
	if stat.Timeouts != 1 || stat.ConsecutiveFails != 1 {
		t.Fatalf("stat = %+v, want one timeout and a failure run of 1", stat)
	}
	if !service.cooldown.Active(nowUnix())["21614-cheap"] {
		t.Fatalf("a timed-out channel should be cooling")
	}
}

// The reliability pause must never strand a number already used for an account:
// the platform refuses to re-issue a number whose channel is paused, so such a
// channel is demoted but left enabled.
func TestSuspendUnreliableProtectsLedgerChannel(t *testing.T) {
	joiner := newFakeJoiner([]Quote{{UID: "21614-used", Price: 0.13, Stock: 4}})
	joiner.joined["21614-used"] = true
	service := newTestService(t, joiner, nil, Budget{})

	// Rent once, so the ledger holds a number attributed to this channel.
	if _, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"}); errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}

	paused, errSuspend := service.SuspendUnreliable(context.Background(), "21614-used")
	if errSuspend != nil {
		t.Fatalf("SuspendUnreliable: %v", errSuspend)
	}
	if paused {
		t.Fatalf("a channel holding a ledger number must not be paused")
	}
	if joiner.paused["21614-used"] {
		t.Fatalf("the channel reached the platform: %+v", joiner.paused)
	}
}

// A channel with no number in the ledger is safe to pause once it has failed too
// often.
func TestSuspendUnreliablePausesCleanChannel(t *testing.T) {
	joiner := newFakeJoiner([]Quote{{UID: "21614-bad", Price: 0.13, Stock: 4}})
	joiner.joined["21614-bad"] = true
	service := newTestService(t, joiner, nil, Budget{})

	paused, errSuspend := service.SuspendUnreliable(context.Background(), "21614-bad")
	if errSuspend != nil {
		t.Fatalf("SuspendUnreliable: %v", errSuspend)
	}
	if !paused || !joiner.paused["21614-bad"] {
		t.Fatalf("a clean unreliable channel should be paused: paused=%v platform=%v", paused, joiner.paused)
	}
	stat, _ := service.Health().Stat("21614-bad")
	if !stat.PausedByUs {
		t.Fatalf("the pause was not recorded as ours: %+v", stat)
	}
}

// The guardrail must not silently undo a reliability pause: a channel this
// plugin paused for unreliability stays paused even when it is affordable and in
// stock, otherwise the two policies fight over the same channel on every pass.
func TestGuardChannelsRespectsReliabilityPause(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 5},
		{UID: "21614-flaky", Price: 0.18, Stock: 5},
	})
	for _, quote := range joiner.all {
		joiner.joined[quote.UID] = true
	}
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})

	// Record the failures that would have triggered the pause, then pause it.
	for range service.PauseThreshold() {
		service.Health().Record("21614-flaky", OutcomeTimeout, 0.18, 1)
	}
	if _, errSuspend := service.SuspendUnreliable(context.Background(), "21614-flaky"); errSuspend != nil {
		t.Fatalf("SuspendUnreliable: %v", errSuspend)
	}

	if _, errGuard := service.GuardChannels(context.Background(), "21614"); errGuard != nil {
		t.Fatalf("GuardChannels: %v", errGuard)
	}
	if !joiner.paused["21614-flaky"] {
		t.Fatalf("the guardrail undid a reliability pause: %+v", joiner.paused)
	}
	if joiner.paused["21614-cheap"] {
		t.Fatalf("the healthy channel should stay enabled: %+v", joiner.paused)
	}
}

// Once a channel we paused for unreliability delivers again, the guardrail must
// release it back to the normal rules, so a recovered channel is not stranded.
func TestGuardChannelsReleasesRecoveredReliabilityPause(t *testing.T) {
	joiner := newFakeJoiner([]Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 5},
		{UID: "21614-flaky", Price: 0.18, Stock: 5},
	})
	for _, quote := range joiner.all {
		joiner.joined[quote.UID] = true
	}
	service := newTestService(t, joiner, nil, Budget{MaxPerNumberCNY: 0.5})

	if _, errSuspend := service.SuspendUnreliable(context.Background(), "21614-flaky"); errSuspend != nil {
		t.Fatalf("SuspendUnreliable: %v", errSuspend)
	}
	// A delivery since the pause proves the channel works again.
	service.RecordDelivery("21614-flaky", 0.18)

	if _, errGuard := service.GuardChannels(context.Background(), "21614"); errGuard != nil {
		t.Fatalf("GuardChannels: %v", errGuard)
	}
	if joiner.paused["21614-flaky"] {
		t.Fatalf("a recovered channel should be released back to the guardrail: %+v", joiner.paused)
	}
	stat, _ := service.Health().Stat("21614-flaky")
	if stat.PausedByUs {
		t.Fatalf("the reliability pause flag should be cleared: %+v", stat)
	}
}
