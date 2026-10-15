package phone

// This file adds the reliability half of channel selection: a local record of
// how each channel has actually behaved, and a score that blends that record
// with the channel's price.
//
// The platform does not publish a delivery success rate, and it never will: the
// only trustworthy signal is what happened when this account rented from a
// channel and waited for a message. So the outcome of every rental is recorded
// here and folded into the next choice, which is what turns "cheapest first"
// into "cheapest that still works".
//
// The record is a companion to the phone pool, not a replacement: the pool
// remembers which number belongs to which account, while this remembers which
// channel deserves the next attempt.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// ChannelOutcome is what happened to one rental.
type ChannelOutcome int

const (
	// OutcomeDelivered: a message arrived within the deadline. The strongest
	// possible signal that the channel works.
	OutcomeDelivered ChannelOutcome = iota
	// OutcomeTimeout: no message arrived before the deadline. The channel was
	// reached and a number was issued, so this is a real failure of the channel.
	OutcomeTimeout
	// OutcomeReleased: the rental was handed back without a verdict — the
	// message was never sent, or the operator cancelled. It says nothing about
	// the channel, so it must not count against it.
	OutcomeReleased
)

// String names the outcome. It is used where the outcome is recorded outside the
// health store, such as the pool, so the value stays readable there.
func (o ChannelOutcome) String() string {
	switch o {
	case OutcomeDelivered:
		return "delivered"
	case OutcomeTimeout:
		return "timeout"
	case OutcomeReleased:
		return "released"
	default:
		return "unknown"
	}
}

// ChannelStat is the running record for one channel.
type ChannelStat struct {
	// UID is the channel (对接码), the key this record is stored under.
	UID string `json:"uid"`
	// Price is the most recent unit price seen for this channel. It is kept so a
	// score can be computed even when the channel has dropped out of the live
	// cache, and so a price change is visible in the record.
	Price float64 `json:"price,omitempty"`
	// Attempts is how many times a number was actually rented from this channel.
	Attempts int `json:"attempts,omitempty"`
	// Delivered and Timeouts are the two verdicts that describe reliability.
	Delivered int `json:"delivered,omitempty"`
	Timeouts  int `json:"timeouts,omitempty"`
	// Released counts rentals that produced no verdict and are excluded from the
	// success rate.
	Released int `json:"released,omitempty"`
	// BlockedByPause counts re-acquire attempts that failed only because this
	// channel was paused, which is our own doing, not the channel's fault.
	BlockedByPause int `json:"blocked_by_pause,omitempty"`
	// ConsecutiveFails is the current run of failures with no success between
	// them. It resets to zero on a delivery, and it is the primary signal for
	// "this channel has stopped working".
	ConsecutiveFails int   `json:"consecutive_fails,omitempty"`
	LastFailAt       int64 `json:"last_fail_at,omitempty"`
	LastSuccessAt    int64 `json:"last_success_at,omitempty"`
	// PausedByUs records that the reliability policy, not the operator, paused
	// this channel upstream, so a later pass knows it may recover it.
	PausedByUs bool `json:"paused_by_us,omitempty"`
}

// Verdicts is the number of rentals that reached a verdict.
func (s ChannelStat) Verdicts() int { return s.Delivered + s.Timeouts }

// SuccessRate is the fraction of verdicts that were deliveries. With no
// verdicts it reports 1, so an untried channel is never pre-judged.
func (s ChannelStat) SuccessRate() float64 {
	if s.Verdicts() == 0 {
		return 1
	}
	return float64(s.Delivered) / float64(s.Verdicts())
}

// ChannelHealth is the store of per-channel records, persisted beside the
// channel cache and the phone pool.
type ChannelHealth struct {
	Version int                     `json:"version"`
	Stats   map[string]*ChannelStat `json:"stats,omitempty"`
}

// channelHealthVersion is the on-disk schema version.
const channelHealthVersion = 1

// NewChannelHealth returns an empty health store.
func NewChannelHealth() *ChannelHealth {
	return &ChannelHealth{Version: channelHealthVersion, Stats: map[string]*ChannelStat{}}
}

// get returns the record for one channel, creating it if needed. The caller must
// hold the service lock when the returned value will be mutated.
func (h *ChannelHealth) get(uid string) *ChannelStat {
	uid = strings.TrimSpace(uid)
	if h.Stats == nil {
		h.Stats = map[string]*ChannelStat{}
	}
	stat, ok := h.Stats[uid]
	if !ok || stat == nil {
		stat = &ChannelStat{UID: uid}
		h.Stats[uid] = stat
	}
	return stat
}

// Stat returns a copy of one channel's record.
func (h *ChannelHealth) Stat(uid string) (ChannelStat, bool) {
	if h.Stats == nil {
		return ChannelStat{}, false
	}
	stat, ok := h.Stats[strings.TrimSpace(uid)]
	if !ok || stat == nil {
		return ChannelStat{}, false
	}
	return *stat, true
}

// Record folds one outcome into a channel's record.
//
// A delivery resets the failure run, which is what stops a channel that had a
// bad spell from being punished forever. Price is refreshed whenever a
// non-negative value is supplied.
func (h *ChannelHealth) Record(uid string, outcome ChannelOutcome, price float64, now int64) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return
	}
	stat := h.get(uid)
	if price > 0 {
		stat.Price = price
	}
	switch outcome {
	case OutcomeDelivered:
		stat.Delivered++
		stat.ConsecutiveFails = 0
		stat.LastSuccessAt = now
	case OutcomeTimeout:
		stat.Timeouts++
		stat.ConsecutiveFails++
		stat.LastFailAt = now
	case OutcomeReleased:
		stat.Released++
	}
}

// MarkBlocked notes that a re-acquire failed only because the channel was
// paused. It is kept separate from timeouts so the channel's own reliability is
// not blamed for a decision this plugin made.
func (h *ChannelHealth) MarkBlocked(uid string, now int64) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return
	}
	stat := h.get(uid)
	stat.BlockedByPause++
	stat.LastFailAt = now
}

// -- scoring -----------------------------------------------------------------

// Strategy holds the tunables that turn a channel's price and record into a
// single ordering. Zero values fall back to the documented defaults, so a
// caller can leave the struct empty and get the intended behaviour.
type Strategy struct {
	// PriceWeight is the score per CNY of unit price. It is the main dial
	// between saving money and buying reliability.
	PriceWeight float64
	// FailWeight is the score added per consecutive failure.
	FailWeight float64
	// RateWeight is the score added by the smoothed failure rate, which keeps an
	// untried channel from being chosen forever.
	RateWeight float64
	// LowStockPenalty is added when a channel reports a single number of stock,
	// so a channel that can only serve one rental does not absorb every retry.
	LowStockPenalty float64
	// PauseAfterConsecutiveFails is the run of failures that pauses a channel.
	PauseAfterConsecutiveFails int
}

// DefaultStrategy returns the documented defaults.
func DefaultStrategy() Strategy {
	return Strategy{
		PriceWeight:                1.0,
		FailWeight:                 0.6,
		RateWeight:                 0.4,
		LowStockPenalty:            0.2,
		PauseAfterConsecutiveFails: 3,
	}
}

// withDefaults fills any unset field from DefaultStrategy.
func (s Strategy) withDefaults() Strategy {
	d := DefaultStrategy()
	if s.PriceWeight <= 0 {
		s.PriceWeight = d.PriceWeight
	}
	if s.FailWeight < 0 {
		s.FailWeight = d.FailWeight
	}
	if s.RateWeight < 0 {
		s.RateWeight = d.RateWeight
	}
	if s.LowStockPenalty < 0 {
		s.LowStockPenalty = d.LowStockPenalty
	}
	if s.PauseAfterConsecutiveFails <= 0 {
		s.PauseAfterConsecutiveFails = d.PauseAfterConsecutiveFails
	}
	return s
}

// Score is the ordering key for one candidate channel: lower is chosen first.
//
// It blends the channel's price with how it has behaved. An untried channel
// carries no reliability penalty, so exploration is not starved; a channel with
// a run of recent failures is pushed down, and above the pause threshold it is
// taken out of the running upstream entirely.
func (s Strategy) Score(quote Quote, stat ChannelStat, cooling bool) float64 {
	s = s.withDefaults()
	score := s.PriceWeight * quote.Price

	// Consecutive failures are the primary signal.
	score += s.FailWeight * float64(stat.ConsecutiveFails)

	// A smoothed failure rate keeps a long-bad channel down even after the run
	// resets, without letting a single failure dominate. Laplace smoothing (+1
	// over +2) means an untried channel contributes nothing here.
	if stat.Verdicts() > 0 {
		rate := (float64(stat.Timeouts) + 1) / (float64(stat.Verdicts()) + 2)
		score += s.RateWeight * rate
	}

	if quote.Stock == 1 {
		score += s.LowStockPenalty
	}
	if cooling {
		// Large enough to defer to any other candidate, finite so it is still
		// used when nothing else is left. This is the "try a different channel"
		// step, and it is bounded on purpose.
		score += 5
	}
	return score
}

// Rank orders candidates cheapest-and-most-reliable first.
//
// The order is a stable sort on Score, so equal scores keep the price-first
// order the cache already provides.
func (s Strategy) Rank(candidates []Quote, health *ChannelHealth, cooling map[string]bool) []Quote {
	ranked := append([]Quote(nil), candidates...)
	s = s.withDefaults()
	sort.SliceStable(ranked, func(i, j int) bool {
		a := s.scoreOf(ranked[i], health, cooling)
		b := s.scoreOf(ranked[j], health, cooling)
		if a != b {
			return a < b
		}
		if ranked[i].Price != ranked[j].Price {
			return ranked[i].Price < ranked[j].Price
		}
		return ranked[i].Stock > ranked[j].Stock
	})
	return ranked
}

// scoreOf looks a channel's record up and scores it.
func (s Strategy) scoreOf(quote Quote, health *ChannelHealth, cooling map[string]bool) float64 {
	var stat ChannelStat
	if health != nil {
		if existing, ok := health.Stat(quote.UID); ok {
			stat = existing
		}
	}
	return s.Score(quote, stat, cooling[quote.UID])
}

// -- cool-down ---------------------------------------------------------------

// CoolDown is a process-lifetime record of channels that just failed, so the
// next acquisition skips them instead of landing on the same one again.
//
// It is deliberately in memory only: the point is to break a retry loop within
// a session, not to blacklist a channel. The platform's own state is the
// durable record; nothing here should survive a restart.
type CoolDown struct {
	until map[string]int64
}

// NewCoolDown returns an empty cool-down set.
func NewCoolDown() *CoolDown { return &CoolDown{until: map[string]int64{}} }

// Mark holds a channel out of the preferred order until now+seconds.
func (c *CoolDown) Mark(uid string, now int64, seconds int64) {
	uid = strings.TrimSpace(uid)
	if uid == "" || seconds <= 0 {
		return
	}
	c.until[uid] = now + seconds
}

// Active reports which channels are currently cooling, for the ranker.
func (c *CoolDown) Active(now int64) map[string]bool {
	active := map[string]bool{}
	for uid, expiry := range c.until {
		if expiry > now {
			active[uid] = true
		} else {
			delete(c.until, uid)
		}
	}
	return active
}

// -- persistence -------------------------------------------------------------

// LoadChannelHealth reads the health store; a missing file yields an empty one.
func LoadChannelHealth(path string) (*ChannelHealth, error) {
	health := NewChannelHealth()
	if errLoad := loadJSON(path, health); errLoad != nil {
		return NewChannelHealth(), errLoad
	}
	if health.Version == 0 {
		health.Version = channelHealthVersion
	}
	if health.Stats == nil {
		health.Stats = map[string]*ChannelStat{}
	}
	return health, nil
}

// Save writes the health store.
func (h *ChannelHealth) Save(path string) error {
	if h.Version == 0 {
		h.Version = channelHealthVersion
	}
	return saveJSON(path, h)
}

// HealthPath is where the channel health store lives.
func (s Store) HealthPath() string { return filepath.Join(s.Dir, "loomy-sms-health.json") }

// describe renders one channel's record as a short human label, for logs.
func (s ChannelStat) describe() string {
	return fmt.Sprintf("%d/%d delivered, run=%d",
		s.Delivered, s.Verdicts(), s.ConsecutiveFails)
}
