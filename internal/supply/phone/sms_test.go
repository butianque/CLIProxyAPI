package phone

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// fakeProvider records what it was asked and answers from a scripted plan, so
// the service's channel-walking and budget rules can be tested without a
// network.
type fakeProvider struct {
	// replies maps a channel id to the error its rental returns; a nil entry
	// rents successfully.
	replies map[string]error
	rented  []string
	phone   string
	// balance is the reported balance; a successful rental subtracts rentCost,
	// which lets a test drive the unpinned price measurement.
	balance  float64
	rentCost float64
	// releaseErr, when set, makes Release fail so the refund-on-release path can
	// be tested.
	releaseErr error
}

func (f *fakeProvider) ID() string { return "fake" }

func (f *fakeProvider) Balance(context.Context) (float64, error) { return f.balance, nil }

func (f *fakeProvider) Rent(_ context.Context, project Project, uid string) (Number, error) {
	f.rented = append(f.rented, uid)
	if errRent, ok := f.replies[uid]; ok && errRent != nil {
		return Number{}, errRent
	}
	f.balance -= f.rentCost
	return Number{Phone: f.phone, SID: project.SID, Code: uid}, nil
}

func (f *fakeProvider) AcquirePhone(_ context.Context, project Project, phone string) (Number, error) {
	f.rented = append(f.rented, "spec:"+phone)
	return Number{Phone: phone, SID: project.SID}, nil
}

func (f *fakeProvider) Read(context.Context, Project, string) (Message, error) {
	return Message{}, ErrNotReady
}

func (f *fakeProvider) Release(context.Context, Project, string) error { return f.releaseErr }

func (f *fakeProvider) Blacklist(context.Context, Project, string) error { return nil }

// newTestService builds a service over a temporary store with a fixed channel
// cache.
func newTestService(t *testing.T, provider Provider, channels []Quote, budget Budget) *Service {
	t.Helper()
	store := Store{Dir: t.TempDir()}
	service := NewService(provider, store, budget)
	if errReplace := service.ReplaceChannels("21614", channels, 1); errReplace != nil {
		t.Fatalf("ReplaceChannels: %v", errReplace)
	}
	return service
}

// The cheapest in-stock channel must be tried first, and a channel that refuses
// must not be retried on the next rental.
func TestAcquireWalksChannelsCheapestFirst(t *testing.T) {
	provider := &fakeProvider{phone: "13800000000"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-pricey", Price: 0.9, Stock: 5},
		{UID: "21614-cheapout", Price: 0.1, Stock: 0},
		{UID: "21614-cheap", Price: 0.13, Stock: 1},
	}, Budget{})

	number, entry, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Code != "21614-cheap" {
		t.Fatalf("rented %q, want the cheapest in-stock channel", number.Code)
	}
	if entry.Price != 0.13 {
		t.Fatalf("recorded price %v, want 0.13", entry.Price)
	}
	if len(provider.rented) != 1 || provider.rented[0] != "21614-cheap" {
		t.Fatalf("provider calls = %v, want one call to the cheapest channel", provider.rented)
	}
}

// A refused channel is marked out of stock, so the next rental starts at the
// next cheapest one.
func TestAcquireMarksRefusedChannelOutOfStock(t *testing.T) {
	provider := &fakeProvider{
		phone:   "13800000001",
		replies: map[string]error{"21614-a": errors.New("no stock")},
	}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-a", Price: 0.13, Stock: 4},
		{UID: "21614-b", Price: 0.18, Stock: 4},
	}, Budget{})

	number, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Code != "21614-b" {
		t.Fatalf("rented %q, want the next channel after the refusal", number.Code)
	}
	// The refused channel must now be skipped without being called again.
	if _, _, errSecond := service.Acquire(context.Background(), Project{SID: "21614"}); errSecond != nil {
		t.Fatalf("second Acquire: %v", errSecond)
	}
	calls := 0
	for _, uid := range provider.rented {
		if uid == "21614-a" {
			calls++
		}
	}
	if calls != 1 {
		t.Fatalf("refused channel was called %d times, want 1", calls)
	}
}

// A credential error is fatal: every channel would fail, so acquisition stops
// instead of walking the whole list.
func TestAcquireStopsOnCredentialError(t *testing.T) {
	provider := &fakeProvider{
		replies: map[string]error{"21614-a": ErrCredential},
	}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-a", Price: 0.13, Stock: 4},
		{UID: "21614-b", Price: 0.18, Stock: 4},
	}, Budget{})

	_, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if !errors.Is(errAcquire, ErrCredential) {
		t.Fatalf("err = %v, want ErrCredential", errAcquire)
	}
	if len(provider.rented) != 1 {
		t.Fatalf("provider calls = %v, want only the first channel", provider.rented)
	}
}

// The per-number cap skips expensive channels; the total cap ends renting.
func TestAcquireRespectsBudget(t *testing.T) {
	provider := &fakeProvider{phone: "13800000002"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-cheap", Price: 0.2, Stock: 4},
		{UID: "21614-pricey", Price: 3.0, Stock: 4},
	}, Budget{MaxPerNumberCNY: 0.5, MaxTotalCNY: 0.3})

	// The first rental (0.2) fits under the total cap.
	if _, _, errFirst := service.Acquire(context.Background(), Project{SID: "21614"}); errFirst != nil {
		t.Fatalf("first Acquire: %v", errFirst)
	}
	// The second would take the total to 0.4, past the 0.3 cap.
	if _, _, errSecond := service.Acquire(context.Background(), Project{SID: "21614"}); !errors.Is(errSecond, ErrBudget) {
		t.Fatalf("second Acquire err = %v, want ErrBudget", errSecond)
	}
	// The pricey channel was never touched.
	for _, uid := range provider.rented {
		if uid == "21614-pricey" {
			t.Fatalf("rented a channel above the per-number cap: %v", provider.rented)
		}
	}
}

// An empty channel cache must not block renting: the documented getPhone call
// needs only the project id, so acquisition falls back to an unpinned rental and
// still records the channel the platform chose.
func TestAcquireFallsBackToUnpinnedWhenCacheEmpty(t *testing.T) {
	provider := &fakeProvider{phone: "13800000006"}
	store := Store{Dir: t.TempDir()}
	// No ReplaceChannels: the cache is cold, as it is before any web refresh.
	service := NewService(provider, store, Budget{MaxPerNumberCNY: 0.5})

	number, entry, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Phone != "13800000006" {
		t.Fatalf("number = %+v, want the rented number", number)
	}
	if len(provider.rented) != 1 || provider.rented[0] != "" {
		t.Fatalf("provider calls = %v, want one unpinned rental", provider.rented)
	}
	if entry.Address != "13800000006" {
		t.Fatalf("ledger record = %+v, want the rented number recorded", entry)
	}
}

// A channel the platform lists as free must be rentable; a zero price is a real
// price, not a missing one.
func TestAcquireKeepsFreeChannel(t *testing.T) {
	provider := &fakeProvider{phone: "13800000007"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-free", Name: "[21614]讯飞", Price: 0, Stock: 2},
		{UID: "21614-cheap", Name: "[21614]讯飞", Price: 0.13, Stock: 4},
	}, Budget{MaxPerNumberCNY: 0.5})

	number, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Code != "21614-free" {
		t.Fatalf("rented %q, want the free channel", number.Code)
	}
}

// An unpinned rental must be priced from the balance difference so the ledger
// and the cumulative ceiling stay truthful when the channel list is empty.
func TestAcquireUnpinnedPricesFromBalance(t *testing.T) {
	provider := &fakeProvider{phone: "13800000008", balance: 3.19, rentCost: 0.33}
	store := Store{Dir: t.TempDir()}
	service := NewService(provider, store, Budget{MaxPerNumberCNY: 0.5, MaxTotalCNY: 20})

	_, entry, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if entry.Price != 0.33 {
		t.Fatalf("entry price = %v, want 0.33 from the balance difference", entry.Price)
	}
	if spent := service.Ledger().Spent(); spent != 0.33 {
		t.Fatalf("ledger spend = %v, want 0.33", spent)
	}
}

// An explicit channel code pins the rental, bypassing the price order.
func TestAcquirePinnedChannel(t *testing.T) {
	provider := &fakeProvider{phone: "13800000003"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 4},
	}, Budget{})

	number, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614", Code: "21614-pinned"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if number.Code != "21614-pinned" {
		t.Fatalf("rented %q, want the pinned channel", number.Code)
	}
}

// The ledger accumulates spend and links a number to the account it registered.
func TestLedgerRecordsSpendAndAccount(t *testing.T) {
	provider := &fakeProvider{phone: "13800000004"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 4},
	}, Budget{})

	number, _, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if errLink := service.LinkAccount(number.Phone, "loomy", "loomy-"+number.Phone, "idx-1"); errLink != nil {
		t.Fatalf("LinkAccount: %v", errLink)
	}

	// A fresh service over the same directory must see the same ledger.
	reloaded := NewService(provider, service.Store, Budget{})
	entry, ok := reloaded.Ledger().Get(supply.KindPhone, number.Phone)
	if !ok {
		t.Fatalf("ledger lost %s after reload", number.Phone)
	}
	if entry.Account != "loomy-"+number.Phone || entry.AuthIndex != "idx-1" {
		t.Fatalf("entry = %+v, want the linked account", entry)
	}
	if entry.Target != "loomy" {
		t.Fatalf("target = %q, want the platform the number registered on", entry.Target)
	}
	if reloaded.Ledger().Spent() != 0.13 {
		t.Fatalf("spent = %v, want 0.13", reloaded.Ledger().Spent())
	}
	if got := reloaded.Ledger().ForAccount("loomy-" + number.Phone); len(got) != 1 {
		t.Fatalf("ForAccount returned %d entries, want 1", len(got))
	}
}

// Releasing a rental that produced nothing must credit the spend back, so the
// running total tracks money actually consumed rather than every attempt.
func TestReleaseUnusedCreditsSpendBack(t *testing.T) {
	provider := &fakeProvider{phone: "13800000009"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 4},
	}, Budget{MaxTotalCNY: 20})

	number, entry, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if service.Ledger().Spent() != 0.13 {
		t.Fatalf("spent after rent = %v, want 0.13", service.Ledger().Spent())
	}

	if errRelease := service.ReleaseUnused(context.Background(), Project{SID: "21614"}, number.Phone, entry.Price, OutcomeReleased); errRelease != nil {
		t.Fatalf("ReleaseUnused: %v", errRelease)
	}
	if got := service.Ledger().Spent(); got != 0 {
		t.Fatalf("spent after release = %v, want 0 (the rental was credited back)", got)
	}
	reloaded := NewService(provider, service.Store, Budget{})
	if got := reloaded.Ledger().Spent(); got != 0 {
		t.Fatalf("reloaded spent = %v, want 0", got)
	}
}

// A failed release leaves the number rented and the platform charged, so the
// spend must stay booked rather than being credited back.
func TestReleaseUnusedSkipsRefundWhenReleaseFails(t *testing.T) {
	provider := &fakeProvider{phone: "13800000011", releaseErr: errors.New("platform busy")}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-cheap", Price: 0.13, Stock: 4},
	}, Budget{})

	number, entry, errAcquire := service.Acquire(context.Background(), Project{SID: "21614"})
	if errAcquire != nil {
		t.Fatalf("Acquire: %v", errAcquire)
	}
	if errRelease := service.ReleaseUnused(context.Background(), Project{SID: "21614"}, number.Phone, entry.Price, OutcomeReleased); errRelease == nil {
		t.Fatalf("ReleaseUnused should report the failed release")
	}
	if got := service.Ledger().Spent(); got != 0.13 {
		t.Fatalf("spent = %v, want 0.13 (a failed release keeps the charge)", got)
	}
}

// The channel cache is persisted and reloaded beside the ledger.
func TestChannelCachePersists(t *testing.T) {
	provider := &fakeProvider{phone: "13800000005"}
	service := newTestService(t, provider, []Quote{
		{UID: "21614-b", Price: 0.18, Stock: 4},
		{UID: "21614-a", Price: 0.13, Stock: 4},
	}, Budget{})

	reloaded := NewService(provider, service.Store, Budget{})
	cheapest := reloaded.Channels().Cheapest(0)
	if len(cheapest) != 2 || cheapest[0].UID != "21614-a" {
		t.Fatalf("reloaded cheapest = %+v, want 21614-a first", cheapest)
	}
	// The ledger is cross-kind now, so its file is the shared one rather than a
	// phone-only name.
	if filepath.Base(reloaded.Store.LedgerPath()) != "ledger.json" {
		t.Fatalf("ledger path = %s", reloaded.Store.LedgerPath())
	}
}
