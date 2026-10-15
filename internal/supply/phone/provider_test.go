package phone

import (
	"context"
	"errors"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// readyProvider is the fake provider with a scripted inbox, so the delivery
// recording that the host now owns can be exercised.
type readyProvider struct {
	fakeProvider
	message Message
	readErr error
}

func (r *readyProvider) Read(context.Context, Project, string) (Message, error) {
	return r.message, r.readErr
}

// newHostPhoneProvider builds a host phone provider over a temporary store and a
// fixed channel cache, without touching the network.
func newHostPhoneProvider(t *testing.T, provider Provider, channels []Quote, budget Budget) *ProviderImpl {
	t.Helper()
	return &ProviderImpl{
		service:   newTestService(t, provider, channels, budget),
		project:   Project{SID: "21614"},
		delivered: map[string]bool{},
	}
}

// A number the pool never recorded must not be re-occupied: asking the
// platform for it would either fail or take a number that was never ours. The
// caller is told so distinctly, and no platform call is made.
func TestGrabUnknownAddressIsRejectedWithoutRenting(t *testing.T) {
	provider := &fakeProvider{phone: "13800000000"}
	impl := newHostPhoneProvider(t, provider, []Quote{{UID: "21614-cheap", Price: 0.1, Stock: 1}}, Budget{})

	_, errGrab := impl.Grab(context.Background(), supply.GrabOptions{Address: "13900000000"})
	if !errors.Is(errGrab, supply.ErrUnknownIdentity) {
		t.Fatalf("err = %v, want ErrUnknownIdentity", errGrab)
	}
	if len(provider.rented) != 0 {
		t.Fatalf("platform was asked to re-occupy %v, want no rental", provider.rented)
	}
}

// A number the pool recorded is re-occupied through the platform, and the
// rental is attributed to that exact number.
func TestGrabReacquiresKnownAddress(t *testing.T) {
	provider := &fakeProvider{phone: "13800000000"}
	impl := newHostPhoneProvider(t, provider, []Quote{{UID: "21614-cheap", Price: 0.1, Stock: 1}}, Budget{})

	first, errFirst := impl.Grab(context.Background(), supply.GrabOptions{})
	if errFirst != nil {
		t.Fatalf("first grab: %v", errFirst)
	}
	second, errSecond := impl.Grab(context.Background(), supply.GrabOptions{Address: first.Address})
	if errSecond != nil {
		t.Fatalf("re-acquire: %v", errSecond)
	}
	if second.Address != first.Address {
		t.Fatalf("re-acquired %q, want %q", second.Address, first.Address)
	}
	if len(provider.rented) == 0 || provider.rented[len(provider.rented)-1] != "spec:"+first.Address {
		t.Fatalf("platform rentals = %v, want the last to re-occupy %s", provider.rented, first.Address)
	}
}

// A message credits the channel that produced the number with exactly one
// delivery, no matter how many times the inbox is polled while verifying.
func TestReadRecordsDeliveryOnce(t *testing.T) {
	provider := &readyProvider{
		fakeProvider: fakeProvider{phone: "13800000000"},
		message:      Message{Ready: true, Code: "123456"},
	}
	impl := newHostPhoneProvider(t, provider, []Quote{{UID: "21614-cheap", Price: 0.1, Stock: 1}}, Budget{})

	identity, errGrab := impl.Grab(context.Background(), supply.GrabOptions{})
	if errGrab != nil {
		t.Fatalf("grab: %v", errGrab)
	}
	for range 3 {
		if _, errRead := impl.Read(context.Background(), "", identity.Address); errRead != nil {
			t.Fatalf("read: %v", errRead)
		}
	}
	stat, ok := impl.service.Health().Stat(identity.Code)
	if !ok {
		t.Fatalf("no health recorded for channel %s", identity.Code)
	}
	if stat.Delivered != 1 {
		t.Fatalf("delivered = %d, want 1", stat.Delivered)
	}
}

// Releasing on timeout counts a failure against the channel that produced the
// number, so the rent order can demote it.
func TestReleaseTimeoutCountsChannelFailure(t *testing.T) {
	provider := &fakeProvider{phone: "13800000000"}
	impl := newHostPhoneProvider(t, provider, []Quote{{UID: "21614-cheap", Price: 0.1, Stock: 1}}, Budget{})

	identity, errGrab := impl.Grab(context.Background(), supply.GrabOptions{})
	if errGrab != nil {
		t.Fatalf("grab: %v", errGrab)
	}
	if errRelease := impl.Release(context.Background(), identity.Address, "timeout"); errRelease != nil {
		t.Fatalf("release: %v", errRelease)
	}
	stat, ok := impl.service.Health().Stat(identity.Code)
	if !ok {
		t.Fatalf("no health recorded for channel %s", identity.Code)
	}
	if stat.Timeouts != 1 || stat.ConsecutiveFails != 1 {
		t.Fatalf("timeouts=%d consecutiveFails=%d, want 1 and 1", stat.Timeouts, stat.ConsecutiveFails)
	}
}

// A plain release is not a failure: it leaves the channel's failure run alone.
func TestReleaseUnusedDoesNotCountFailure(t *testing.T) {
	provider := &fakeProvider{phone: "13800000000"}
	impl := newHostPhoneProvider(t, provider, []Quote{{UID: "21614-cheap", Price: 0.1, Stock: 1}}, Budget{})

	identity, errGrab := impl.Grab(context.Background(), supply.GrabOptions{})
	if errGrab != nil {
		t.Fatalf("grab: %v", errGrab)
	}
	if errRelease := impl.Release(context.Background(), identity.Address, "released"); errRelease != nil {
		t.Fatalf("release: %v", errRelease)
	}
	if stat, ok := impl.service.Health().Stat(identity.Code); ok && stat.ConsecutiveFails != 0 {
		t.Fatalf("consecutiveFails = %d after a plain release, want 0", stat.ConsecutiveFails)
	}
}

// A re-occupied number credits its channel again: the once-per-number delivery
// flag is per rental, not per number.
func TestReadCreditsDeliveryAgainAfterReacquire(t *testing.T) {
	provider := &readyProvider{
		fakeProvider: fakeProvider{phone: "13800000000"},
		message:      Message{Ready: true, Code: "123456"},
	}
	impl := newHostPhoneProvider(t, provider, []Quote{{UID: "21614-cheap", Price: 0.1, Stock: 1}}, Budget{})

	first, errFirst := impl.Grab(context.Background(), supply.GrabOptions{})
	if errFirst != nil {
		t.Fatalf("first grab: %v", errFirst)
	}
	if _, errRead := impl.Read(context.Background(), "", first.Address); errRead != nil {
		t.Fatalf("first read: %v", errRead)
	}
	if errRelease := impl.Release(context.Background(), first.Address, "released"); errRelease != nil {
		t.Fatalf("release: %v", errRelease)
	}
	second, errSecond := impl.Grab(context.Background(), supply.GrabOptions{Address: first.Address})
	if errSecond != nil {
		t.Fatalf("re-acquire: %v", errSecond)
	}
	if _, errRead := impl.Read(context.Background(), "", second.Address); errRead != nil {
		t.Fatalf("second read: %v", errRead)
	}
	stat, ok := impl.service.Health().Stat(first.Code)
	if !ok {
		t.Fatalf("no health recorded for channel %s", first.Code)
	}
	if stat.Delivered != 2 {
		t.Fatalf("delivered = %d, want 2 (one per rental)", stat.Delivered)
	}
}
