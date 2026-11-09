package pluginhost

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type blockingGuardPluginClient struct {
	started  chan struct{}
	release  chan struct{}
	shutdown atomic.Int32
}

func (c *blockingGuardPluginClient) Call(context.Context, string, []byte) ([]byte, error) {
	close(c.started)
	<-c.release
	return nil, nil
}

func (c *blockingGuardPluginClient) Shutdown() {
	c.shutdown.Add(1)
}

// limitGuardPluginClient models the native call: it ignores the request
// context because a CGO call cannot be canceled from Go.
type limitGuardPluginClient struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (c *limitGuardPluginClient) Call(context.Context, string, []byte) ([]byte, error) {
	c.calls.Add(1)
	c.started <- struct{}{}
	<-c.release
	return nil, nil
}

func (c *limitGuardPluginClient) Shutdown() {}

func TestGuardedPluginClientShutdownContextDetachesBlockedCall(t *testing.T) {
	inner := &blockingGuardPluginClient{started: make(chan struct{}), release: make(chan struct{})}
	guarded := newGuardedPluginClient(inner, nil)

	callDone := make(chan struct{})
	go func() {
		_, _ = guarded.Call(context.Background(), "blocked", nil)
		close(callDone)
	}()
	select {
	case <-inner.started:
	case <-time.After(time.Second):
		t.Fatal("guarded call did not start")
	}

	shutdownCtx, cancelShutdown := context.WithCancel(context.Background())
	cancelShutdown()
	shutdownDone := make(chan struct{})
	go func() {
		guarded.ShutdownContext(shutdownCtx)
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("context-canceled guarded shutdown waited for the active call")
	}
	if got := inner.shutdown.Load(); got != 0 {
		t.Fatalf("shutdown calls before active call exits = %d, want 0", got)
	}

	close(inner.release)
	select {
	case <-callDone:
	case <-time.After(time.Second):
		t.Fatal("guarded call did not exit")
	}
	deadline := time.Now().Add(time.Second)
	for inner.shutdown.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := inner.shutdown.Load(); got != 1 {
		t.Fatalf("shutdown calls after active call exits = %d, want 1", got)
	}
}

func waitForInFlight(t *testing.T, limiter *pluginCallLimiter, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for limiter.inFlight() != want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := limiter.inFlight(); got != want {
		t.Fatalf("in-flight calls = %d, want %d", got, want)
	}
}

func TestGuardedPluginClientCallLimitShedsExcessCalls(t *testing.T) {
	inner := &limitGuardPluginClient{started: make(chan struct{}, 4), release: make(chan struct{})}
	limiter := newPluginCallLimiter(1)
	guarded := newGuardedPluginClient(inner, limiter)

	firstDone := make(chan error, 1)
	go func() {
		_, errCall := guarded.Call(context.Background(), "executor.execute", nil)
		firstDone <- errCall
	}()
	select {
	case <-inner.started:
	case <-time.After(time.Second):
		t.Fatal("first call did not start")
	}

	_, errShed := guarded.Call(context.Background(), "executor.execute", nil)
	if errShed == nil {
		t.Fatal("second call was admitted over the limit")
	}
	var statusCoder interface{ StatusCode() int }
	if !errors.As(errShed, &statusCoder) || statusCoder.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("shed error status = %v, want %d", errShed, http.StatusServiceUnavailable)
	}
	var loadShedder interface{ LoadShed() bool }
	if !errors.As(errShed, &loadShedder) || !loadShedder.LoadShed() {
		t.Fatalf("shed error %v does not mark itself as load shedding", errShed)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("inner calls after shedding = %d, want 1", got)
	}

	close(inner.release)
	if errCall := <-firstDone; errCall != nil {
		t.Fatalf("first call error = %v", errCall)
	}
	waitForInFlight(t, limiter, 0)

	if _, errCall := guarded.Call(context.Background(), "executor.execute", nil); errCall != nil {
		t.Fatalf("call after the slot was released error = %v", errCall)
	}
}

func TestGuardedPluginClientCallLimitHoldsSlotUntilNativeCallReturns(t *testing.T) {
	inner := &limitGuardPluginClient{started: make(chan struct{}, 4), release: make(chan struct{})}
	limiter := newPluginCallLimiter(1)
	guarded := newGuardedPluginClient(inner, limiter)

	ctx, cancel := context.WithCancel(context.Background())
	callDone := make(chan error, 1)
	go func() {
		_, errCall := guarded.Call(ctx, "executor.execute", nil)
		callDone <- errCall
	}()
	select {
	case <-inner.started:
	case <-time.After(time.Second):
		t.Fatal("first call did not start")
	}

	cancel()
	select {
	case errCall := <-callDone:
		if !errors.Is(errCall, context.Canceled) {
			t.Fatalf("canceled call error = %v, want %v", errCall, context.Canceled)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled call did not return")
	}
	if got := limiter.inFlight(); got != 1 {
		t.Fatalf("in-flight calls after context cancel = %d, want 1", got)
	}
	if _, errShed := guarded.Call(context.Background(), "executor.execute", nil); errShed == nil {
		t.Fatal("call was admitted while the canceled native call still held its slot")
	}

	close(inner.release)
	waitForInFlight(t, limiter, 0)
	if _, errCall := guarded.Call(context.Background(), "executor.execute", nil); errCall != nil {
		t.Fatalf("call after the native call returned error = %v", errCall)
	}
}

func TestGuardedPluginClientCallLimitDisabledAdmitsEveryCall(t *testing.T) {
	inner := &limitGuardPluginClient{started: make(chan struct{}, 4), release: make(chan struct{})}
	limiter := newPluginCallLimiter(0)
	guarded := newGuardedPluginClient(inner, limiter)

	done := make(chan error, 2)
	for range 2 {
		go func() {
			_, errCall := guarded.Call(context.Background(), "executor.execute", nil)
			done <- errCall
		}()
	}
	for range 2 {
		select {
		case <-inner.started:
		case <-time.After(time.Second):
			t.Fatal("call did not start with the limit disabled")
		}
	}
	close(inner.release)
	for range 2 {
		if errCall := <-done; errCall != nil {
			t.Fatalf("call error = %v", errCall)
		}
	}
}
