package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// capTestExecutor records which credential each call landed on and can hold a
// call open, which is what makes "in flight" observable to the admission gate.
type capTestExecutor struct {
	identifier string
	gate       chan struct{}
	started    chan string

	mu   sync.Mutex
	ids  []string
	errs []error
}

func (e *capTestExecutor) Identifier() string { return e.identifier }

func (e *capTestExecutor) record(auth *Auth) {
	e.mu.Lock()
	e.ids = append(e.ids, auth.ID)
	e.mu.Unlock()
	e.started <- auth.ID
}

func (e *capTestExecutor) waitGate(ctx context.Context) error {
	if e.gate == nil {
		return nil
	}
	select {
	case <-e.gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *capTestExecutor) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.record(auth)
	if errWait := e.waitGate(ctx); errWait != nil {
		return cliproxyexecutor.Response{}, errWait
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"ok":true}`)}, nil
}

func (e *capTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.record(auth)
	chunks := make(chan cliproxyexecutor.StreamChunk, 2)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: first\n\n")}
	go func() {
		defer close(chunks)
		if errWait := e.waitGate(ctx); errWait != nil {
			chunks <- cliproxyexecutor.StreamChunk{Err: errWait}
			return
		}
		chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: last\n\n")}
	}()
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func (e *capTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}

func (*capTestExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }

func (*capTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *capTestExecutor) calls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.ids...)
}

// waitCapCall fails the test instead of hanging when a call never starts.
func waitCapCall(t *testing.T, started <-chan string) string {
	t.Helper()
	select {
	case id := <-started:
		return id
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the executor to be called")
		return ""
	}
}

func newCapTestManager(t *testing.T, provider string, caps map[string]any) (*Manager, *capTestExecutor) {
	t.Helper()
	model := provider + "-model"
	manager := NewManager(nil, nil, nil)
	executor := &capTestExecutor{
		identifier: provider,
		gate:       make(chan struct{}),
		started:    make(chan string, 8),
	}
	manager.RegisterExecutor(executor)
	reg := registry.GetGlobalRegistry()
	for id, cap := range caps {
		reg.RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { reg.UnregisterClient(id) })
		metadata := map[string]any{"disable_cooling": true}
		if cap != nil {
			metadata[AttributeMaxConcurrency] = cap
		}
		if _, errRegister := manager.Register(context.Background(), &Auth{
			ID:         id,
			Provider:   provider,
			Metadata:   metadata,
			Attributes: map[string]string{AttributePath: "/auths/" + id + ".json"},
		}); errRegister != nil {
			t.Fatalf("register %s: %v", id, errRegister)
		}
	}
	return manager, executor
}

func TestCredentialConcurrencyLimitResolution(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		metadata any
		attr     string
		want     int
	}{
		{name: "zcode default", provider: "zcode-bigmodel", want: 3},
		{name: "loomy default", provider: "loomy", want: 5},
		{name: "workbuddy default", provider: "workbuddy-cn", want: 2},
		{name: "unknown provider default", provider: "some-upstream", want: 2},
		{name: "empty provider default", provider: "", want: 2},
		{name: "metadata overrides the default", provider: "zcode-bigmodel", metadata: "7", want: 7},
		{name: "metadata number overrides the default", provider: "zcode-bigmodel", metadata: 7, want: 7},
		{name: "metadata zero disables the cap", provider: "zcode-bigmodel", metadata: 0, want: 0},
		{name: "metadata zero string disables the cap", provider: "zcode-bigmodel", metadata: "0", want: 0},
		{name: "negative metadata falls back to the default", provider: "zcode-bigmodel", metadata: -1, want: 3},
		{name: "non-numeric metadata falls back to the default", provider: "zcode-bigmodel", metadata: "many", want: 3},
		{name: "fractional metadata falls back to the default", provider: "zcode-bigmodel", metadata: 2.5, want: 3},
		{name: "metadata wins over attributes", provider: "loomy", metadata: "4", attr: "9", want: 4},
		{name: "attributes apply without metadata", provider: "loomy", attr: "9", want: 9},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &Auth{ID: "cap-resolution", Provider: test.provider}
			if test.metadata != nil {
				auth.Metadata = map[string]any{AttributeMaxConcurrency: test.metadata}
			}
			if test.attr != "" {
				auth.Attributes = map[string]string{AttributeMaxConcurrency: test.attr}
			}
			if got := credentialConcurrencyLimit(auth); got != test.want {
				t.Fatalf("credentialConcurrencyLimit(%s, metadata=%v, attr=%q) = %d, want %d", test.provider, test.metadata, test.attr, got, test.want)
			}
		})
	}
}

func TestParseAuthMaxConcurrency(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		want    int
		wantErr bool
	}{
		{name: "zero disables the cap", value: 0},
		{name: "positive", value: 3, want: 3},
		{name: "numeric string", value: "3", want: 3},
		{name: "json number", value: json.Number("4"), want: 4},
		{name: "negative is rejected", value: -1, wantErr: true},
		{name: "fractional is rejected", value: 1.5, wantErr: true},
		{name: "text is rejected", value: "lots", wantErr: true},
		{name: "boolean is rejected", value: true, wantErr: true},
		{name: "empty string is rejected", value: "  ", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, errParse := ParseAuthMaxConcurrency(test.value)
			if test.wantErr != (errParse != nil) {
				t.Fatalf("ParseAuthMaxConcurrency(%v) error = %v, want error=%v", test.value, errParse, test.wantErr)
			}
			if !test.wantErr && got != test.want {
				t.Fatalf("ParseAuthMaxConcurrency(%v) = %d, want %d", test.value, got, test.want)
			}
		})
	}
}

func TestCredentialConcurrencyKeyUsesTheSourceFile(t *testing.T) {
	virtual := &Auth{ID: "expanded-2", Attributes: map[string]string{
		AttributeVirtualSource: "/auths/pool.json",
		AttributePath:          "/auths/other.json",
	}}
	if got := credentialConcurrencyKey(virtual); got != "src:/auths/pool.json" {
		t.Fatalf("virtual source key = %q", got)
	}
	fileBacked := &Auth{ID: "single", Attributes: map[string]string{AttributePath: "/auths/single.json"}}
	if got := credentialConcurrencyKey(fileBacked); got != "src:/auths/single.json" {
		t.Fatalf("path key = %q", got)
	}
	runtimeOnly := &Auth{ID: "runtime"}
	if got := credentialConcurrencyKey(runtimeOnly); got != "id:runtime" {
		t.Fatalf("fallback key = %q", got)
	}
}

// A full credential must not fail the request: the same pick has to spill to the
// credential that still has room, with no error, no result record and no cooldown.
func TestCredentialCapSpillsToAnIdleCredential(t *testing.T) {
	manager, executor := newCapTestManager(t, "cap-spill", map[string]any{
		"cap-spill-a": 1,
		"cap-spill-b": 1,
	})
	manager.credentialCapQueueWait = 100 * time.Millisecond
	manager.credentialCapPollInterval = 5 * time.Millisecond

	results := make(chan error, 2)
	go func() {
		_, errExecute := manager.Execute(context.Background(), []string{"cap-spill"}, cliproxyexecutor.Request{Model: "cap-spill-model"}, cliproxyexecutor.Options{})
		results <- errExecute
	}()
	first := waitCapCall(t, executor.started)

	go func() {
		_, errExecute := manager.Execute(context.Background(), []string{"cap-spill"}, cliproxyexecutor.Request{Model: "cap-spill-model"}, cliproxyexecutor.Options{})
		results <- errExecute
	}()
	second := waitCapCall(t, executor.started)

	if first == second {
		t.Fatalf("both requests ran on %s; the second should have spilled", first)
	}
	close(executor.gate)
	for range 2 {
		if errExecute := <-results; errExecute != nil {
			t.Fatalf("execution error = %v, want nil; spilling must not fail a request", errExecute)
		}
	}
	for _, auth := range manager.List() {
		if auth.Failed != 0 {
			t.Fatalf("auth %s failed count = %d; a busy credential is not a failure", auth.ID, auth.Failed)
		}
		if auth.Success != 1 {
			t.Fatalf("auth %s success count = %d, want 1", auth.ID, auth.Success)
		}
	}
	if inFlight := manager.CredentialConcurrencySnapshot(manager.List(), ""); len(inFlight) != 2 {
		t.Fatalf("snapshot entries = %d, want 2", len(inFlight))
	}
	for id, usage := range manager.CredentialConcurrencySnapshot(manager.List(), "") {
		if usage.InFlight != 0 || usage.Limit != 1 {
			t.Fatalf("auth %s snapshot = %+v, want in-flight 0 and limit 1", id, usage)
		}
	}
}

// When the whole pool is at its cap the request is refused with the busy shape
// (429 + Retry-After) instead of being recorded against a healthy credential.
func TestCredentialCapFullPoolReturnsBusy(t *testing.T) {
	manager, executor := newCapTestManager(t, "cap-full", map[string]any{
		"cap-full-a": 1,
	})
	manager.credentialCapQueueWait = 100 * time.Millisecond
	manager.credentialCapPollInterval = 5 * time.Millisecond

	results := make(chan error, 1)
	go func() {
		_, errExecute := manager.Execute(context.Background(), []string{"cap-full"}, cliproxyexecutor.Request{Model: "cap-full-model"}, cliproxyexecutor.Options{})
		results <- errExecute
	}()
	waitCapCall(t, executor.started)

	_, errBusy := manager.Execute(context.Background(), []string{"cap-full"}, cliproxyexecutor.Request{Model: "cap-full-model"}, cliproxyexecutor.Options{})
	var busy *HomeConcurrencyBusyError
	if !errors.As(errBusy, &busy) {
		t.Fatalf("second request error = %v, want a *HomeConcurrencyBusyError", errBusy)
	}
	if status := busy.StatusCode(); status != 429 {
		t.Fatalf("busy status = %d, want 429", status)
	}
	retryAfter := busy.RetryAfter()
	if retryAfter == nil || *retryAfter <= 0 {
		t.Fatalf("busy retry-after = %v, want a positive duration", retryAfter)
	}
	if headers := busy.SafeResponseHeaders(); strings.TrimSpace(headers.Get("Retry-After")) == "" {
		t.Fatalf("busy headers = %v, want Retry-After", headers)
	}

	close(executor.gate)
	if errExecute := <-results; errExecute != nil {
		t.Fatalf("first request error = %v, want nil", errExecute)
	}
	auth, okAuth := manager.GetByID("cap-full-a")
	if !okAuth {
		t.Fatal("auth cap-full-a missing")
	}
	if auth.Failed != 0 {
		t.Fatalf("failed count = %d; a full pool must not count as a credential failure", auth.Failed)
	}
}

// A stream is not over when ExecuteStream returns, so the slot must stay held
// until the last chunk has been handed to the consumer.
func TestCredentialCapStreamHoldsTheSlotUntilTheLastChunk(t *testing.T) {
	manager, executor := newCapTestManager(t, "cap-stream", map[string]any{
		"cap-stream-a": 1,
	})
	manager.credentialCapQueueWait = 100 * time.Millisecond
	manager.credentialCapPollInterval = 5 * time.Millisecond

	stream, errStream := manager.ExecuteStream(context.Background(), []string{"cap-stream"}, cliproxyexecutor.Request{Model: "cap-stream-model"}, cliproxyexecutor.Options{Stream: true})
	if errStream != nil {
		t.Fatalf("ExecuteStream error = %v", errStream)
	}
	if got := waitCapCall(t, executor.started); got != "cap-stream-a" {
		t.Fatalf("stream started on %s", got)
	}
	if usage := manager.CredentialConcurrencySnapshot(manager.List(), "cap-stream-model")["cap-stream-a"]; usage.InFlight != 1 {
		t.Fatalf("in-flight during the stream = %d, want 1", usage.InFlight)
	}

	_, errBusy := manager.ExecuteStream(context.Background(), []string{"cap-stream"}, cliproxyexecutor.Request{Model: "cap-stream-model"}, cliproxyexecutor.Options{Stream: true})
	var busy *HomeConcurrencyBusyError
	if !errors.As(errBusy, &busy) {
		t.Fatalf("second stream error = %v, want a *HomeConcurrencyBusyError", errBusy)
	}

	close(executor.gate)
	chunks := 0
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
		chunks++
	}
	if chunks < 2 {
		t.Fatalf("stream chunks = %d, want at least 2", chunks)
	}
	if usage := manager.CredentialConcurrencySnapshot(manager.List(), "cap-stream-model")["cap-stream-a"]; usage.InFlight != 0 {
		t.Fatalf("in-flight after the stream drained = %d, want 0", usage.InFlight)
	}

	// The slot is free again, so the next request must be admitted.
	next, errNext := manager.ExecuteStream(context.Background(), []string{"cap-stream"}, cliproxyexecutor.Request{Model: "cap-stream-model"}, cliproxyexecutor.Options{Stream: true})
	if errNext != nil {
		t.Fatalf("third stream error = %v, want nil", errNext)
	}
	waitCapCall(t, executor.started)
	for range next.Chunks {
	}
}

// An explicit 0 means "no cap", which is how a credential that must never be
// throttled is expressed.
func TestCredentialCapZeroAdmitsUnlimitedRequests(t *testing.T) {
	manager, executor := newCapTestManager(t, "cap-off", map[string]any{
		"cap-off-a": 0,
	})
	manager.credentialCapQueueWait = 100 * time.Millisecond
	manager.credentialCapPollInterval = 5 * time.Millisecond

	results := make(chan error, 3)
	for range 3 {
		go func() {
			_, errExecute := manager.Execute(context.Background(), []string{"cap-off"}, cliproxyexecutor.Request{Model: "cap-off-model"}, cliproxyexecutor.Options{})
			results <- errExecute
		}()
	}
	for range 3 {
		if got := waitCapCall(t, executor.started); got != "cap-off-a" {
			t.Fatalf("call landed on %s, want cap-off-a", got)
		}
	}
	close(executor.gate)
	for range 3 {
		if errExecute := <-results; errExecute != nil {
			t.Fatalf("execution error = %v, want nil", errExecute)
		}
	}
	if usage := manager.CredentialConcurrencySnapshot(manager.List(), "")["cap-off-a"]; usage.Limit != 0 {
		t.Fatalf("snapshot limit = %d, want 0 (disabled)", usage.Limit)
	}
}

// A provider default applies to a credential that has no explicit cap, which is
// what makes the feature work without rewriting existing auth files.
func TestCredentialCapUsesTheProviderDefault(t *testing.T) {
	manager, executor := newCapTestManager(t, "zcode-default", map[string]any{
		"zcode-default-a": nil,
	})
	manager.credentialCapQueueWait = 100 * time.Millisecond
	manager.credentialCapPollInterval = 5 * time.Millisecond

	results := make(chan error, 4)
	for range 4 {
		go func() {
			_, errExecute := manager.Execute(context.Background(), []string{"zcode-default"}, cliproxyexecutor.Request{Model: "zcode-default-model"}, cliproxyexecutor.Options{})
			results <- errExecute
		}()
	}
	for range 3 {
		waitCapCall(t, executor.started)
	}
	if usage := manager.CredentialConcurrencySnapshot(manager.List(), "zcode-default-model")["zcode-default-a"]; usage.InFlight != 3 || usage.Limit != 3 {
		t.Fatalf("snapshot = %+v, want in-flight 3 of limit 3", usage)
	}

	// The fourth request must be refused while the first three are still in
	// flight, so read its result before releasing the gate. Releasing first would
	// only prove that the queue eventually admits it, which is a different rule.
	var errFourth error
	select {
	case errFourth = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the fourth request to be refused")
	}
	var busyErr *HomeConcurrencyBusyError
	if !errors.As(errFourth, &busyErr) {
		t.Fatalf("fourth request error = %v, want a *HomeConcurrencyBusyError", errFourth)
	}

	close(executor.gate)
	for range 3 {
		if errExecute := <-results; errExecute != nil {
			t.Fatalf("admitted request error = %v, want nil", errExecute)
		}
	}
	if usage := manager.CredentialConcurrencySnapshot(manager.List(), "zcode-default-model")["zcode-default-a"]; usage.InFlight != 0 {
		t.Fatalf("in-flight after every request finished = %d, want 0", usage.InFlight)
	}
}

func TestParseAuthModelMaxConcurrency(t *testing.T) {
	list := []any{
		map[string]any{"model": "GLM-5.3", "max_concurrency": 1},
		map[string]any{"model": "glm-5.3-flash", "max_concurrency": "20"},
		map[string]any{"model": "", "max_concurrency": 5},
		map[string]any{"model": "broken", "max_concurrency": -1},
		map[string]any{"model": "glm-5.3", "max_concurrency": 4},
	}
	tests := []struct {
		name string
		raw  any
		want map[string]int
	}{
		{name: "nil is empty", raw: nil, want: map[string]int{}},
		{name: "list folds case and keeps the last duplicate", raw: list, want: map[string]int{"glm-5.3": 4, "glm-5.3-flash": 20}},
		{name: "object shape is accepted", raw: map[string]any{"glm-5.3": 2}, want: map[string]int{"glm-5.3": 2}},
		{name: "json string is accepted", raw: `[{"model":"glm-5.3","max_concurrency":6}]`, want: map[string]int{"glm-5.3": 6}},
		{name: "empty string is empty", raw: "  ", want: map[string]int{}},
		{name: "zero means unlimited", raw: []any{map[string]any{"model": "glm-5.3", "max_concurrency": 0}}, want: map[string]int{"glm-5.3": 0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, errParse := ParseAuthModelMaxConcurrency(test.raw)
			if errParse != nil {
				t.Fatalf("ParseAuthModelMaxConcurrency(%v) error = %v", test.raw, errParse)
			}
			if len(got) != len(test.want) {
				t.Fatalf("limits = %#v, want %#v", got, test.want)
			}
			for model, wantLimit := range test.want {
				if got[model] != wantLimit {
					t.Fatalf("limits[%s] = %d, want %d (all: %#v)", model, got[model], wantLimit, got)
				}
			}
		})
	}
	if _, errParse := ParseAuthModelMaxConcurrency(42); errParse == nil {
		t.Fatal("a scalar table must be rejected")
	}
}

func TestCredentialConcurrencyLimitForModelFallsBackInOrder(t *testing.T) {
	auth := &Auth{
		ID:       "cap-model-resolution",
		Provider: "zcode-bigmodel",
		Metadata: map[string]any{
			AttributeModelMaxConcurrency: []any{
				map[string]any{"model": "glm-5.3", "max_concurrency": 1},
				map[string]any{"model": "glm-5.3-flash", "max_concurrency": 0},
			},
		},
	}
	manager := NewManager(nil, nil, nil)

	if got := manager.credentialConcurrencyLimitForModel(auth, "GLM-5.3"); got != 1 {
		t.Fatalf("cap for glm-5.3 = %d, want 1", got)
	}
	if got := manager.credentialConcurrencyLimitForModel(auth, "glm-5.3-flash"); got != 0 {
		t.Fatalf("cap for glm-5.3-flash = %d, want 0 (unlimited)", got)
	}
	if got := manager.credentialConcurrencyLimitForModel(auth, "glm-5.4"); got != 3 {
		t.Fatalf("cap for an unlisted model = %d, want the zcode default 3", got)
	}

	auth.Metadata[AttributeMaxConcurrency] = 7
	if got := manager.credentialConcurrencyLimitForModel(auth, "glm-5.4"); got != 7 {
		t.Fatalf("unlisted model must inherit the scalar cap, got %d want 7", got)
	}
	if got := manager.credentialConcurrencyLimitForModel(auth, "glm-5.3"); got != 1 {
		t.Fatalf("a listed model must win over the scalar cap, got %d want 1", got)
	}
}

// A cap on one model must not consume another model's slots: the upstream counts
// concurrency per model, so a credential that is full on glm-5.3 still has room
// for glm-5.3-flash.
func TestCredentialCapIsolatesModels(t *testing.T) {
	manager, _ := newCapTestManager(t, "zcode-models", map[string]any{"zcode-models-a": nil})
	manager.credentialCapQueueWait = 20 * time.Millisecond
	manager.credentialCapPollInterval = time.Millisecond

	auth := manager.List()[0]
	auth.Metadata[AttributeModelMaxConcurrency] = []any{
		map[string]any{"model": "glm-5.3", "max_concurrency": 1},
		map[string]any{"model": "glm-5.3-flash", "max_concurrency": 2},
	}

	hold := func(model string) (context.Context, *credentialCapLedger) {
		t.Helper()
		ledger := manager.newCredentialCapLedger()
		return withCredentialCapLedger(context.Background(), ledger), ledger
	}

	ctxFirst, ledgerFirst := hold("glm-5.3")
	if !manager.holdCredentialSlot(ctxFirst, auth, "glm-5.3") {
		t.Fatal("the first glm-5.3 request must be admitted")
	}
	ctxSecond, ledgerSecond := hold("glm-5.3")
	if manager.holdCredentialSlot(ctxSecond, auth, "glm-5.3") {
		t.Fatal("the second glm-5.3 request must be refused at a cap of 1")
	}
	ctxFlash, ledgerFlash := hold("glm-5.3-flash")
	if !manager.holdCredentialSlot(ctxFlash, auth, "glm-5.3-flash") {
		t.Fatal("glm-5.3-flash must not be blocked by a saturated glm-5.3")
	}
	if !manager.credentialCapSaturated(ctxSecond, auth, "glm-5.3") {
		t.Fatal("glm-5.3 must read as saturated")
	}
	if manager.credentialCapSaturated(ctxFlash, auth, "glm-5.3-flash") {
		t.Fatal("glm-5.3-flash must not read as saturated")
	}

	ledgerFirst.release()
	if !manager.holdCredentialSlot(ctxSecond, auth, "glm-5.3") {
		t.Fatal("releasing the first slot must admit the queued glm-5.3 request")
	}
	ledgerSecond.release()
	ledgerFlash.release()
}

// Pressure is per model as well: one saturated model must not route every request
// through the legacy scheduler path.
func TestCredentialCapPressureIsPerModel(t *testing.T) {
	manager, _ := newCapTestManager(t, "zcode-pressure", map[string]any{"zcode-pressure-a": nil})
	// Pressure reads the stored auths, not the clone List returns, so the table
	// has to land on the record the manager iterates.
	manager.mu.Lock()
	stored := manager.auths["zcode-pressure-a"]
	manager.mu.Unlock()
	if stored == nil {
		t.Fatal("stored auth zcode-pressure-a missing")
	}
	auth := stored
	auth.Metadata[AttributeModelMaxConcurrency] = []any{
		map[string]any{"model": "glm-5.3", "max_concurrency": 1},
	}

	ledger := manager.newCredentialCapLedger()
	ctx := withCredentialCapLedger(context.Background(), ledger)
	if !manager.holdCredentialSlot(ctx, auth, "glm-5.3") {
		t.Fatal("the first glm-5.3 request must be admitted")
	}
	if !manager.credentialCapPressure([]string{"zcode-pressure"}, "glm-5.3") {
		t.Fatal("pressure must report a saturated model")
	}
	if manager.credentialCapPressure([]string{"zcode-pressure"}, "glm-5.4") {
		t.Fatal("pressure must not report an unrelated model as saturated")
	}
	ledger.release()
}
