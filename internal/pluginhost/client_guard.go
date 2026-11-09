package pluginhost

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// pluginCallLimitLogInterval bounds how often a saturated limiter logs. The
// rejection path runs on every shed request, so an unthrottled warning would
// turn load shedding into a second load source.
const pluginCallLimitLogInterval = 10 * time.Second

// pluginCallLimiter bounds how many host-to-plugin calls may be in flight at
// once across every loaded plugin.
//
// A plugin call runs inside an uncancellable CGO call, so a request that times
// out keeps its slot until the plugin actually returns. Without a global bound
// those stranded calls pile up until they exhaust threads and swap. The limiter
// never blocks: a call over the limit is rejected immediately and the request is
// shed with HTTP 503.
type pluginCallLimiter struct {
	mu            sync.Mutex
	limit         int
	inflight      int
	lastRejectLog time.Time
}

func newPluginCallLimiter(limit int) *pluginCallLimiter {
	return &pluginCallLimiter{limit: normalizePluginCallLimit(limit)}
}

func normalizePluginCallLimit(limit int) int {
	if limit < 0 {
		return 0
	}
	return limit
}

func (l *pluginCallLimiter) setLimit(limit int) {
	if l == nil {
		return
	}
	limit = normalizePluginCallLimit(limit)
	l.mu.Lock()
	l.limit = limit
	l.mu.Unlock()
}

func (l *pluginCallLimiter) currentLimit() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

// acquire reserves a slot without waiting. It reports false when the limit is
// already reached; the caller must not start the plugin call in that case.
func (l *pluginCallLimiter) acquire(method string) (bool, int) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.limit <= 0 {
		l.inflight++
		return true, 0
	}
	if l.inflight >= l.limit {
		now := time.Now()
		if now.Sub(l.lastRejectLog) >= pluginCallLimitLogInterval {
			l.lastRejectLog = now
			log.Warnf("pluginhost: plugin call limit reached: %d in flight (limit %d), shedding %s", l.inflight, l.limit, method)
		}
		return false, l.limit
	}
	l.inflight++
	return true, l.limit
}

func (l *pluginCallLimiter) release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.inflight > 0 {
		l.inflight--
	}
	l.mu.Unlock()
}

func (l *pluginCallLimiter) inFlight() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inflight
}

// pluginCallLimitError reports a plugin call refused by the global in-flight
// limit. StatusCode makes the request fail with 503 and LoadShed marks it as an
// admission decision: retrying against another credential cannot succeed while
// the limit holds, and no credential may be cooled down for it.
type pluginCallLimitError struct {
	limit  int
	method string
}

func (e *pluginCallLimitError) Error() string {
	if e == nil {
		return "plugin call limit reached"
	}
	return fmt.Sprintf("plugin call limit reached (%d in flight, method %s)", e.limit, e.method)
}

func (e *pluginCallLimitError) StatusCode() int {
	return http.StatusServiceUnavailable
}

func (e *pluginCallLimitError) LoadShed() bool {
	return true
}

type guardedPluginClient struct {
	mu           sync.Mutex
	cond         *sync.Cond
	inner        pluginClient
	instance     *hostCallbackInstance
	limiter      *pluginCallLimiter
	calls        int
	closed       bool
	shutdownDone chan struct{}
}

func newGuardedPluginClient(inner pluginClient, limiter *pluginCallLimiter) *guardedPluginClient {
	instance := pluginCallbackInstance(inner)
	if instance == nil {
		instance = &hostCallbackInstance{}
	}
	client := &guardedPluginClient{inner: inner, instance: instance, limiter: limiter, shutdownDone: make(chan struct{})}
	client.cond = sync.NewCond(&client.mu)
	return client
}

func (c *guardedPluginClient) callbackInstance() *hostCallbackInstance {
	if c == nil {
		return nil
	}
	return c.instance
}

func pluginCallbackInstance(client pluginClient) *hostCallbackInstance {
	if client == nil {
		return nil
	}
	if provider, ok := client.(interface{ callbackInstance() *hostCallbackInstance }); ok {
		return provider.callbackInstance()
	}
	return nil
}

func (c *guardedPluginClient) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	inner, errAcquire := c.acquire()
	if errAcquire != nil {
		return nil, errAcquire
	}
	admitted, limit := c.limiter.acquire(method)
	if !admitted {
		c.release()
		return nil, &pluginCallLimitError{limit: limit, method: method}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	result := make(chan guardedPluginCallResult, 1)
	go func() {
		defer c.release()
		defer c.limiter.release()
		defer func() {
			if recovered := recover(); recovered != nil {
				result <- guardedPluginCallResult{recovered: recovered}
			}
		}()
		response, errCall := inner.Call(ctx, method, request)
		result <- guardedPluginCallResult{response: response, err: errCall}
	}()
	select {
	case callResult := <-result:
		if callResult.recovered != nil {
			panic(callResult.recovered)
		}
		return callResult.response, callResult.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type guardedPluginCallResult struct {
	response  []byte
	err       error
	recovered any
}

func (c *guardedPluginClient) acquire() (pluginClient, error) {
	if c == nil {
		return nil, fmt.Errorf("plugin client is closed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.inner == nil {
		return nil, fmt.Errorf("plugin client is closed")
	}
	c.calls++
	return c.inner, nil
}

func (c *guardedPluginClient) release() {
	c.mu.Lock()
	c.calls--
	if c.calls == 0 {
		c.cond.Broadcast()
	}
	c.mu.Unlock()
}

func (c *guardedPluginClient) Shutdown() {
	c.ShutdownContext(context.Background())
}

// ShutdownContext detaches the client immediately and waits for active calls only
// until ctx is canceled. Detached cleanup continues asynchronously when needed.
func (c *guardedPluginClient) ShutdownContext(ctx context.Context) {
	if c == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	if c.closed {
		done := c.shutdownDone
		c.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
		}
		return
	}
	c.closed = true
	inner := c.inner
	c.inner = nil
	done := c.shutdownDone
	c.mu.Unlock()

	go func() {
		c.mu.Lock()
		for c.calls > 0 {
			c.cond.Wait()
		}
		c.mu.Unlock()
		if inner != nil {
			inner.Shutdown()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}
