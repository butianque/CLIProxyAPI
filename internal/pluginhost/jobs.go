package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// A job is one execution of a long-running plugin action. Triggering such an
// action returns its id immediately instead of holding an HTTP request open for
// minutes, and the caller polls the job for progress. Jobs are deliberately
// process-local: they describe work in flight, not durable history, so they are
// not persisted and the oldest finished job is dropped once the cap is reached.

// Job states.
const (
	JobStateRunning   = "running"
	JobStateDone      = "done"
	JobStateFailed    = "failed"
	JobStateCancelled = "cancelled"
)

const (
	// maxRetainedJobs bounds the in-memory job history.
	maxRetainedJobs = 100
	// maxJobLogLines bounds one job's log so a chatty action cannot grow the
	// process without limit.
	maxJobLogLines = 200
)

// Job is one running or finished instance of a long-running plugin action.
type Job struct {
	// ID identifies the job for polling and cancellation.
	ID string `json:"id"`
	// PluginID is the plugin that owns the action.
	PluginID string `json:"plugin_id"`
	// Key is the action key that started the job.
	Key string `json:"key"`
	// Title is the action's display label, copied so a job list renders without
	// joining against the action table.
	Title string `json:"title,omitempty"`
	// State is running, done, failed or cancelled.
	State string `json:"state"`
	// Progress is the reported completion fraction, 0 to 1.
	Progress float64 `json:"progress"`
	// Message is the latest human-readable status line.
	Message string `json:"message,omitempty"`
	// StartedAt is the Unix start time in seconds.
	StartedAt int64 `json:"started_at"`
	// EndedAt is the Unix finish time in seconds; zero while running.
	EndedAt int64 `json:"ended_at,omitempty"`
	// Result is the plugin's response body once the job finished.
	Result json.RawMessage `json:"result,omitempty"`
	// Error explains a failed job.
	Error string `json:"error,omitempty"`
	// Logs are the lines the plugin appended through host.job.log.
	Logs []string `json:"logs,omitempty"`
}

// jobEntry is a job plus the cancel function of the context its handler runs
// under.
type jobEntry struct {
	job    Job
	cancel context.CancelFunc
}

// jobManager holds the process-local job table. Every method tolerates a nil
// receiver so a Host built without New() degrades to "no jobs" instead of
// panicking.
type jobManager struct {
	mu     sync.Mutex
	next   uint64
	order  []string
	active map[string]*jobEntry
}

func newJobManager() *jobManager {
	return &jobManager{active: make(map[string]*jobEntry)}
}

// start records a new running job and returns it with the context its handler
// must run under.
func (m *jobManager) start(pluginID, key, title string) (Job, context.Context) {
	if m == nil {
		return Job{PluginID: pluginID, Key: key, Title: title, State: JobStateRunning}, context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		m.active = make(map[string]*jobEntry)
	}
	m.next++
	job := Job{
		ID:        fmt.Sprintf("job-%d", m.next),
		PluginID:  pluginID,
		Key:       key,
		Title:     title,
		State:     JobStateRunning,
		StartedAt: time.Now().Unix(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.active[job.ID] = &jobEntry{job: job, cancel: cancel}
	m.order = append(m.order, job.ID)
	m.pruneLocked()
	return job, ctx
}

// progress records a plugin-reported progress update. It rejects an unknown
// job, a job owned by another plugin, and a job that is no longer running, so a
// late or forged update cannot rewrite a finished job.
func (m *jobManager) progress(id, pluginID string, value float64, message string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, okEntry := m.active[id]
	if !okEntry || entry.job.PluginID != pluginID || entry.job.State != JobStateRunning {
		return false
	}
	entry.job.Progress = clampProgress(value)
	if message != "" {
		entry.job.Message = message
	}
	return true
}

// logLine appends one line to a running job's log, dropping the oldest line
// once the cap is reached.
func (m *jobManager) logLine(id, pluginID, line string) bool {
	if m == nil {
		return false
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, okEntry := m.active[id]
	if !okEntry || entry.job.PluginID != pluginID || entry.job.State != JobStateRunning {
		return false
	}
	if len(entry.job.Logs) >= maxJobLogLines {
		entry.job.Logs = append(entry.job.Logs[1:], line)
		return true
	}
	entry.job.Logs = append(entry.job.Logs, line)
	return true
}

// finish closes a running job. A job that already left the running state (a
// cancelled job, or one finished twice) keeps its first terminal state.
func (m *jobManager) finish(id, pluginID, state string, result json.RawMessage, errMessage string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, okEntry := m.active[id]
	if !okEntry || entry.job.PluginID != pluginID || entry.job.State != JobStateRunning {
		return
	}
	entry.job.State = state
	entry.job.EndedAt = time.Now().Unix()
	if state == JobStateDone {
		entry.job.Progress = 1
	}
	if len(result) > 0 {
		entry.job.Result = result
	}
	entry.job.Error = errMessage
	if entry.cancel != nil {
		entry.cancel()
	}
}

// cancel stops a running job. Cancellation is best effort: the job is marked
// cancelled immediately and its handler context is cancelled, but a plugin that
// does not observe cancellation runs on while its late updates are ignored.
func (m *jobManager) cancel(id string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, okEntry := m.active[id]
	if !okEntry || entry.job.State != JobStateRunning {
		return false
	}
	entry.job.State = JobStateCancelled
	entry.job.EndedAt = time.Now().Unix()
	if entry.cancel != nil {
		entry.cancel()
	}
	return true
}

// get returns a copy of one job.
func (m *jobManager) get(id string) (Job, bool) {
	if m == nil {
		return Job{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, okEntry := m.active[id]
	if !okEntry {
		return Job{}, false
	}
	return copyJob(entry.job), true
}

// list returns copies of every retained job, newest first.
func (m *jobManager) list() []Job {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Job, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		entry, okEntry := m.active[m.order[i]]
		if !okEntry {
			continue
		}
		out = append(out, copyJob(entry.job))
	}
	return out
}

// pruneLocked drops the oldest finished jobs beyond the retention cap. It stops
// at the first running job so an in-flight action is never evicted.
func (m *jobManager) pruneLocked() {
	for len(m.order) > maxRetainedJobs {
		entry, okEntry := m.active[m.order[0]]
		if okEntry && entry.job.State == JobStateRunning {
			return
		}
		delete(m.active, m.order[0])
		m.order = m.order[1:]
	}
}

func clampProgress(value float64) float64 {
	if math.IsNaN(value) || value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

// copyJob detaches the slices a caller reads from the manager's own state.
func copyJob(job Job) Job {
	if len(job.Logs) > 0 {
		job.Logs = append([]string(nil), job.Logs...)
	}
	if len(job.Result) > 0 {
		job.Result = append(json.RawMessage(nil), job.Result...)
	}
	return job
}

// jobResult renders a plugin response body as a JSON value. A non-JSON body is
// carried as a string so the result is always valid JSON.
func jobResult(body []byte) json.RawMessage {
	if len(body) == 0 {
		return nil
	}
	if json.Valid(body) {
		return json.RawMessage(body)
	}
	encoded, errMarshal := json.Marshal(string(body))
	if errMarshal != nil {
		return nil
	}
	return json.RawMessage(encoded)
}
