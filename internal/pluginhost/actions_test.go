package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// newActionHost registers one plugin that declares a single POST route plus the
// given actions, and returns the host with its action table built.
func newActionHost(t *testing.T, pluginID string, route string, handler managementHandlerFunc, actions ...pluginapi.ManagementAction) *Host {
	t.Helper()
	plugin := &managementPluginDouble{
		routes:  []pluginapi.ManagementRoute{{Method: http.MethodPost, Path: route, Handler: handler}},
		actions: actions,
	}
	host := newHostWithRecords(capabilityRecord{
		id:       pluginID,
		priority: 1,
		plugin:   pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ManagementAPI: plugin}},
	})
	host.RegisterManagementRoutes(context.Background(), nil)
	return host
}

func TestRegisterManagementActionsResolveDeclaredRoutes(t *testing.T) {
	host := newActionHost(t, "alpha", "/plugins/alpha/scan",
		managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return pluginapi.ManagementResponse{Body: []byte(`{"status":"ok"}`)}, nil
		}),
		pluginapi.ManagementAction{Key: "alpha.scan", Title: "Scan", Path: "plugins/alpha/scan"},
		// Points at a route this plugin never declared.
		pluginapi.ManagementAction{Key: "alpha.missing", Title: "Missing", Path: "/plugins/alpha/nope"},
		// Unusable key.
		pluginapi.ManagementAction{Key: "  ", Title: "Blank", Path: "/plugins/alpha/scan"},
	)

	actions := host.RegisteredActions()
	if len(actions) != 1 {
		t.Fatalf("RegisteredActions() = %#v, want only alpha.scan", actions)
	}
	got := actions[0]
	if got.PluginID != "alpha" || got.Action.Key != "alpha.scan" {
		t.Fatalf("action = %#v, want alpha.scan owned by alpha", got)
	}
	if got.Action.Method != http.MethodPost || got.Action.Path != "/v0/management/plugins/alpha/scan" {
		t.Fatalf("normalized action = %#v, want POST /v0/management/plugins/alpha/scan", got.Action)
	}
	if got.Action.Title != "Scan" {
		t.Fatalf("title = %q, want Scan", got.Action.Title)
	}
}

func TestRegisterManagementActionsKeepTheHigherPriorityPlugin(t *testing.T) {
	high := &managementPluginDouble{
		routes: []pluginapi.ManagementRoute{{Method: http.MethodPost, Path: "/plugins/high/run", Handler: managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return pluginapi.ManagementResponse{Body: []byte("high")}, nil
		})}},
		actions: []pluginapi.ManagementAction{{Key: "shared.run", Path: "/plugins/high/run"}},
	}
	low := &managementPluginDouble{
		routes: []pluginapi.ManagementRoute{{Method: http.MethodPost, Path: "/plugins/low/run", Handler: managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return pluginapi.ManagementResponse{Body: []byte("low")}, nil
		})}},
		actions: []pluginapi.ManagementAction{{Key: "shared.run", Path: "/plugins/low/run"}},
	}
	host := newHostWithRecords(
		capabilityRecord{id: "low", priority: 1, plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ManagementAPI: low}}},
		capabilityRecord{id: "high", priority: 10, plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ManagementAPI: high}}},
	)
	host.RegisterManagementRoutes(context.Background(), nil)

	run, errRun := host.RunAction(context.Background(), "shared.run", nil)
	if errRun != nil {
		t.Fatalf("RunAction() error = %v", errRun)
	}
	if run.Action.PluginID != "high" {
		t.Fatalf("action owner = %q, want high", run.Action.PluginID)
	}
	if string(run.Response.Body) != "high" {
		t.Fatalf("response body = %q, want the high-priority plugin's handler", run.Response.Body)
	}
}

func TestRunActionUnknownKey(t *testing.T) {
	host := newActionHost(t, "alpha", "/plugins/alpha/scan",
		managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return pluginapi.ManagementResponse{}, nil
		}),
	)
	if _, errRun := host.RunAction(context.Background(), "alpha.absent", nil); !errors.Is(errRun, ErrActionNotFound) {
		t.Fatalf("RunAction() error = %v, want ErrActionNotFound", errRun)
	}
}

func TestRunActionLongRunningReturnsAJobAndReportsProgress(t *testing.T) {
	reported := make(chan struct{})
	release := make(chan struct{})
	var jobID string
	var host *Host
	handler := managementHandlerFunc(func(_ context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
		jobID = req.JobID
		progress, errMarshal := json.Marshal(pluginapi.HostJobProgressRequest{
			JobID:    req.JobID,
			Progress: 0.5,
			Message:  "half way",
		})
		if errMarshal != nil {
			return pluginapi.ManagementResponse{}, errMarshal
		}
		if _, errProgress := host.callHostJobProgress(withHostCallbackPluginID(context.Background(), "alpha"), progress); errProgress != nil {
			return pluginapi.ManagementResponse{}, errProgress
		}
		close(reported)
		<-release
		return pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       []byte(`{"status":"ok"}`),
		}, nil
	})
	host = newActionHost(t, "alpha", "/plugins/alpha/scan", handler,
		pluginapi.ManagementAction{Key: "alpha.scan", Title: "Scan", Path: "/plugins/alpha/scan", LongRunning: true},
	)

	run, errRun := host.RunAction(context.Background(), "alpha.scan", nil)
	if errRun != nil {
		t.Fatalf("RunAction() error = %v", errRun)
	}
	if run.Job == nil {
		t.Fatal("RunAction() returned no job for a long-running action")
	}
	if run.Job.State != JobStateRunning {
		t.Fatalf("job state = %q, want running", run.Job.State)
	}

	<-reported
	if jobID != run.Job.ID {
		t.Fatalf("plugin saw job id %q, want %q", jobID, run.Job.ID)
	}
	midway := waitForJobProgress(t, host, run.Job.ID, 0.5)
	if midway.Message != "half way" {
		t.Fatalf("job message = %q, want the plugin-reported message", midway.Message)
	}

	close(release)
	done := waitForJob(t, host, run.Job.ID)
	if done.State != JobStateDone {
		t.Fatalf("job state = %q, want done", done.State)
	}
	if done.Progress != 1 {
		t.Fatalf("job progress = %v, want 1", done.Progress)
	}
	if string(done.Result) != `{"status":"ok"}` {
		t.Fatalf("job result = %s, want the plugin response body", done.Result)
	}
}

func TestRunActionJobMarksAPluginErrorAsFailed(t *testing.T) {
	host := newActionHost(t, "alpha", "/plugins/alpha/scan",
		managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return pluginapi.ManagementResponse{StatusCode: http.StatusBadGateway, Body: []byte(`{"status":"error"}`)}, nil
		}),
		pluginapi.ManagementAction{Key: "alpha.scan", Path: "/plugins/alpha/scan", LongRunning: true},
	)

	record, okAction := host.lookupAction("alpha.scan")
	if !okAction {
		t.Fatal("lookupAction() found no action")
	}
	job, jobCtx := host.jobs.start(record.pluginID, record.action.Key, record.action.Title)
	host.runActionJob(jobCtx, job, record, pluginapi.ManagementRequest{Method: record.action.Method, Path: record.route.route.Path})

	got, okJob := host.Job(job.ID)
	if !okJob {
		t.Fatal("job disappeared")
	}
	if got.State != JobStateFailed || got.Error == "" {
		t.Fatalf("job = %#v, want failed with an error", got)
	}
	if string(got.Result) != `{"status":"error"}` {
		t.Fatalf("job result = %s, want the plugin error body", got.Result)
	}
}

func TestJobCallbacksRejectForeignAndFinishedJobs(t *testing.T) {
	host := New()
	job, _ := host.jobs.start("alpha", "alpha.scan", "Scan")
	request, errMarshal := json.Marshal(pluginapi.HostJobProgressRequest{JobID: job.ID, Progress: 0.4})
	if errMarshal != nil {
		t.Fatalf("marshal: %v", errMarshal)
	}

	if _, errProgress := host.callHostJobProgress(withHostCallbackPluginID(context.Background(), "beta"), request); errProgress == nil {
		t.Fatal("callHostJobProgress() accepted a foreign plugin")
	}
	if _, errProgress := host.callHostJobProgress(withHostCallbackPluginID(context.Background(), "alpha"), request); errProgress != nil {
		t.Fatalf("callHostJobProgress() rejected the owning plugin: %v", errProgress)
	}
	got, _ := host.Job(job.ID)
	if got.Progress != 0.4 {
		t.Fatalf("progress = %v, want 0.4", got.Progress)
	}

	host.jobs.finish(job.ID, "alpha", JobStateDone, nil, "")
	if _, errProgress := host.callHostJobProgress(withHostCallbackPluginID(context.Background(), "alpha"), request); errProgress == nil {
		t.Fatal("callHostJobProgress() accepted an update for a finished job")
	}
	got, _ = host.Job(job.ID)
	if got.State != JobStateDone || got.Progress != 1 {
		t.Fatalf("finished job = %#v, want done at progress 1", got)
	}
}

func TestJobLogAppendsLines(t *testing.T) {
	host := New()
	job, _ := host.jobs.start("alpha", "alpha.scan", "Scan")
	request, errMarshal := json.Marshal(pluginapi.HostJobLogRequest{JobID: job.ID, Line: "checked account 1\n"})
	if errMarshal != nil {
		t.Fatalf("marshal: %v", errMarshal)
	}
	if _, errLog := host.callHostJobLog(withHostCallbackPluginID(context.Background(), "alpha"), request); errLog != nil {
		t.Fatalf("callHostJobLog() error = %v", errLog)
	}
	got, _ := host.Job(job.ID)
	if len(got.Logs) != 1 || got.Logs[0] != "checked account 1" {
		t.Fatalf("logs = %#v, want one trimmed line", got.Logs)
	}
}

func TestCancelJobOnlyStopsRunningJobs(t *testing.T) {
	host := New()
	job, _ := host.jobs.start("alpha", "alpha.scan", "Scan")
	if !host.CancelJob(job.ID) {
		t.Fatal("CancelJob() = false, want true for a running job")
	}
	if host.CancelJob(job.ID) {
		t.Fatal("CancelJob() = true, want false for an already finished job")
	}
	got, _ := host.Job(job.ID)
	if got.State != JobStateCancelled {
		t.Fatalf("job state = %q, want cancelled", got.State)
	}
}

func TestUnloadingAPluginDropsItsActions(t *testing.T) {
	host := newActionHost(t, "alpha", "/plugins/alpha/scan",
		managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Body: []byte(`{"status":"ok"}`)}, nil
		}),
		pluginapi.ManagementAction{Key: "alpha.scan", Path: "/plugins/alpha/scan"},
	)
	if len(host.RegisteredActions()) != 1 {
		t.Fatalf("RegisteredActions() = %#v, want the declared action", host.RegisteredActions())
	}

	// UnloadPlugin and the hot-reload replacement path both purge a plugin's
	// runtime state through this method.
	host.mu.Lock()
	host.removePluginRuntimeStateLocked("alpha")
	host.mu.Unlock()

	if actions := host.RegisteredActions(); len(actions) != 0 {
		t.Fatalf("RegisteredActions() = %#v, want none once the plugin's runtime state is gone", actions)
	}
	if _, errRun := host.RunAction(context.Background(), "alpha.scan", nil); !errors.Is(errRun, ErrActionNotFound) {
		t.Fatalf("RunAction() error = %v, want ErrActionNotFound", errRun)
	}
}

func TestRegisteredActionsSkipFusedPlugins(t *testing.T) {
	host := newActionHost(t, "alpha", "/plugins/alpha/scan",
		managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
			return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Body: []byte(`{"status":"ok"}`)}, nil
		}),
		pluginapi.ManagementAction{Key: "alpha.scan", Path: "/plugins/alpha/scan"},
	)
	host.fusePlugin("alpha", "ManagementHandler.HandleManagement", errors.New("boom"))

	// A fused plugin's handler never runs again, so its actions must not be
	// offered: the list has to agree with RunAction.
	if actions := host.RegisteredActions(); len(actions) != 0 {
		t.Fatalf("RegisteredActions() = %#v, want none for a fused plugin", actions)
	}
	if _, errRun := host.RunAction(context.Background(), "alpha.scan", nil); !errors.Is(errRun, ErrActionNotFound) {
		t.Fatalf("RunAction() error = %v, want ErrActionNotFound", errRun)
	}
}

func TestRunActionReportsAPluginThatNoLongerServesTheAction(t *testing.T) {
	handler := managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
		return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Body: []byte(`{"status":"ok"}`)}, nil
	})
	host := newActionHost(t, "alpha", "/plugins/alpha/scan", handler,
		pluginapi.ManagementAction{Key: "alpha.scan", Path: "/plugins/alpha/scan"},
		pluginapi.ManagementAction{Key: "alpha.job", Path: "/plugins/alpha/scan", LongRunning: true},
	)

	// Simulate the plugin being replaced by a new build: the route table still
	// holds the old identity, so the host stops calling the handler. Reporting
	// that as success would claim work that never happened.
	setHostSnapshotForTest(host, true, capabilityRecord{id: "alpha", priority: 1, version: "replacement"})

	if _, errRun := host.RunAction(context.Background(), "alpha.scan", nil); errRun == nil {
		t.Fatal("RunAction() reported success for a plugin that no longer serves the action")
	}

	run, errRun := host.RunAction(context.Background(), "alpha.job", nil)
	if errRun != nil {
		t.Fatalf("RunAction() error = %v", errRun)
	}
	done := waitForJob(t, host, run.Job.ID)
	if done.State != JobStateFailed || done.Error == "" {
		t.Fatalf("job = %#v, want failed with an error", done)
	}
}

// waitForJobProgress polls until the job reports the wanted progress, yielding
// between checks so it settles as soon as the reporting goroutine runs.
func waitForJobProgress(t *testing.T, host *Host, id string, want float64) Job {
	t.Helper()
	for range 100000 {
		job, okJob := host.Job(id)
		if !okJob {
			t.Fatalf("job %s disappeared", id)
		}
		if job.Progress == want {
			return job
		}
		runtime.Gosched()
	}
	t.Fatalf("job %s never reported progress %v", id, want)
	return Job{}
}

// waitForJob polls until the job leaves the running state.
func waitForJob(t *testing.T, host *Host, id string) Job {
	t.Helper()
	for range 100000 {
		job, okJob := host.Job(id)
		if !okJob {
			t.Fatalf("job %s disappeared", id)
		}
		if job.State != JobStateRunning {
			return job
		}
		runtime.Gosched()
	}
	t.Fatalf("job %s never left the running state", id)
	return Job{}
}
