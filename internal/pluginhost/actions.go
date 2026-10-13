package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

// The action table turns plugin-owned management routes into named,
// user-triggerable operations. A route is transport; an action is the business
// unit ("register an account", "scan rewards") that the management UI can list
// and trigger without knowing which plugin implements it or what its own HTML
// looks like.

// ErrActionNotFound reports that no active plugin exposes the action key.
var ErrActionNotFound = errors.New("management action not found")

// managementActionRecord is one registered action plus the route it dispatches
// to.
type managementActionRecord struct {
	pluginID string
	path     string
	version  string
	action   pluginapi.ManagementAction
	route    managementRouteRecord
}

// RegisteredActionInfo describes one action exposed by an active plugin.
type RegisteredActionInfo struct {
	PluginID string
	Action   pluginapi.ManagementAction
}

// ActionRun is the outcome of triggering an action: either a response from a
// synchronous action, or a job running in the background.
type ActionRun struct {
	Action   RegisteredActionInfo
	Job      *Job
	Response pluginapi.ManagementResponse
}

// normalizeManagementAction validates one declared action and resolves the route
// key it dispatches to. It returns false when the action must be skipped.
func normalizeManagementAction(item pluginapi.ManagementAction) (pluginapi.ManagementAction, string, bool) {
	key := strings.TrimSpace(item.Key)
	if key == "" || strings.ContainsFunc(key, unicode.IsSpace) {
		return pluginapi.ManagementAction{}, "", false
	}
	method, okMethod := normalizeManagementMethod(item.Method, http.MethodPost)
	if !okMethod {
		return pluginapi.ManagementAction{}, "", false
	}
	path, okPath := normalizeManagementPath(item.Path)
	if !okPath {
		return pluginapi.ManagementAction{}, "", false
	}
	item.Key = key
	if item.Title = strings.TrimSpace(item.Title); item.Title == "" {
		item.Title = key
	}
	item.Method = method
	item.Path = path
	item.Params = normalizeActionParams(item.Params)
	return item, managementRouteKey(method, path), true
}

// normalizeActionParams drops unnamed inputs and gives every remaining one a
// concrete type, so the management UI can render the form without guessing.
func normalizeActionParams(params []pluginapi.ActionParam) []pluginapi.ActionParam {
	if len(params) == 0 {
		return nil
	}
	out := make([]pluginapi.ActionParam, 0, len(params))
	for _, param := range params {
		param.Name = strings.TrimSpace(param.Name)
		if param.Name == "" {
			continue
		}
		param.Title = strings.TrimSpace(param.Title)
		param.Type = strings.ToLower(strings.TrimSpace(param.Type))
		if param.Type == "" {
			param.Type = "string"
		}
		out = append(out, param)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// registerManagementAction adds one action to the table. An action is skipped
// when its key is unusable, when the plugin never registered the route it points
// at, or when another plugin already owns the key.
func registerManagementAction(actions map[string]managementActionRecord, routes map[string]managementRouteRecord, pluginRoutes map[string]struct{}, record capabilityRecord, item pluginapi.ManagementAction) {
	action, routeKey, okAction := normalizeManagementAction(item)
	if !okAction {
		log.Warnf("pluginhost: plugin %s declared invalid management action %q", record.id, item.Key)
		return
	}
	if _, okRoute := pluginRoutes[routeKey]; !okRoute {
		log.Warnf("pluginhost: plugin %s management action %s points at the undeclared route %s", record.id, action.Key, routeKey)
		return
	}
	if _, exists := actions[action.Key]; exists {
		log.Warnf("pluginhost: plugin %s management action %s conflicts with a higher-priority plugin and was skipped", record.id, action.Key)
		return
	}
	actions[action.Key] = managementActionRecord{
		pluginID: record.id,
		path:     record.path,
		version:  record.version,
		action:   action,
		route:    routes[routeKey],
	}
}

// RegisteredActions lists the actions the current plugin set exposes, ordered by
// key so the management UI renders a stable list.
func (h *Host) RegisteredActions() []RegisteredActionInfo {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	out := make([]RegisteredActionInfo, 0, len(h.managementActions))
	for _, record := range h.managementActions {
		// A fused plugin's handlers no longer run, so listing its actions would
		// offer the panel operations that can only fail.
		if _, fused := h.fused[record.pluginID]; fused {
			continue
		}
		out = append(out, RegisteredActionInfo{PluginID: record.pluginID, Action: record.action})
	}
	h.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Action.Key < out[j].Action.Key })
	return out
}

// RunAction triggers one plugin action. A long-running action returns a job the
// caller polls; a synchronous action returns the plugin's own response.
func (h *Host) RunAction(ctx context.Context, key string, body []byte) (ActionRun, error) {
	record, okAction := h.lookupAction(key)
	if !okAction {
		return ActionRun{}, ErrActionNotFound
	}
	info := RegisteredActionInfo{PluginID: record.pluginID, Action: record.action}
	req := pluginapi.ManagementRequest{
		Method:  record.action.Method,
		Path:    record.route.route.Path,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		Body:    body,
	}
	if record.action.LongRunning {
		job, jobCtx := h.jobs.start(record.pluginID, record.action.Key, record.action.Title)
		go h.runActionJob(jobCtx, job, record, req)
		return ActionRun{Action: info, Job: &job}, nil
	}
	resp, errHandle := h.callManagementHandler(ctx, record.route, req)
	if errHandle != nil {
		return ActionRun{}, errHandle
	}
	if managementResponseSkipped(resp) {
		return ActionRun{}, fmt.Errorf("plugin %s no longer serves action %s", record.pluginID, record.action.Key)
	}
	if managementResponseEscapesHTML(record.route.schemaVersion) {
		resp.Body = escapeManagementResponseBody(resp)
	}
	return ActionRun{Action: info, Response: resp}, nil
}

// runActionJob executes one long-running action and records its outcome. The job
// id is handed to the plugin so its progress and log calls can name the job.
func (h *Host) runActionJob(ctx context.Context, job Job, record managementActionRecord, req pluginapi.ManagementRequest) {
	req.JobID = job.ID
	resp, errHandle := h.callManagementHandler(ctx, record.route, req)
	if errHandle != nil {
		h.jobs.finish(job.ID, record.pluginID, JobStateFailed, nil, errHandle.Error())
		return
	}
	if managementResponseSkipped(resp) {
		// The plugin was unloaded or replaced while the job ran; reporting
		// success here would claim work that never happened.
		h.jobs.finish(job.ID, record.pluginID, JobStateFailed, nil, "the plugin no longer serves this action")
		return
	}
	body := resp.Body
	if managementResponseEscapesHTML(record.route.schemaVersion) {
		body = escapeManagementResponseBody(resp)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		// The plugin answered with an error body: the job failed, but that body
		// is still the most useful thing to show the operator.
		h.jobs.finish(job.ID, record.pluginID, JobStateFailed, jobResult(body), fmt.Sprintf("plugin returned HTTP %d", resp.StatusCode))
		return
	}
	h.jobs.finish(job.ID, record.pluginID, JobStateDone, jobResult(body), "")
}

// managementResponseSkipped reports that the plugin handler never ran. The host
// answers with the zero response when the plugin was unloaded or replaced
// between resolving the route and calling it, and that must not be reported as
// a successful action.
func managementResponseSkipped(resp pluginapi.ManagementResponse) bool {
	return resp.StatusCode == 0 && len(resp.Body) == 0
}

// Jobs lists the retained jobs, newest first.
func (h *Host) Jobs() []Job {
	if h == nil {
		return nil
	}
	return h.jobs.list()
}

// Job returns one job for polling.
func (h *Host) Job(id string) (Job, bool) {
	if h == nil {
		return Job{}, false
	}
	return h.jobs.get(strings.TrimSpace(id))
}

// CancelJob asks a running job to stop and reports whether it was running.
func (h *Host) CancelJob(id string) bool {
	if h == nil {
		return false
	}
	return h.jobs.cancel(strings.TrimSpace(id))
}

func (h *Host) lookupAction(key string) (managementActionRecord, bool) {
	if h == nil {
		return managementActionRecord{}, false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return managementActionRecord{}, false
	}
	h.mu.Lock()
	record, okAction := h.managementActions[key]
	h.mu.Unlock()
	if !okAction || record.route.route.Handler == nil || h.isPluginFused(record.pluginID) {
		return managementActionRecord{}, false
	}
	return record, true
}
