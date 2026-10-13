package management

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// This file is the management surface of the plugin action table. A plugin
// declares named actions and the host aggregates them, so the panel can list and
// trigger operations by name instead of knowing which plugin owns them or
// embedding the plugin's own HTML.
//
// A long-running action is not held open: triggering it returns 202 with a job
// id and the caller polls /jobs/:id for progress.

// pluginActionView is the wire shape of one action. It carries the plugin that
// owns the action so the panel can group them, and the parameter descriptions
// so it can render the form without plugin-specific code.
type pluginActionView struct {
	PluginID    string                  `json:"plugin_id"`
	Key         string                  `json:"key"`
	Title       string                  `json:"title"`
	Description string                  `json:"description,omitempty"`
	Method      string                  `json:"method"`
	Path        string                  `json:"path"`
	Params      []pluginapi.ActionParam `json:"params,omitempty"`
	Destructive bool                    `json:"destructive,omitempty"`
	LongRunning bool                    `json:"long_running,omitempty"`
}

// ListPluginActions reports every action the active plugins expose.
func (h *Handler) ListPluginActions(c *gin.Context) {
	actions := []pluginActionView{}
	if h.pluginHost != nil {
		for _, item := range h.pluginHost.RegisteredActions() {
			actions = append(actions, pluginActionView{
				PluginID:    item.PluginID,
				Key:         item.Action.Key,
				Title:       item.Action.Title,
				Description: item.Action.Description,
				Method:      item.Action.Method,
				Path:        item.Action.Path,
				Params:      item.Action.Params,
				Destructive: item.Action.Destructive,
				LongRunning: item.Action.LongRunning,
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "actions": actions})
}

// TriggerPluginAction runs one action by key. A synchronous action forwards the
// plugin's own response; a long-running action returns 202 and a job.
func (h *Handler) TriggerPluginAction(c *gin.Context) {
	if h.pluginHost == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": "plugin host is unavailable"})
		return
	}
	body, errRead := io.ReadAll(c.Request.Body)
	if errRead != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "failed to read the request body"})
		return
	}
	run, errRun := h.pluginHost.RunAction(c.Request.Context(), c.Param("key"), body)
	if errRun != nil {
		if errors.Is(errRun, pluginhost.ErrActionNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "unknown action"})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": "the action failed"})
		return
	}
	if run.Job != nil {
		c.JSON(http.StatusAccepted, gin.H{"status": "ok", "job": run.Job})
		return
	}
	writePluginResponse(c, run.Response)
}

// ListPluginJobs reports the retained jobs, newest first, so the panel can show
// what is running without polling each job.
func (h *Handler) ListPluginJobs(c *gin.Context) {
	jobs := []pluginhost.Job{}
	if h.pluginHost != nil {
		jobs = h.pluginHost.Jobs()
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "jobs": jobs})
}

// GetPluginJob reports one job for progress polling.
func (h *Handler) GetPluginJob(c *gin.Context) {
	if h.pluginHost == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": "plugin host is unavailable"})
		return
	}
	job, okJob := h.pluginHost.Job(strings.TrimSpace(c.Param("id")))
	if !okJob {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "unknown job"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "job": job})
}

// CancelPluginJob asks a running job to stop. Cancellation is best effort: the
// job leaves the running state at once, and a plugin that does not observe
// cancellation runs on while its late updates are ignored.
func (h *Handler) CancelPluginJob(c *gin.Context) {
	if h.pluginHost == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": "plugin host is unavailable"})
		return
	}
	if !h.pluginHost.CancelJob(strings.TrimSpace(c.Param("id"))) {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "unknown or already finished job"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// writePluginResponse forwards a plugin's own response so an action keeps its
// result shape and status code instead of being rewrapped.
func writePluginResponse(c *gin.Context, resp pluginapi.ManagementResponse) {
	for keyHeader, values := range resp.Headers {
		for _, value := range values {
			c.Writer.Header().Add(keyHeader, value)
		}
	}
	statusCode := resp.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	contentType := resp.Headers.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json; charset=utf-8"
	}
	c.Data(statusCode, contentType, resp.Body)
}
