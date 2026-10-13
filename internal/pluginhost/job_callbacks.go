package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// The job callbacks let a plugin report the progress of the long-running action
// it is executing. The plugin names the job explicitly because it may run the
// same handler both as a job and as a direct call; the host then checks that the
// job belongs to the calling plugin before accepting the update.

// callHostJobProgress records how far the plugin's job has progressed.
func (h *Host) callHostJobProgress(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostJobProgressRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host job progress request: %w", errUnmarshal)
	}
	jobID := strings.TrimSpace(req.JobID)
	if jobID == "" {
		return nil, errors.New("host job progress: job_id is required")
	}
	if !h.jobs.progress(jobID, hostCallbackPluginIDFromContext(ctx), req.Progress, req.Message) {
		return nil, fmt.Errorf("host job progress: job %q is not running for this plugin", jobID)
	}
	return marshalRPCResult(pluginapi.HostJobProgressResponse{Recorded: true})
}

// callHostJobLog appends one line to the plugin's job log.
func (h *Host) callHostJobLog(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostJobLogRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host job log request: %w", errUnmarshal)
	}
	jobID := strings.TrimSpace(req.JobID)
	if jobID == "" {
		return nil, errors.New("host job log: job_id is required")
	}
	if !h.jobs.logLine(jobID, hostCallbackPluginIDFromContext(ctx), req.Line) {
		return nil, fmt.Errorf("host job log: job %q is not running for this plugin", jobID)
	}
	return marshalRPCResult(pluginapi.HostJobLogResponse{Logged: true})
}
