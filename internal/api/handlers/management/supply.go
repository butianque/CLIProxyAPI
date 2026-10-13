package management

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// supplyStatusPayload describes the account-supply service to management
// clients. It carries no credential value: only whether the service is usable,
// which kinds are configured, and whether the credential store is locked.
type supplyStatusPayload struct {
	Enabled bool     `json:"enabled"`
	Kinds   []string `json:"kinds"`
	Locked  bool     `json:"locked"`
}

func supplyStatus() supplyStatusPayload {
	payload := supplyStatusPayload{Kinds: []string{}}
	service := supply.Default()
	if service == nil {
		return payload
	}
	status, errStatus := service.Status(context.Background())
	if errStatus != nil {
		return payload
	}
	payload.Enabled = status.Enabled
	payload.Locked = status.Locked
	payload.Kinds = make([]string, 0, len(status.Kinds))
	for _, kind := range status.Kinds {
		payload.Kinds = append(payload.Kinds, string(kind))
	}
	return payload
}

// GetSupplyStatus reports whether the account-supply service is usable and
// which kinds are configured.
func (h *Handler) GetSupplyStatus(c *gin.Context) {
	c.JSON(http.StatusOK, supplyStatus())
}