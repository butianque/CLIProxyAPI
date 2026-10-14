package management

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// This file is the channel surface: the configured sources of identities.
//
// A channel is a label plus a nature plus the connection details that nature
// implies. The label is what a person selects by; the nature is what the host
// switches on, so it decides both the connection form and the shape of the pool
// the channel feeds. Keeping the two apart is what lets a channel be renamed
// without changing how it is reached.
//
// Credential values never cross this surface. A channel names a secret in the
// host secret store, and this surface reports only whether that name exists.

// supplyChannels loads the channel list from the supply state directory.
//
// It is read from disk per request rather than cached: the document is small,
// and a cache here would be a second copy that can drift from what a concurrent
// write just stored.
func (h *Handler) supplyChannels() (*supply.ChannelStore, error) {
	return supply.LoadChannels(supply.ChannelPath(h.supplyStateDir()))
}

// supplyStateDir resolves where the supply state documents live, through the
// same helper startup uses so both name the same directory.
func (h *Handler) supplyStateDir() string {
	configured := ""
	configPath := ""
	if h != nil {
		if h.cfg != nil {
			configured = h.cfg.Supply.WithDefaults().StorageDir
		}
		configPath = h.configFilePath
	}
	return supply.StateDir(filepath.Dir(configPath), configured)
}

// channelView renders one channel for the panel.
//
// secret_present reports whether the named secret exists in the store; the
// value itself is never read here, let alone returned.
func channelView(channel supply.Channel, secretNames []string, storeEnabled bool) gin.H {
	view := gin.H{
		"id":      channel.ID,
		"kind":    string(channel.Kind),
		"label":   channel.Label,
		"nature":  string(channel.Nature),
		"enabled": channel.Enabled,
		"created": channel.Created,
		"updated": channel.Updated,
	}
	if channel.Endpoint != "" {
		view["endpoint"] = channel.Endpoint
	}
	if channel.Account != "" {
		view["account"] = channel.Account
	}
	if channel.Secret != "" {
		view["secret"] = channel.Secret
		view["secret_present"] = storeEnabled && contains(secretNames, channel.Secret)
	}
	if channel.Usage != "" {
		view["usage"] = channel.Usage
	}
	if channel.Domain != "" {
		view["domain"] = channel.Domain
	}
	return view
}

// natureView describes one nature and the kinds it can serve, so the panel
// renders the same set the host enforces instead of a hand-kept copy.
func natureView(nature supply.Nature) gin.H {
	kinds := make([]string, 0, 2)
	for _, kind := range []supply.Kind{supply.KindPhone, supply.KindEmail} {
		if nature.SupportsKind(kind) {
			kinds = append(kinds, string(kind))
		}
	}
	return gin.H{"nature": string(nature), "kinds": kinds}
}

// GetSupplyChannels lists the configured channels. ?kind=phone|email narrows it.
//
// The nature list is returned alongside, because which natures a kind accepts is
// a host rule, and the panel must offer exactly that set.
func (h *Handler) GetSupplyChannels(c *gin.Context) {
	store, errStore := h.supplyChannels()
	if errStore != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	kind := supply.Kind(strings.ToLower(strings.TrimSpace(c.Query("kind"))))
	channels := store.All()
	if kind.Valid() {
		channels = store.List(kind)
	}
	status := secretStatus()
	out := make([]gin.H, 0, len(channels))
	for _, channel := range channels {
		out = append(out, channelView(channel, status.Names, status.Enabled))
	}
	natures := make([]gin.H, 0, len(supply.Natures()))
	for _, nature := range supply.Natures() {
		natures = append(natures, natureView(nature))
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"channels": out,
		"natures":  natures,
	})
}

// PostSupplyChannel creates or updates one channel.
//
// An empty id creates a channel; a known id updates it in place. The body never
// carries a credential value — only the name of one.
func (h *Handler) PostSupplyChannel(c *gin.Context) {
	var body struct {
		ID       string `json:"id"`
		Kind     string `json:"kind"`
		Label    string `json:"label"`
		Nature   string `json:"nature"`
		Endpoint string `json:"endpoint"`
		Account  string `json:"account"`
		Secret   string `json:"secret"`
		Enabled  *bool  `json:"enabled"`
		Usage    string `json:"usage"`
		Domain   string `json:"domain"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	store, errStore := h.supplyChannels()
	if errStore != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	channel := supply.Channel{
		ID:       body.ID,
		Kind:     supply.Kind(strings.ToLower(strings.TrimSpace(body.Kind))),
		Label:    body.Label,
		Nature:   supply.Nature(strings.ToLower(strings.TrimSpace(body.Nature))),
		Endpoint: body.Endpoint,
		Account:  body.Account,
		Secret:   body.Secret,
		Usage:    body.Usage,
		Domain:   body.Domain,
		Enabled:  true,
	}
	if body.Enabled != nil {
		channel.Enabled = *body.Enabled
	}
	saved, errSave := store.Upsert(channel, time.Now().Unix())
	if errSave != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errSave.Error()})
		return
	}
	status := secretStatus()
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"channel": channelView(saved, status.Names, status.Enabled),
	})
}

// DeleteSupplyChannel removes one channel.
//
// Identities it already handed out stay in the pool: they are the record of what
// happened, and deleting a channel must not erase that.
func (h *Handler) DeleteSupplyChannel(c *gin.Context) {
	store, errStore := h.supplyChannels()
	if errStore != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	if errDelete := store.Delete(c.Param("id")); errDelete != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errDelete.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
