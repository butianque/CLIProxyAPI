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
// A channel is a label plus a category plus per-kind blocks (phone, email, or
// both). Each kind block lists the natures it speaks and holds per-nature
// connection details. Credential values never cross this surface.

// supplyChannels loads the channel list from the supply state directory.
func (h *Handler) supplyChannels() (*supply.ChannelStore, error) {
	return supply.LoadChannels(supply.ChannelPath(supplyStateDir(h)))
}

func supplyStateDir(h *Handler) string {
	var configured, configPath string
	if h.cfg != nil {
		configured = h.cfg.Supply.WithDefaults().StorageDir
	}
	if h.configFilePath != "" {
		configPath = h.configFilePath
	}
	return supply.StateDir(filepath.Dir(configPath), configured)
}

// connectionView renders one connection for the panel. Secret values are never
// included; only whether the named secret exists in the store.
func connectionView(nature supply.Nature, conn supply.Connection, secretNames []string, storeEnabled bool) gin.H {
	view := gin.H{}
	if conn.Endpoint != "" {
		view["endpoint"] = conn.Endpoint
	}
	if conn.Account != "" {
		view["account"] = conn.Account
	}
	if conn.Secret != "" {
		view["secret"] = conn.Secret
		view["secret_present"] = storeEnabled && contains(secretNames, conn.Secret)
	}
	if conn.Usage != "" {
		view["usage"] = conn.Usage
	}
	if conn.Domain != "" {
		view["domain"] = conn.Domain
	}
	return view
}

// kindConfigView renders one per-kind block.
func kindConfigView(kc *supply.KindConfig, secretNames []string, storeEnabled bool) gin.H {
	if kc == nil {
		return nil
	}
	natures := make([]string, len(kc.Natures))
	for i, n := range kc.Natures {
		natures[i] = string(n)
	}
	conns := make(map[string]gin.H, len(kc.Connections))
	for nature, conn := range kc.Connections {
		conns[string(nature)] = connectionView(nature, conn, secretNames, storeEnabled)
	}
	return gin.H{
		"enabled":     kc.Enabled,
		"natures":     natures,
		"connections": conns,
	}
}

// channelView renders one channel for the panel.
func channelView(channel supply.Channel, secretNames []string, storeEnabled bool) gin.H {
	view := gin.H{
		"id":      channel.ID,
		"label":   channel.Label,
		"created": channel.Created,
		"updated": channel.Updated,
	}
	if channel.Category != "" {
		view["category"] = channel.Category
	}
	if pv := kindConfigView(channel.Phone, secretNames, storeEnabled); pv != nil {
		view["phone"] = pv
	}
	if ev := kindConfigView(channel.Email, secretNames, storeEnabled); ev != nil {
		view["email"] = ev
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
func (h *Handler) GetSupplyChannels(c *gin.Context) {
	store, errStore := h.supplyChannels()
	if errStore != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	kind := supply.Kind(strings.ToLower(strings.TrimSpace(c.Query("kind"))))
	status := secretStatus()

	channels := store.List(kind)
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
func (h *Handler) PostSupplyChannel(c *gin.Context) {
	var body struct {
		ID       string          `json:"id"`
		Label    string          `json:"label"`
		Category string          `json:"category"`
		Phone    *kindConfigBody `json:"phone"`
		Email    *kindConfigBody `json:"email"`
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
	phone := toKindConfig(body.Phone)
	h.stampPhoneCredentialNames(phone)
	channel := supply.Channel{
		ID:       body.ID,
		Label:    body.Label,
		Category: body.Category,
		Phone:    phone,
		Email:    toKindConfig(body.Email),
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

// stampPhoneCredentialNames names the phone kind's single platform credential on
// every nature a submitted phone block declares.
//
// The phone kind has exactly one platform credential per surface, and the
// secret-store entry name holding it belongs to the configuration
// (supply.phone.api-secret / supply.phone.cookie-secret), not to a channel. A
// connection has to name it: the probe resolves a credential through the
// connection's Secret, so a connection that leaves the name out is reported as
// "credential not ready" even though the credential is stored and the channel is
// otherwise configured.
//
// The panel cannot know these names, because they are configuration rather than
// channel data, so the host stamps them here instead of letting the panel guess.
// Only the Secret field is touched: endpoint, account, usage and domain stay
// whatever the operator submitted.
func (h *Handler) stampPhoneCredentialNames(kc *supply.KindConfig) {
	if kc == nil {
		return
	}
	if kc.Connections == nil {
		kc.Connections = make(map[supply.Nature]supply.Connection, len(kc.Natures))
	}
	phoneCfg := h.supplyPhoneConfig()
	for _, nature := range kc.Natures {
		conn := kc.Connections[nature]
		switch nature {
		case supply.NatureAPI:
			conn.Secret = phoneCfg.APISecret
		case supply.NatureWeb:
			conn.Secret = phoneCfg.CookieSecret
		default:
			// Another kind's nature, or one the base has no credential for:
			// leave the connection exactly as submitted.
			continue
		}
		kc.Connections[nature] = conn
	}
}

// DeleteSupplyChannel removes one channel.
func (h *Handler) DeleteSupplyChannel(c *gin.Context) {
	id := c.Param("id")
	store, errStore := h.supplyChannels()
	if errStore != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	if errDel := store.Delete(id); errDel != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errDel.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// kindConfigBody is the JSON shape the panel sends for one kind block.
type kindConfigBody struct {
	Enabled     bool                      `json:"enabled"`
	Natures     []string                  `json:"natures"`
	Connections map[string]connectionBody `json:"connections"`
}

type connectionBody struct {
	Endpoint string `json:"endpoint"`
	Account  string `json:"account"`
	Secret   string `json:"secret"`
	Usage    string `json:"usage"`
	Domain   string `json:"domain"`
}

func toKindConfig(body *kindConfigBody) *supply.KindConfig {
	if body == nil {
		return nil
	}
	natures := make([]supply.Nature, len(body.Natures))
	for i, n := range body.Natures {
		natures[i] = supply.Nature(strings.ToLower(strings.TrimSpace(n)))
	}
	conns := make(map[supply.Nature]supply.Connection, len(body.Connections))
	for key, cb := range body.Connections {
		nature := supply.Nature(strings.ToLower(strings.TrimSpace(key)))
		conns[nature] = supply.Connection{
			Endpoint: cb.Endpoint,
			Account:  cb.Account,
			Secret:   cb.Secret,
			Usage:    cb.Usage,
			Domain:   cb.Domain,
		}
	}
	return &supply.KindConfig{
		Enabled:     body.Enabled,
		Natures:     natures,
		Connections: conns,
	}
}
