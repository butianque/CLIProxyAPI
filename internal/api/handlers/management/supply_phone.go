package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/phone"
)

// This file is the phone kind's management surface: the base-side counterpart
// of the plugin's former /sms/* routes. The panel reads status from here and
// writes credentials here; it no longer reaches into the plugin.
//
// Credential values are only ever *written* through this surface and never read
// back out: status reports presence and masked hints, exactly as the plugin did.
// The master passphrase gates every credential write.

// phoneOps is the phone kind's management surface: the operations this HTTP
// layer drives on the platform. It is declared here, not in internal/supply,
// because these operations are phone-specific and must not grow the shared
// supply contract; the provider registered for the phone kind implements it.
type phoneOps interface {
	Balance(ctx context.Context) (float64, error)
	Channels() *phone.ChannelCache
	Pool() *supply.Pool
	Health() *phone.ChannelHealth
	RefreshChannels(ctx context.Context, join bool) (int, error)
	Guardrail(ctx context.Context) (int, error)
	SetChannelOpen(ctx context.Context, action, uid string) error
	Blacklist(ctx context.Context, phone string) error
	WebLogin(ctx context.Context, user, pass string) (string, int, error)
}

// phoneProvider returns the phone supply provider's management surface, or nil
// when the kind is not configured (disabled, or the secret store is locked and
// its credential cannot be read).
//
// The lookup goes through the shared supply service rather than asserting on a
// concrete service type, so a decorated or re-wrapped service keeps working.
func phoneProvider() phoneOps {
	provider, errProvider := supply.ProviderFor(supply.KindPhone)
	if errProvider != nil {
		return nil
	}
	ops, ok := provider.(phoneOps)
	if !ok {
		return nil
	}
	return ops
}

// supplyPhoneConfig resolves the phone kind's configuration with defaults.
func (h *Handler) supplyPhoneConfig() config.SupplyPhoneConfig {
	if h == nil || h.cfg == nil {
		return config.SupplyConfig{}.WithDefaults().Phone
	}
	return h.cfg.Supply.WithDefaults().Phone
}

// GetSupplyPhoneStatus reports the phone kind to the panel: whether it is
// configured, the account balance, the cached channels and the phone pool.
//
// Every platform call here is read-only and free, so the panel can poll it.
func (h *Handler) GetSupplyPhoneStatus(c *gin.Context) {
	phoneCfg := h.supplyPhoneConfig()
	// The provider is the truth for "is this kind serving": it exists only when
	// the kind is enabled in configuration *and* its platform credential was
	// readable at startup. Reporting the raw config flag would claim the kind is
	// off while it is demonstrably working.
	provider := phoneProvider()
	payload := gin.H{
		"status":   "ok",
		"enabled":  provider != nil,
		"provider": phoneCfg.Provider,
		"project":  phoneCfg.Project,
		"budget": gin.H{
			"max_total_cny":      phoneCfg.MaxTotalCNY,
			"max_per_number_cny": phoneCfg.MaxPerNumberCNY,
		},
	}

	// The store's own state drives the panel: whether it is usable, whether a
	// master passphrase is installed, and which credentials exist.
	status := secretStatus()
	payload["store_enabled"] = status.Enabled
	payload["store_available"] = status.Unlocked
	payload["passphrase_set"] = status.Passphrase
	payload["credentials"] = status.Names
	payload["api_present"] = status.Enabled && contains(status.Names, phoneCfg.APISecret)
	payload["cookie_present"] = status.Enabled && contains(status.Names, phoneCfg.CookieSecret)
	if status.Enabled && status.Unlocked {
		if raw, errGet := secretstore.Default().Get(phoneCfg.APISecret); errGet == nil {
			if parsed, errParse := phone.ParseHaozhumaSecret(raw); errParse == nil {
				webUser := strings.TrimSpace(parsed.WebUser)
				payload["web_present"] = webUser != ""
				payload["api_user_hint"] = phone.MaskIdentifier(strings.TrimSpace(parsed.User))
				payload["web_user_hint"] = phone.MaskIdentifier(webUser)
			}
		}
	}

	// The channel cache, pool and health are plain documents on disk, not
	// secrets, so they are reported whether or not the store is unlocked.
	if provider != nil {
		reportPhoneRecords(payload, provider, h.authIndexByName())
	}

	if provider == nil {
		if phoneCfg.Disabled {
			// The operator has turned the kind off: enabled=false is the honest
			// state.
			c.JSON(http.StatusOK, payload)
			return
		}
		// Enabled but no credential is readable (locked or unparsable): report
		// which one it is so the panel can guide the operator.
		payload["status"] = "unavailable"
		payload["locked"] = true
		payload["error"] = "credentials are not available"
		c.JSON(http.StatusOK, payload)
		return
	}
	ctxBalance, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if balance, errBalance := provider.Balance(ctxBalance); errBalance != nil {
		payload["balance_error"] = errBalance.Error()
	} else {
		payload["balance_cny"] = balance
	}
	c.JSON(http.StatusOK, payload)
}

// reportPhoneRecords adds the cached channels, the pool and the channel
// health to a status payload. It reads only documents, never credentials.
func reportPhoneRecords(payload gin.H, provider phoneOps, index map[string]string) {
	if cache := provider.Channels(); cache != nil {
		payload["channels"] = cache.Channels
		payload["channels_updated_at"] = cache.UpdatedAt
	}
	if pool := provider.Pool(); pool != nil {
		payload["ledger"] = phoneRecords(pool, index)
		payload["spent_cny"] = pool.Spent()
	}
	if health := provider.Health(); health != nil {
		payload["channel_health"] = health.Stats
	}
}

// phoneRecords renders the phone kind's slice of the cross-kind pool for the
// phone view. The record's kind-specific details live in Meta, so the channel a
// number was rented from is read from there rather than from a phone-only field.
func phoneRecords(pool *supply.Pool, index map[string]string) []gin.H {
	if pool == nil {
		return nil
	}
	records := pool.All()
	out := make([]gin.H, 0, len(records))
	for _, record := range records {
		if record.Kind != supply.KindPhone {
			continue
		}
		authIndex, _ := resolveAuthIndex(record, index)
		out = append(out, gin.H{
			"phone":      record.Address,
			"sid":        record.MetaString("sid"),
			"code":       record.MetaString("channel"),
			"account":    record.Account,
			"target":     record.Target,
			"auth_index": authIndex,
			"price":      record.Price,
			"rents":      record.Rents,
			"spend":      record.Spend,
			"first_seen": record.FirstSeen,
			"last_used":  record.LastUsed,
			"outcome":    record.Outcome,
			"state":      record.State,
		})
	}
	return out
}

// PostSupplyPhoneRefresh re-reads the joined channels and rewrites the cache.
//
// It needs the web session cookie, not the API credential, so the cookie check
// comes first: without one the honest answer is "sign in first", not a
// credential error that reads as if the API credential were broken.
func (h *Handler) PostSupplyPhoneRefresh(c *gin.Context) {
	if errCookie := h.requirePhoneCookie(c, "channel refresh"); errCookie {
		return
	}
	provider, errProvider := requirePhoneProvider(c)
	if errProvider {
		return
	}
	var body struct {
		Join bool `json:"join"`
	}
	_ = c.ShouldBindJSON(&body)

	count, errRefresh := provider.RefreshChannels(c.Request.Context(), body.Join)
	if errRefresh != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": errRefresh.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"channels": provider.Channels().Channels,
		"count":    count,
		"joined":   body.Join,
	})
}

// PostSupplyPhoneGuardrail switches channels above the ceiling or out of stock
// off and affordable in-stock ones back on.
func (h *Handler) PostSupplyPhoneGuardrail(c *gin.Context) {
	if errCookie := h.requirePhoneCookie(c, "the guardrail"); errCookie {
		return
	}
	provider, errProvider := requirePhoneProvider(c)
	if errProvider {
		return
	}
	changed, errGuard := provider.Guardrail(c.Request.Context())
	if errGuard != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": errGuard.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"changed":  changed,
		"channels": provider.Channels().Channels,
	})
}

// PostSupplyPhoneChannel pauses or recovers one joined channel.
func (h *Handler) PostSupplyPhoneChannel(c *gin.Context) {
	provider, errProvider := requirePhoneProvider(c)
	if errProvider {
		return
	}
	var body struct {
		UID    string `json:"uid"`
		Paused *bool  `json:"paused"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	uid := strings.TrimSpace(body.UID)
	if uid == "" || body.Paused == nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "a channel uid and its paused state are required"})
		return
	}
	if errCookie := h.requirePhoneCookie(c, "switching a channel"); errCookie {
		return
	}
	action := "pause"
	if !*body.Paused {
		action = "recover"
	}
	if errSwitch := provider.SetChannelOpen(c.Request.Context(), action, uid); errSwitch != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": errSwitch.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"uid":      uid,
		"paused":   *body.Paused,
		"channels": provider.Channels().Channels,
	})
}

// PostSupplyPhoneAPI stores the platform's fixed API credential.
func (h *Handler) PostSupplyPhoneAPI(c *gin.Context) {
	var body struct {
		APIUser    string `json:"api_user"`
		APIPass    string `json:"api_pass"`
		Token      string `json:"token"`
		Endpoint   string `json:"endpoint"`
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	store, errGate := gateSupplyWrite(c, body.Passphrase)
	if errGate {
		return
	}
	phoneCfg := h.supplyPhoneConfig()

	// Read back what is stored so a blank field means "leave it alone" rather
	// than "erase it": the panel never echoes secrets.
	secret := phone.HaozhumaSecret{}
	if existing, errGet := store.Get(phoneCfg.APISecret); errGet == nil {
		if parsed, errParse := phone.ParseHaozhumaSecret(existing); errParse == nil {
			secret = parsed
		}
	}
	merged, errMerge := mergePhoneAPICredential(secret, strings.TrimSpace(body.APIUser), strings.TrimSpace(body.APIPass), strings.TrimSpace(body.Token), strings.TrimSpace(body.Endpoint))
	if errMerge != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errMerge.Error()})
		return
	}
	encoded, errMarshal := json.Marshal(merged)
	if errMarshal != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errMarshal.Error()})
		return
	}
	if errStore := store.Set(phoneCfg.APISecret, string(encoded)); errStore != nil {
		c.JSON(errStatus(errStore), gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	reloadSupply()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "stored": phoneCfg.APISecret})
}

// mergePhoneAPICredential folds the fields a panel submit filled into the
// stored credential. A blank field keeps its stored value. The merged value is
// rejected unless it carries a usable credential: a bare token works, otherwise
// the account/password pair must both be present.
func mergePhoneAPICredential(base phone.HaozhumaSecret, user, pass, token, endpoint string) (phone.HaozhumaSecret, error) {
	if user != "" {
		base.User = user
	}
	if pass != "" {
		base.Pass = pass
	}
	if token != "" {
		base.Token = token
	}
	if endpoint != "" {
		base.Endpoint = endpoint
	}
	if base.Token == "" && (base.User == "" || base.Pass == "") {
		return phone.HaozhumaSecret{}, errors.New("provide either a token, or both api_user and api_pass")
	}
	return base, nil
}

// PostSupplyPhoneCookie stores or clears the platform's temporary web session
// cookie. An empty cookie clears it, which downgrades channel refresh to the
// cached list rather than breaking login.
func (h *Handler) PostSupplyPhoneCookie(c *gin.Context) {
	var body struct {
		Cookie     string `json:"cookie"`
		WebBase    string `json:"web_base"`
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	store, errGate := gateSupplyWrite(c, body.Passphrase)
	if errGate {
		return
	}
	phoneCfg := h.supplyPhoneConfig()
	cookie := strings.TrimSpace(body.Cookie)
	if cookie == "" {
		if errDelete := store.Delete(phoneCfg.CookieSecret); errDelete != nil && !errors.Is(errDelete, secretstore.ErrNotFound) {
			c.JSON(errStatus(errDelete), gin.H{"status": "error", "error": errDelete.Error()})
			return
		}
		reloadSupply()
		c.JSON(http.StatusOK, gin.H{"status": "ok", "cleared": true})
		return
	}
	encoded, errMarshal := json.Marshal(phone.HaozhumaSecret{Cookie: cookie, WebBase: strings.TrimSpace(body.WebBase)})
	if errMarshal != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errMarshal.Error()})
		return
	}
	if errStore := store.Set(phoneCfg.CookieSecret, string(encoded)); errStore != nil {
		c.JSON(errStatus(errStore), gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	reloadSupply()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "stored": phoneCfg.CookieSecret})
}

// PostSupplyPhoneWebLogin signs in to the platform's web surface, solving its
// click-order captcha, and stores the resulting session cookie.
//
// A supplied account or password is adopted; a blank field reuses what is
// stored. The cookie is verified against the channel list before it is stored,
// so a cookie is only ever written once it has been shown to work.
func (h *Handler) PostSupplyPhoneWebLogin(c *gin.Context) {
	var body struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	store, errGate := gateSupplyWrite(c, body.Passphrase)
	if errGate {
		return
	}
	phoneCfg := h.supplyPhoneConfig()
	existing, errGet := store.Get(phoneCfg.APISecret)
	if errGet != nil {
		if errors.Is(errGet, secretstore.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "store the platform API credential first"})
			return
		}
		c.JSON(errStatus(errGet), gin.H{"status": "error", "error": errGet.Error()})
		return
	}
	secret, errParse := phone.ParseHaozhumaSecret(existing)
	if errParse != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errParse.Error()})
		return
	}
	user := strings.TrimSpace(body.Username)
	pass := strings.TrimSpace(body.Password)
	if user != "" {
		secret.WebUser = user
	}
	if pass != "" {
		secret.WebPass = pass
	}
	if secret.WebUser == "" || secret.WebPass == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "a web account and password are required to fetch the session cookie"})
		return
	}

	provider := phoneProvider()
	if provider == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": "the phone kind is not configured"})
		return
	}
	cookie, channels, errLogin := provider.WebLogin(c.Request.Context(), secret.WebUser, secret.WebPass)
	if errLogin != nil {
		status := http.StatusBadGateway
		if errors.Is(errLogin, phone.ErrCredential) {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"status": "error", "error": errLogin.Error()})
		return
	}

	// Only a sign-in that actually worked persists anything: a typo would
	// otherwise be stored and silently reused on the next attempt.
	if user != "" || pass != "" {
		encoded, errMarshal := json.Marshal(secret)
		if errMarshal != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errMarshal.Error()})
			return
		}
		if errStore := store.Set(phoneCfg.APISecret, string(encoded)); errStore != nil {
			c.JSON(errStatus(errStore), gin.H{"status": "error", "error": errStore.Error()})
			return
		}
	}
	cookieSecret := phone.HaozhumaSecret{Cookie: cookie, WebBase: secret.WebBase}
	encoded, errMarshal := json.Marshal(cookieSecret)
	if errMarshal != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errMarshal.Error()})
		return
	}
	if errStore := store.Set(phoneCfg.CookieSecret, string(encoded)); errStore != nil {
		c.JSON(errStatus(errStore), gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	reloadSupply()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "cookie_present": true, "channels": channels})
}

// PostSupplyPhoneWebCredential stores the web-surface sign-in account and
// password without attempting a sign-in.
func (h *Handler) PostSupplyPhoneWebCredential(c *gin.Context) {
	var body struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	store, errGate := gateSupplyWrite(c, body.Passphrase)
	if errGate {
		return
	}
	user := strings.TrimSpace(body.Username)
	pass := strings.TrimSpace(body.Password)
	if user == "" && pass == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "provide a web account or password"})
		return
	}
	phoneCfg := h.supplyPhoneConfig()
	existing, errGet := store.Get(phoneCfg.APISecret)
	if errGet != nil {
		if errors.Is(errGet, secretstore.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "store the platform API credential first"})
			return
		}
		c.JSON(errStatus(errGet), gin.H{"status": "error", "error": errGet.Error()})
		return
	}
	secret, errParse := phone.ParseHaozhumaSecret(existing)
	if errParse != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errParse.Error()})
		return
	}
	if user != "" {
		secret.WebUser = user
	}
	if pass != "" {
		secret.WebPass = pass
	}
	encoded, errMarshal := json.Marshal(secret)
	if errMarshal != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errMarshal.Error()})
		return
	}
	if errStore := store.Set(phoneCfg.APISecret, string(encoded)); errStore != nil {
		c.JSON(errStatus(errStore), gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	reloadSupply()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "stored": phoneCfg.APISecret})
}

// PostSupplyPhoneBlacklist asks the platform never to hand back one number.
func (h *Handler) PostSupplyPhoneBlacklist(c *gin.Context) {
	var body struct {
		Phone string `json:"phone"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	number := strings.TrimSpace(body.Phone)
	if number == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "phone is required"})
		return
	}
	provider, errProvider := requirePhoneProvider(c)
	if errProvider {
		return
	}
	if errBlacklist := provider.Blacklist(c.Request.Context(), number); errBlacklist != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": errBlacklist.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// requirePhoneProvider writes the error response and returns true when the
// phone kind is not configured.
func requirePhoneProvider(c *gin.Context) (phoneOps, bool) {
	provider := phoneProvider()
	if provider == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": "the phone kind is not configured"})
		return nil, true
	}
	return provider, false
}

// requirePhoneCookie refuses an action that needs the web session cookie when
// no cookie is stored, saying so instead of a credential error that reads as if
// the API credential were broken.
func (h *Handler) requirePhoneCookie(c *gin.Context, action string) bool {
	store := secretstore.Default()
	if store == nil || !store.Unlocked() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": action + " needs the web session; unlock the store first"})
		return true
	}
	phoneCfg := h.supplyPhoneConfig()
	if _, errGet := store.Get(phoneCfg.CookieSecret); errGet != nil {
		if errors.Is(errGet, secretstore.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": action + " needs the web session; sign in under the web tab first"})
			return true
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": errGet.Error()})
		return true
	}
	return false
}

// gateSupplyWrite applies the master-passphrase gate to a credential write and
// returns the store. It writes the error response and returns true when the
// write must not proceed.
func gateSupplyWrite(c *gin.Context, passphrase string) (*secretstore.Store, bool) {
	store := secretstore.Default()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": "secret store is disabled"})
		return nil, true
	}
	if errGate := gateWrite(store, passphrase); errGate != nil {
		payload := gin.H{"status": "error", "error": errGate.Error()}
		if errors.Is(errGate, secretstore.ErrInvalidPassphrase) {
			payload["passphrase_wrong"] = true
		}
		c.JSON(errStatus(errGate), payload)
		return nil, true
	}
	return store, false
}

// reloadSupply rebuilds the process-wide supply service so a credential change
// takes effect on the next call. A nil service is fine: the next call rebuilds
// from the store.
func reloadSupply() {
	if h := supplyReloader; h != nil {
		h()
	}
}

// supplyReloader is installed by the command layer so the management surface can
// ask it to rebuild the supply service after a credential change.
var supplyReloader func()

// SetSupplyReloader installs the callback that rebuilds the supply service.
func SetSupplyReloader(reload func()) { supplyReloader = reload }

// contains reports whether values holds want.
func contains(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
