package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
)

// registerManagementV8Routes defines the v8 contract independently of v0.
// Configuration paths mirror the v8 YAML tree; operational routes use its groups.
func (s *Server) registerManagementV8Routes() {
	const prefix = "/v8/management"
	s.engine.GET(prefix+"/oauth/callback", s.managementAvailabilityMiddleware(), s.mgmt.GetOAuthCallback)
	s.engine.POST(prefix+"/oauth/callback", s.managementAvailabilityMiddleware(), s.mgmt.PostOAuthCallback)

	v8 := s.engine.Group(prefix)
	v8.Use(s.managementAvailabilityMiddleware(), s.mgmt.Middleware(), s.mgmt.SessionMiddleware(), func(c *gin.Context) {
		c.Set(management.ConfigV8ContextKey, true)
	})

	// A management session is what the idle timeout, the master-passphrase gate
	// and the secret-store grants are keyed to. The management key starts one; the
	// session token identifies it afterwards.
	v8.POST("/session", s.mgmt.PostSession)
	v8.GET("/session", s.mgmt.GetSession)
	v8.DELETE("/session", s.mgmt.DeleteSession)
	v8.POST("/session/touch", s.mgmt.PostSessionTouch)
	v8.GET("/config", s.mgmt.ConfigV8)
	v8.PUT("/config", s.mgmt.ConfigV8)
	v8.PATCH("/config", s.mgmt.ConfigV8)
	v8.GET("/config.yaml", s.mgmt.ConfigV8)
	v8.PUT("/config.yaml", s.mgmt.ConfigV8)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		v8.Handle(method, "/config/*path", s.mgmt.ConfigV8)
	}

	v8.GET("/server/latest-version", s.mgmt.GetLatestVersion)
	v8.POST("/requests/api-call", s.mgmt.APICall)
	v8.POST("/routing/cooldown/reset", s.mgmt.ResetQuota)
	v8.GET("/routing/model-definitions/:channel", s.mgmt.GetStaticModelDefinitions)

	v8.GET("/observability/logs", s.mgmt.GetLogs)
	v8.DELETE("/observability/logs", s.mgmt.DeleteLogs)
	v8.GET("/observability/logs/errors", s.mgmt.GetRequestErrorLogs)
	v8.GET("/observability/logs/errors/:name", s.mgmt.DownloadRequestErrorLog)
	v8.GET("/observability/logs/requests/:id", s.mgmt.GetRequestLogByID)
	v8.GET("/observability/usage/api-keys", s.mgmt.GetAPIKeyUsage)
	v8.GET("/observability/usage/queue", s.mgmt.GetUsageQueue)

	v8.GET("/credentials", s.mgmt.ListAuthFiles)
	v8.POST("/credentials", s.mgmt.UploadAuthFile)
	v8.DELETE("/credentials", s.mgmt.DeleteAuthFile)
	v8.GET("/credentials/models", s.mgmt.GetAuthFileModels)
	v8.GET("/credentials/download", s.mgmt.DownloadAuthFile)
	v8.PATCH("/credentials/status", s.mgmt.PatchAuthFileStatus)
	v8.PATCH("/credentials/fields", s.mgmt.PatchAuthFileFields)
	v8.POST("/credentials/refresh", s.mgmt.RefreshAuthFiles)

	// The account-centric view: one row per credential carrying its identity,
	// routing policy, cached quota and request health. The panel reads this
	// instead of stitching four per-credential endpoints together. Quota here
	// is always a cached snapshot; reading it never probes upstream.
	v8.GET("/accounts", s.mgmt.ListAccounts)
	v8.POST("/oauth/import", s.mgmt.ImportOAuthV8)
	v8.GET("/oauth/auth-url", s.mgmt.StartOAuthV8)
	v8.GET("/oauth/status", s.mgmt.GetAuthStatus)
	v8.DELETE("/oauth/session", s.mgmt.CancelAuthSession)

	v8.GET("/plugins", s.mgmt.ListPlugins)
	v8.DELETE("/plugins/:id", s.mgmt.DeletePlugin)
	v8.GET("/plugins/store", s.mgmt.ListPluginStore)
	v8.POST("/plugins/store/:id/install", s.mgmt.InstallPluginFromStore)
	v8.GET("/plugins/:id/quota", s.mgmt.GetPluginQuota)
	v8.POST("/plugins/:id/quota", s.mgmt.FetchPluginQuota)
	v8.DELETE("/plugins/:id/quota", s.mgmt.ResetPluginQuota)

	v8.GET("/secrets", s.mgmt.GetSecretStatus)
	v8.POST("/secrets/initialize", s.mgmt.PostSecretInitialize)
	v8.POST("/secrets/unlock", s.mgmt.PostSecretUnlock)
	v8.POST("/secrets/lock", s.mgmt.PostSecretLock)
	v8.POST("/secrets/passphrase", s.mgmt.PostSecretPassphrase)
	v8.POST("/secrets/verify", s.mgmt.PostSecretVerify)
	v8.POST("/secrets/machine-unlock", s.mgmt.PostSecretMachineUnlock)
	v8.DELETE("/secrets/machine-unlock", s.mgmt.DeleteSecretMachineUnlock)
	v8.PUT("/secrets/:name", s.mgmt.PutSecret)
	v8.DELETE("/secrets/:name", s.mgmt.DeleteSecret)

	v8.GET("/supply/status", s.mgmt.GetSupplyStatus)
	// The one call that proves an exit is what it claims: an echo service asked
	// from the far side. Omitting the URL probes the exit supply traffic uses.
	v8.POST("/egress/probe", s.mgmt.PostEgressProbe)

	// The exits this installation owns. An exit is identified by a small number
	// because it is replaced as a unit: when an address is retired, everything
	// bound to it moves together.
	v8.GET("/egress/pool", s.mgmt.GetEgressPool)
	v8.POST("/egress/pool", s.mgmt.PostEgressPool)
	// Which exit a new identity would be given right now.
	v8.POST("/egress/pool/next", s.mgmt.PostEgressPoolNext)
	v8.PATCH("/egress/pool/:id", s.mgmt.PatchEgressPool)
	v8.DELETE("/egress/pool/:id", s.mgmt.DeleteEgressPool)
	// Asking one exit what address it presents, and remembering the answer.
	v8.POST("/egress/pool/:id/probe", s.mgmt.PostEgressPoolProbe)
	// Exactly what is bound to one exit.
	v8.GET("/egress/pool/:id/members", s.mgmt.GetEgressPoolMembers)
	// Making and releasing a binding. Automation and the panel both go through
	// here, so an exit is assigned in one place instead of once per target.
	v8.POST("/egress/pool/:id/bind", s.mgmt.PostEgressPoolBind)
	// Releasing is not about one exit, so it lives beside the pool rather than
	// under an id: a target can only be bound to one exit at a time.
	v8.POST("/egress/unbind", s.mgmt.PostEgressPoolUnbind)

	// The cross-kind identity pool: which identity is behind a credential,
	// and which platform it registered on. It is also the pool view: ?kind=
	// narrows it to one kind's handed-out identities.
	v8.GET("/supply/pool", s.mgmt.GetSupplyPool)
	// Recording a registration the pool cannot observe on its own: the caller
	// that ran the signup reports the platform, account and outcome.
	v8.POST("/supply/pool/accounts", s.mgmt.PostSupplyPoolAccount)

	// The configured sources of identities. A channel is a label plus a nature
	// plus the connection details that nature implies; the nature is what the
	// host switches on.
	v8.GET("/supply/channels", s.mgmt.GetSupplyChannels)
	v8.POST("/supply/channels", s.mgmt.PostSupplyChannel)
	v8.DELETE("/supply/channels/:id", s.mgmt.DeleteSupplyChannel)
	// The probe answers "is this channel actually reachable": one cheap
	// authenticated call per declared nature, read-only and concurrent.
	v8.POST("/supply/channels/probe", s.mgmt.PostSupplyChannelProbe)

	// The phone kind's management surface. The panel drives the platform
	// through these instead of reaching into the plugin.
	v8.GET("/supply/phone/status", s.mgmt.GetSupplyPhoneStatus)
	v8.POST("/supply/phone/refresh", s.mgmt.PostSupplyPhoneRefresh)
	v8.POST("/supply/phone/guardrail", s.mgmt.PostSupplyPhoneGuardrail)
	v8.POST("/supply/phone/channel", s.mgmt.PostSupplyPhoneChannel)
	v8.POST("/supply/phone/api", s.mgmt.PostSupplyPhoneAPI)
	v8.POST("/supply/phone/cookie", s.mgmt.PostSupplyPhoneCookie)
	v8.POST("/supply/phone/web-login", s.mgmt.PostSupplyPhoneWebLogin)
	v8.POST("/supply/phone/web-credential", s.mgmt.PostSupplyPhoneWebCredential)
	v8.POST("/supply/phone/blacklist", s.mgmt.PostSupplyPhoneBlacklist)

	// The email kind's management surface: what mailboxes are configured, what
	// arrived in them, and where a mailbox authorization code is stored.
	v8.GET("/supply/email/status", s.mgmt.GetSupplyEmailStatus)
	v8.GET("/supply/email/inbox", s.mgmt.GetSupplyEmailInbox)
	// The machine surface: hand out one address, then ask what arrived for it
	// after the position the caller holds. A script uses these two and nothing
	// else; the panel uses the two above.
	v8.POST("/supply/email/grab", s.mgmt.PostSupplyEmailGrab)
	v8.GET("/supply/email/code", s.mgmt.GetSupplyEmailCode)
	v8.POST("/supply/email/credential", s.mgmt.PostSupplyEmailCredential)
	// "Can the mailbox that receives this address be opened right now" — the
	// answer an identity with its own credential cannot get from a channel.
	v8.POST("/supply/email/probe", s.mgmt.PostSupplyEmailProbe)
	// A batch of mailboxes from a seller's paste: one call parses every line,
	// stores the refresh tokens, and creates one channel per mailbox.
	v8.POST("/supply/email/import", s.mgmt.PostSupplyEmailImport)

	// The action surface: every plugin's named operations, plus the jobs their
	// long-running actions run as. The panel triggers actions by key instead of
	// reaching into a plugin's own routes or HTML.
	v8.GET("/actions", s.mgmt.ListPluginActions)
	v8.POST("/actions/:key", s.mgmt.TriggerPluginAction)
	v8.GET("/jobs", s.mgmt.ListPluginJobs)
	v8.GET("/jobs/:id", s.mgmt.GetPluginJob)
	v8.DELETE("/jobs/:id", s.mgmt.CancelPluginJob)
}
