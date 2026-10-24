package config

const (
	DefaultPanelGitHubRepository = "https://github.com/router-for-me/Cli-Proxy-API-Management-Center"
	DefaultPprofAddr             = "127.0.0.1:8316"
	DefaultAuthDir               = "~/.cli-proxy-api"
	DefaultDiscoveryServiceType  = "_ai-gateway._tcp"
)

// DefaultAutomationAllow is what an automation key may call when the operator
// does not spell out a list.
//
// The set is chosen by reach, not by HTTP method: every read a registration
// script needs (supply pool, mailboxes, mail bodies and their links, accounts,
// logs) plus the few writes that are part of that loop (allocating an address,
// probing a channel, waking an egress). Configuration, the secret store,
// credential download and the arbitrary-request proxy are all left out, because
// each of them would hand the holder something it cannot be given back.
var DefaultAutomationAllow = []string{
	"GET /v8/management/supply/*",
	"POST /v8/management/supply/email/grab",
	"POST /v8/management/supply/channels/probe",
	"POST /v8/management/supply/email/probe",
	"GET /v8/management/accounts",
	"GET /v8/management/credentials",
	"GET /v8/management/credentials/models",
	"GET /v8/management/observability/logs",
	"GET /v8/management/observability/logs/*",
	"GET /v8/management/observability/usage/*",
	"GET /v8/management/plugins",
	"GET /v8/management/egress/pool",
	"POST /v8/management/egress/probe",
}
