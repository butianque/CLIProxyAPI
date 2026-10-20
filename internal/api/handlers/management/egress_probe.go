package management

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// This file answers one question the panel cannot answer from configuration
// alone: through this exit, what address does the outside world actually see?
//
// It exists because an exit is bought by its address, not by its URL. A vendor's
// country label, its ASN, and the address it really presents can all disagree
// with the listing, and the only way to know is to ask a third party from the
// far side. Doing that here rather than in a browser keeps the credentials in
// the process that already holds them.
//
// Nothing here reads the secret store, and nothing returns a proxy password: the
// probe takes a URL (or the configured one) and reports only what an echo
// service said.

// egressProbeTimeout bounds the whole probe, including the fallback echo
// services, so a dead proxy cannot hold the panel open.
const egressProbeTimeout = 12 * time.Second

// Errors the probe can report about itself rather than about the exit.
var (
	errEgressNoAddress  = errors.New("no echo service reported an address")
	errEgressEchoStatus = errors.New("an echo service answered with a non-200 status")
)

// egressEchoServices are asked in order until one answers.
//
// Order is by how much of the answer they give, not by brand: the first two
// report the country *and* the network, which is what makes a vendor's listing
// checkable. An IP-only service stays last because it can confirm reachability
// but not that the exit is the one that was bought.
//
// ifconfig.co was dropped on purpose: its free answer carries no ASN and placed
// a Hong Kong address in the United States, which is worse than no answer.
var egressEchoServices = []string{
	"https://ipwho.is/",
	"https://api.ip.sb/geoip",
	"https://ipinfo.io/json",
	"https://api.ipify.org?format=json",
}

// egressEcho is what a probe reports. A field a service does not answer stays
// empty rather than being guessed.
type egressEcho struct {
	IP          string
	Country     string
	CountryCode string
	City        string
	Region      string
	ASN         string
	Org         string
}

// supplyExit is the address supply traffic leaves through.
//
// Supply has no exit of its own: it inherits the process-wide one, which was
// already resolved from the pool when the server started. Reporting anything
// else here would make the panel describe an exit the server never uses.
func (h *Handler) supplyExit() string {
	if h == nil || h.cfg == nil {
		return ""
	}
	return h.cfg.EffectiveProxyURL()
}

// describeEgress turns a configured value into what the panel shows.
//
// The explicit "direct" and "none" spellings mean "bypass every proxy", so they
// are reported as direct with no address. Passing them through Redact would
// render them as an invalid proxy URL, which reads like a broken setting when it
// is in fact a deliberate one.
func describeEgress(configured string) (display string, direct bool) {
	trimmed := strings.TrimSpace(configured)
	if trimmed == "" || strings.EqualFold(trimmed, "direct") || strings.EqualFold(trimmed, "none") {
		return "", true
	}
	return proxyutil.Redact(trimmed), false
}

// PostEgressProbe asks an echo service what address it sees through one exit.
//
// The body's url is optional: omitting it probes the configured supply exit,
// which is the common case ("is the exit I set up working"). Passing "direct"
// probes the host's own route, which is what tells an operator whether a proxy
// is doing anything at all.
func (h *Handler) PostEgressProbe(c *gin.Context) {
	var body struct {
		URL string `json:"url"`
	}
	_ = c.ShouldBindJSON(&body)

	target := strings.TrimSpace(body.URL)
	if target == "" {
		target = h.supplyExit()
	}
	isDirect := strings.EqualFold(target, "direct") || strings.EqualFold(target, "none")
	if target != "" && !isDirect && !proxyutil.ValidRequestProxy(target) {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "the proxy URL is not usable: expected http, https, socks5 or socks5h with a host",
		})
		return
	}

	transport, mode, errTransport := proxyutil.BuildHTTPTransport(target)
	if errTransport != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errTransport.Error()})
		return
	}
	client := &http.Client{Timeout: egressProbeTimeout}
	if transport != nil && (mode == proxyutil.ModeProxy || mode == proxyutil.ModeDirect) {
		client.Transport = transport
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), egressProbeTimeout)
	defer cancel()

	display, _ := describeEgress(target)
	started := time.Now()
	echo, service, errProbe := probeExit(ctx, client)
	elapsed := time.Since(started).Milliseconds()
	if errProbe != nil {
		// No echo service confirmed an address. That is not the same as the
		// exit being broken, so the reason is reported rather than a verdict.
		c.JSON(http.StatusBadGateway, gin.H{
			"status":     "error",
			"error":      errProbe.Error(),
			"egress":     display,
			"latency_ms": elapsed,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"egress":       display,
		"direct":       target == "" || isDirect,
		"ip":           echo.IP,
		"country":      echo.Country,
		"country_code": echo.CountryCode,
		"city":         echo.City,
		"region":       echo.Region,
		"asn":          echo.ASN,
		"org":          echo.Org,
		"via":          service,
		"latency_ms":   elapsed,
	})
}

// probeExit asks each echo service in turn and returns the first answer.
//
// A service that cannot be reached is skipped rather than reported: from the
// operator's side, "one of four echo services was down" says nothing about
// their exit. Only when every one fails is there something to report.
func probeExit(ctx context.Context, client *http.Client) (egressEcho, string, error) {
	var lastErr error
	for _, service := range egressEchoServices {
		if ctx.Err() != nil {
			return egressEcho{}, "", ctx.Err()
		}
		echo, errProbe := askEchoService(ctx, client, service)
		if errProbe != nil {
			lastErr = errProbe
			continue
		}
		if echo.IP == "" {
			lastErr = errEgressNoAddress
			continue
		}
		return echo, service, nil
	}
	if lastErr == nil {
		lastErr = errEgressNoAddress
	}
	return egressEcho{}, "", lastErr
}

// askEchoService performs one echo request. The body is capped because the
// answer is a few hundred bytes and a misbehaving peer must not stream.
func askEchoService(ctx context.Context, client *http.Client, service string) (egressEcho, error) {
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, service, nil)
	if errRequest != nil {
		return egressEcho{}, errRequest
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "CLIProxyAPI-egress-probe")
	response, errDo := client.Do(request)
	if errDo != nil {
		return egressEcho{}, unwrapURLError(errDo)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return egressEcho{}, errEgressEchoStatus
	}
	body, errRead := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	if errRead != nil {
		return egressEcho{}, errRead
	}
	var payload map[string]any
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return egressEcho{}, errUnmarshal
	}
	return normalizeEcho(payload), nil
}

// unwrapURLError drops the request URL from a transport error.
//
// The URL is whichever echo service the probe happened to try, and it says
// nothing about the operator's exit. Leaving it in would make a wrong proxy port
// read like the panel were fetching that address for its own reasons, which
// buries the one part of the message that is actionable.
func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// normalizeEcho maps an echo service's payload onto the probe's fields.
//
// The services agree on none of this. One nests the network under
// "connection", another flattens it into "asn_organization", and a third reports
// the ASN as a number instead of a string. Reading through a map and accepting
// the known spellings means a rename at one service empties one field instead of
// silently emptying the whole answer.
func normalizeEcho(payload map[string]any) egressEcho {
	connection, _ := payload["connection"].(map[string]any)
	pick := func(keys ...string) string {
		if text := echoText(payload, keys...); text != "" {
			return text
		}
		return echoText(connection, keys...)
	}
	echo := egressEcho{
		IP:          pick("ip"),
		Country:     pick("country"),
		CountryCode: pick("country_code", "country_iso"),
		City:        pick("city"),
		Region:      pick("region", "region_name"),
		ASN:         pick("asn"),
		Org:         pick("org", "asn_organization", "organization", "isp"),
	}
	echo.ASN, echo.Org = normalizeNetwork(echo.ASN, echo.Org)
	return echo
}

// echoText returns the first of the named fields that holds a scalar.
func echoText(source map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := source[key]; ok {
			if text := echoScalar(value); text != "" {
				return text
			}
		}
	}
	return ""
}

// echoScalar renders one JSON value as text, accepting the number spellings the
// services use for ASNs.
func echoScalar(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case json.Number:
		return typed.String()
	}
	return ""
}

// normalizeNetwork reduces the three reported shapes to "AS<number>" plus a
// name. ipinfo hands over "AS9009 M247 Europe SRL" in a single field, ipwho.is
// nests a numeric ASN beside a name, and api.ip.sb uses "asn_organization".
func normalizeNetwork(asn, org string) (string, string) {
	asn = strings.TrimSpace(asn)
	org = strings.TrimSpace(org)
	if asn == "" {
		head, rest, found := strings.Cut(org, " ")
		if found && isASNumber(head) {
			asn, org = head, strings.TrimSpace(rest)
		}
	}
	asn = strings.ToUpper(asn)
	if asn != "" && !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}
	return asn, org
}

// isASNumber reports whether a token is an ASN written as "AS<n>".
func isASNumber(token string) bool {
	digits, found := strings.CutPrefix(strings.ToUpper(strings.TrimSpace(token)), "AS")
	if !found || digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
