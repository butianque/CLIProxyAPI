package phone

// This file is the phone kind's reachability probe: one cheap authenticated
// call per nature, so the management surface can answer "is this channel
// actually reachable" instead of only "is it configured".
//
// A probe is read-only. It writes nothing and never needs the master
// passphrase: an unreadable credential is reported as not-ready by the caller
// rather than repaired here. What a probe returns is a short human detail such
// as the account balance or the number of channels a session can see; a
// credential value is never part of it — not even when a failure carries the
// request or the platform's own text back (see redactProbeError).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrProbeUnready reports that a probe could not be attempted at all: the
// stored credential is absent, unparsable, or not the kind the nature needs.
//
// It is what lets a caller tell "not ready" from "the platform was reached and
// refused". Those are two different states on the panel, and reporting a
// missing credential as an unreachable channel would blame the platform for a
// local problem.
var ErrProbeUnready = errors.New("sms: probe credential is not ready")

// ProbeAPI performs one cheap authenticated call against the platform's API
// surface and returns a short detail for the panel: the account balance.
//
// The endpoint is the channel's own address when it has one, and the platform's
// host otherwise. The credential is the stored value behind the connection's
// secret name, decoded here.
//
// The detail is English, like every other string this management surface emits;
// the panel is what localizes it.
//
// egress is the channel's exit; empty means the process environment. The probe
// is what proves an exit works, so it has to take the same route a rental will.
func ProbeAPI(ctx context.Context, endpoint, credential, egress string) (string, error) {
	client, errClient := clientForEgress(egress)
	if errClient != nil {
		return "", probeNotReady(errClient)
	}
	return probeAPI(ctx, client, endpoint, credential)
}

// probeAPI is ProbeAPI with an explicit HTTP client, so a test can point it at
// a local server. A nil client gets the provider's own default.
func probeAPI(ctx context.Context, client *http.Client, endpoint, credential string) (string, error) {
	secret, errParse := ParseHaozhumaSecret(credential)
	if errParse != nil {
		return "", probeNotReady(errParse)
	}
	if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
		secret.Endpoint = endpoint
	}
	provider, errProvider := NewHaozhuma(secret, client)
	if errProvider != nil {
		return "", probeNotReady(errProvider)
	}
	balance, errBalance := provider.Balance(ctx)
	if errBalance != nil {
		return "", redactProbeError(errBalance, secret)
	}
	return fmt.Sprintf("balance ¥%.2f", balance), nil
}

// ProbeWeb performs one cheap authenticated read against the platform's web
// surface and returns a short detail for the panel: how many channels the
// session can see.
//
// The endpoint is the channel's own web address when it has one. Unlike the API
// surface, the web surface authenticates with the session cookie alone, so a
// cookie-only credential is a usable one.
func ProbeWeb(ctx context.Context, endpoint, credential, egress string) (string, error) {
	client, errClient := clientForEgress(egress)
	if errClient != nil {
		return "", probeNotReady(errClient)
	}
	return probeWeb(ctx, client, endpoint, credential)
}

// probeWeb is ProbeWeb with an explicit HTTP client, so a test can point it at
// a local server.
func probeWeb(ctx context.Context, client *http.Client, endpoint, credential string) (string, error) {
	secret, errParse := ParseHaozhumaCookie(credential)
	if errParse != nil {
		return "", probeNotReady(errParse)
	}
	if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
		secret.WebBase = endpoint
	}
	provider, errProvider := newWebProvider(secret, client)
	if errProvider != nil {
		return "", probeNotReady(errProvider)
	}
	quotes, errChannels := provider.Channels(ctx)
	if errChannels != nil {
		return "", redactProbeError(errChannels, secret)
	}
	return fmt.Sprintf("%d channels", len(quotes)), nil
}

// redactProbeError removes the request address and the credential's own values
// from a probe error before it leaves this package.
//
// Two things can carry a credential into a message. A transport error reports
// the address it failed on, and this platform authenticates with query
// parameters, so the token sits in that address. And the platform's own text can
// repeat what was sent — the client quotes the reply body when it is not the
// JSON envelope it expects, which is how a proxy's error page arrives. A probe
// error is handed to the management surface, so the address is dropped and the
// values are then swept out, which holds on a route into the error this package
// does not control.
func redactProbeError(err error, secret HaozhumaSecret) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = fmt.Errorf("sms: %s to the platform failed: %w", urlErr.Op, urlErr.Err)
	}
	message := err.Error()
	scrubbed := message
	for _, value := range secretValues(secret) {
		scrubbed = strings.ReplaceAll(scrubbed, value, "<redacted>")
	}
	if scrubbed == message {
		return err
	}
	return errors.New(scrubbed)
}

// secretValues lists the parts of a credential that must never appear in a
// message: every field the platform authenticates with, whichever surface it
// belongs to.
//
// Values shorter than four characters are skipped, because replacing one would
// rewrite ordinary words in the message without hiding anything a person could
// not guess.
func secretValues(secret HaozhumaSecret) []string {
	fields := []string{
		secret.Token, secret.User, secret.Pass, secret.Cookie, secret.WebUser, secret.WebPass,
	}
	values := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); len(trimmed) >= 4 {
			values = append(values, trimmed)
		}
	}
	return values
}

// newWebProvider builds a provider for the web surface.
//
// It is deliberately not NewHaozhuma: listing channels never touches the SMS
// API, so it must not require the API token. Only the session cookie is needed,
// which is what makes a cookie-only channel probeable.
func newWebProvider(secret HaozhumaSecret, client *http.Client) (*Haozhuma, error) {
	if strings.TrimSpace(secret.Cookie) == "" {
		return nil, fmt.Errorf("%w: haozhuma web probe needs a session cookie", ErrCredential)
	}
	endpoint, errEndpoint := normalizeEndpoint(secret.Endpoint)
	if errEndpoint != nil {
		return nil, errEndpoint
	}
	if endpoint == "" {
		endpoint = haozhumaDefaultEndpoint
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Haozhuma{secret: secret, http: client, endpoint: endpoint}, nil
}

// probeNotReady marks a pre-flight failure: nothing was sent anywhere, so the
// nature is not ready rather than unreachable.
func probeNotReady(err error) error {
	return fmt.Errorf("%w: %v", ErrProbeUnready, err)
}
