package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// This file is the only way to obtain a refresh token without already having
// one.
//
// Every other exchange in this package spends a credential the operator already
// holds. A mailbox bought as nothing but an address has none, so the OAuth2
// device authorization grant (RFC 8628) is what Microsoft offers for that case:
// the operator reads a short code, types it on Microsoft's own page, and the
// endpoint hands back a refresh token. From then on the mailbox is an ordinary
// OAuth2 identity and nothing else here treats it differently.
//
// The one step this file cannot do, and must not try to do, is the sign-in
// itself. The short code exists so that a person proves on Microsoft's page that
// they hold the account; automating that would mean driving the page with the
// account password, which is both outside what the flow is for and the pattern
// Microsoft's abuse scoring is built to catch. Everything around that step —
// asking for the code, polling, exchanging it, and storing the result — is
// automatic.
//
// Nothing here logs a token. The short code and the verification address are the
// only values that leave through anything but the return value.

const (
	// microsoftDeviceCodeURL is where a device authorization starts. The
	// "common" tenant routes each login to its own tenant, so one endpoint
	// serves personal Outlook.com accounts and work/school mailboxes alike.
	microsoftDeviceCodeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
	// deviceCodeGrantType is the grant a device authorization is redeemed with.
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"
	// deviceCodeScope is what a mailbox authorization asks for, and it is
	// deliberately wider than the read path needs.
	//
	// Mail.Read is what makes the mailbox readable. User.Read exists only so the
	// answer can be checked against the account that was asked for: the endpoint
	// never says which mailbox was signed in to, so without a way to ask, a
	// request naming one account could store another account's token under it.
	// offline_access is what makes a refresh token come back at all.
	deviceCodeScope = "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read offline_access"
	// defaultDevicePollInterval is used when the endpoint names no interval. It
	// is RFC 8628's own default.
	defaultDevicePollInterval = 5 * time.Second
	// deviceSlowDownStep is added to the interval each time the endpoint answers
	// slow_down, as RFC 8628 §3.5 requires.
	deviceSlowDownStep = 5 * time.Second
	// maxDevicePollInterval caps that backoff. A polling loop that grows without
	// a bound stops noticing an approval that arrived.
	maxDevicePollInterval = 60 * time.Second
)

// Device authorization failures a caller has to tell apart from a real error.
// Neither is a failure: one means "keep waiting", the other "wait longer".
var (
	// ErrDevicePending means the person has not finished signing in yet.
	ErrDevicePending = errors.New("email: the sign-in is still pending")
	// ErrDeviceSlowDown asks the caller to poll less often.
	ErrDeviceSlowDown = errors.New("email: the sign-in poll must slow down")
)

// DeviceAuthorization is one pending sign-in: the short code a person types,
// where they type it, and how long that stays possible.
type DeviceAuthorization struct {
	// DeviceCode is the opaque value redeemed for a token. It is never shown.
	DeviceCode string
	// UserCode is the short code the person reads out.
	UserCode string
	// VerifyURL is the page the code is typed on.
	VerifyURL string
	// ExpiresIn is how long the code stays usable.
	ExpiresIn time.Duration
	// Interval is how often the endpoint allows a poll.
	Interval time.Duration
}

// DeviceToken is the answer to a completed authorization.
type DeviceToken struct {
	// AccessToken is short-lived and only used to check the identity.
	AccessToken string
	// RefreshToken is the credential worth keeping.
	RefreshToken string
	// Expires is when the access token stops working.
	Expires time.Time
}

// GraphIdentity is who a Graph access token belongs to.
//
// Two addresses are reported because a consumer mailbox answers to both and
// either may be the one an operator typed: "mail" is the primary alias, while
// "userPrincipalName" is the login name, which for a personal account is the
// same mailbox under a different domain.
type GraphIdentity struct {
	Mail              string
	UserPrincipalName string
}

// Addresses lists the addresses this identity answers to, lowercased, without
// duplicates and without empty entries.
func (i GraphIdentity) Addresses() []string {
	out := make([]string, 0, 2)
	for _, candidate := range []string{i.Mail, i.UserPrincipalName} {
		trimmed := strings.ToLower(strings.TrimSpace(candidate))
		if trimmed == "" {
			continue
		}
		if len(out) == 1 && out[0] == trimmed {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

// RequestDeviceCode starts one device authorization.
//
// deviceCodeURL is a parameter rather than the constant so a test can point it at
// a local server, which is the same seam oauth2AccessToken already offers for the
// token endpoint.
func RequestDeviceCode(ctx context.Context, deviceCodeURL, clientID, scope string, client *http.Client) (DeviceAuthorization, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return DeviceAuthorization{}, errors.New("email: no application id to start a sign-in with")
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", strings.TrimSpace(scope))
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(deviceCodeURL), strings.NewReader(form.Encode()))
	if errRequest != nil {
		return DeviceAuthorization{}, fmt.Errorf("email: the sign-in request could not be built: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, errDo := clientOr(graphHTTPClient, client).Do(request)
	if errDo != nil {
		return DeviceAuthorization{}, fmt.Errorf("the sign-in service could not be reached: %w", errDo)
	}
	defer func() { _ = response.Body.Close() }()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes))
	if errRead != nil {
		return DeviceAuthorization{}, fmt.Errorf("the sign-in answer could not be read: %w", errRead)
	}
	var payload struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Error           string `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	if response.StatusCode != http.StatusOK || strings.TrimSpace(payload.DeviceCode) == "" || strings.TrimSpace(payload.UserCode) == "" {
		return DeviceAuthorization{}, describeDeviceStart(payload.Error, response.StatusCode)
	}
	authorization := DeviceAuthorization{
		DeviceCode: strings.TrimSpace(payload.DeviceCode),
		UserCode:   strings.TrimSpace(payload.UserCode),
		VerifyURL:  strings.TrimSpace(payload.VerificationURI),
		ExpiresIn:  time.Duration(payload.ExpiresIn) * time.Second,
		Interval:   time.Duration(payload.Interval) * time.Second,
	}
	if authorization.ExpiresIn <= 0 {
		// No expiry means the code is unusable rather than eternal: a caller
		// that trusted a zero would poll forever.
		authorization.ExpiresIn = defaultDevicePollInterval
	}
	if authorization.Interval <= 0 {
		authorization.Interval = defaultDevicePollInterval
	}
	return authorization, nil
}

// PollDeviceToken redeems the device code once.
//
// The caller drives the loop: this makes one request and reports either a token,
// ErrDevicePending, ErrDeviceSlowDown, or a failure. Keeping the loop out of here
// is what lets a caller stop waiting without a request hanging, and lets the
// waiting be bounded by its own deadline rather than by an HTTP timeout.
func PollDeviceToken(ctx context.Context, tokenURL, clientID, deviceCode string, client *http.Client) (DeviceToken, error) {
	form := url.Values{}
	form.Set("client_id", strings.TrimSpace(clientID))
	form.Set("grant_type", deviceCodeGrantType)
	form.Set("device_code", strings.TrimSpace(deviceCode))
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(tokenURL), strings.NewReader(form.Encode()))
	if errRequest != nil {
		return DeviceToken{}, fmt.Errorf("email: the sign-in poll could not be built: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, errDo := clientOr(graphHTTPClient, client).Do(request)
	if errDo != nil {
		return DeviceToken{}, fmt.Errorf("the token endpoint could not be reached: %w", errDo)
	}
	defer func() { _ = response.Body.Close() }()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes))
	if errRead != nil {
		return DeviceToken{}, fmt.Errorf("the token response could not be read: %w", errRead)
	}
	var payload struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &payload)
	switch payload.Error {
	case "":
		// Fall through to the success checks below.
	case "authorization_pending":
		return DeviceToken{}, ErrDevicePending
	case "slow_down":
		return DeviceToken{}, ErrDeviceSlowDown
	case "expired_token", "code_expired", "bad_verification_code":
		return DeviceToken{}, errors.New("the sign-in code expired before it was used")
	case "access_denied", "authorization_declined":
		return DeviceToken{}, errors.New("the sign-in was declined")
	default:
		// Only the error code is quoted: the description is free text that can
		// echo the request, and this string reaches an operator's screen.
		return DeviceToken{}, describeTokenError(&oauth2.RetrieveError{
			ErrorCode:        payload.Error,
			ErrorDescription: payload.ErrorDescription,
			Response:         response,
			Body:             body,
		}, "graph")
	}
	if response.StatusCode != http.StatusOK || strings.TrimSpace(payload.AccessToken) == "" {
		return DeviceToken{}, fmt.Errorf("the token endpoint answered %d without an access token", response.StatusCode)
	}
	if strings.TrimSpace(payload.RefreshToken) == "" {
		// This is a real failure and a specific one: the authorization completed
		// but the grant did not carry offline_access, so the token it produced
		// dies within the hour and the whole sign-in has to be repeated.
		return DeviceToken{}, errors.New("the sign-in returned no refresh token; the authorization did not include offline_access")
	}
	expires := time.Now().Add(oauth2AssumedLifetime)
	if payload.ExpiresIn > 0 {
		expires = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	}
	return DeviceToken{
		AccessToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		Expires:      expires,
	}, nil
}

// VerifyAccount asks Graph who an access token belongs to.
//
// It exists because the device authorization never names the account: the answer
// carries a token and nothing else. Without this check, an import that asked for
// one address and was signed in to another would store that other account's
// refresh token under the requested address, and every later read of the
// requested address would return someone else's mail.
func VerifyAccount(ctx context.Context, graphURL, accessToken string, client *http.Client) (GraphIdentity, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return GraphIdentity{}, errors.New("email: no access token to identify the account with")
	}
	address := strings.TrimRight(strings.TrimSpace(graphURL), "/") + "/me?$select=mail,userPrincipalName"
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if errRequest != nil {
		return GraphIdentity{}, fmt.Errorf("email: the identity request could not be built: %w", errRequest)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")
	response, errDo := clientOr(graphHTTPClient, client).Do(request)
	if errDo != nil {
		return GraphIdentity{}, fmt.Errorf("Graph could not be reached: %w", errDo)
	}
	defer func() { _ = response.Body.Close() }()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes))
	if errRead != nil {
		return GraphIdentity{}, fmt.Errorf("the identity answer could not be read: %w", errRead)
	}
	if response.StatusCode != http.StatusOK {
		// The status is enough. The body can echo the bearer token's claims, and
		// this message reaches an operator's screen.
		return GraphIdentity{}, fmt.Errorf("the signed-in account could not be identified (Graph answered %d)", response.StatusCode)
	}
	var payload struct {
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return GraphIdentity{}, fmt.Errorf("the identity answer could not be parsed: %w", errUnmarshal)
	}
	identity := GraphIdentity{
		Mail:              strings.TrimSpace(payload.Mail),
		UserPrincipalName: strings.TrimSpace(payload.UserPrincipalName),
	}
	if len(identity.Addresses()) == 0 {
		return GraphIdentity{}, errors.New("the signed-in account reported no address")
	}
	return identity, nil
}

// describeDeviceStart turns a refused authorization start into something an
// operator can act on. Only the error code is repeated, never the description.
func describeDeviceStart(code string, status int) error {
	switch code {
	case "invalid_client", "unauthorized_client":
		return errors.New("the application id cannot start a sign-in for this kind of account")
	case "invalid_scope":
		return errors.New("the sign-in permissions were refused")
	case "invalid_request":
		return errors.New("the sign-in request was refused")
	}
	if strings.TrimSpace(code) != "" {
		return fmt.Errorf("the sign-in could not be started (%s)", code)
	}
	return fmt.Errorf("the sign-in could not be started (%d)", status)
}

// The three exported wrappers below are what a caller outside this package uses.
// They take the mailbox's egress rather than an HTTP client, because the client
// pool is this package's own business: a sign-in has to leave from the same
// address the mailbox will later be read from, or Microsoft sees the
// authorization and the first read arriving from two different places.

// RequestMailboxAuthorization starts a device authorization through a mailbox
// exit.
func RequestMailboxAuthorization(ctx context.Context, egress, clientID string) (DeviceAuthorization, error) {
	client, errClient := clientForEgress(egress)
	if errClient != nil {
		return DeviceAuthorization{}, errClient
	}
	return RequestDeviceCode(ctx, microsoftDeviceCodeURL, clientID, deviceCodeScope, client)
}

// PollMailboxAuthorization redeems a device code once, through a mailbox exit.
func PollMailboxAuthorization(ctx context.Context, egress, clientID, deviceCode string) (DeviceToken, error) {
	client, errClient := clientForEgress(egress)
	if errClient != nil {
		return DeviceToken{}, errClient
	}
	return PollDeviceToken(ctx, oauth2TokenURL, clientID, deviceCode, client)
}

// VerifyMailboxAccount asks Graph who a freshly minted token belongs to, through
// a mailbox exit.
func VerifyMailboxAccount(ctx context.Context, egress, accessToken string) (GraphIdentity, error) {
	client, errClient := clientForEgress(egress)
	if errClient != nil {
		return GraphIdentity{}, errClient
	}
	return VerifyAccount(ctx, graphBaseURL, accessToken, client)
}
