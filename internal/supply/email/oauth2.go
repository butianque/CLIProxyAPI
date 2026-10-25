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
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
)

// OAuth2 is the only way into a Microsoft mailbox: its IMAP server answers
// LOGINDISABLED and advertises AUTH=XOAUTH2 alone, so a password — even an app
// password, which is basic authentication by another name — is refused before
// it is ever checked. What the operator stores instead is a refresh token, which
// is exchanged here for a short-lived access token that the SASL exchange
// carries.
//
// The same refresh token can also be spent on a Graph token, which is how a
// mailbox whose grant only covers Graph is read. Both are minted here so there
// is one place that talks to the token endpoint.
//
// Nothing in this file logs or returns a token, a refresh token, or a client
// id's secret half. The only thing that leaves it is a bearer token handed
// straight to the protocol client that needs it.

const (
	// oauth2TokenURL is Microsoft's token endpoint. The "common" tenant routes
	// each login to its own tenant, so one endpoint serves both personal
	// Outlook.com accounts and work/school mailboxes.
	oauth2TokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	// oauth2RenewBefore renews a cached token shortly before it expires, so a
	// read that starts just under the deadline does not fail mid-session.
	oauth2RenewBefore = 2 * time.Minute
	// oauth2AssumedLifetime is used when the endpoint returns a token without
	// an expiry. It is deliberately short: re-minting is cheap, and trusting a
	// token that might already be dead is not.
	oauth2AssumedLifetime = 5 * time.Minute
	// maxTokenResponseBytes caps how much of a token response is read. A real
	// answer is about two kilobytes; the cap only stops a wrong endpoint from
	// streaming something unbounded into memory.
	maxTokenResponseBytes = 1 << 20
)

// xoauth2Client is the SASL XOAUTH2 mechanism as Microsoft implements it: one
// initial response carrying the login and the bearer token, no challenge on
// success.
type xoauth2Client struct {
	account string
	token   string
}

// Start returns the mechanism name and its initial response.
func (c xoauth2Client) Start() (string, []byte, error) {
	if strings.TrimSpace(c.token) == "" {
		return "", nil, errors.New("xoauth2: no bearer token")
	}
	// The field separator is 0x01 and the response ends with two of them.
	return "XOAUTH2", []byte("user=" + c.account + "\x01auth=Bearer " + c.token + "\x01\x01"), nil
}

// Next abandons a rejected exchange. A refusal arrives as a challenge (a JSON
// error document); the documented answer is an empty line, after which the
// server sends the tagged NO that carries the reason.
func (c xoauth2Client) Next(challenge []byte) ([]byte, error) {
	return []byte{}, nil
}

// mintedToken is one exchange's answer.
//
// refresh is what the endpoint now considers the current refresh token. It is
// carried alongside the access token because Microsoft's refresh tokens live on
// a sliding window: spending one can hand back a replacement and retire the value
// that was spent. A caller that drops it keeps spending a token the endpoint has
// already stopped honouring.
type mintedToken struct {
	access  string
	refresh string
	expires time.Time
}

// cachedToken is one minted access token, when it stops being usable, and the
// refresh token that was current when it was minted.
type cachedToken struct {
	value   string
	refresh string
	expires time.Time
}

// accessTokens holds minted tokens for their lifetime.
//
// Reading a code is a polling loop: without this, every poll would ask the token
// endpoint for a new token, which is both slower than the read it precedes and a
// good way to get throttled. Tokens are kept in memory only — they live about an
// hour, and persisting them would add a second thing that can go stale.
var accessTokens = struct {
	mu     sync.Mutex
	tokens map[string]cachedToken
}{tokens: map[string]cachedToken{}}

// oauth2Bearer returns a usable access token for one mailbox, minting one when
// the cache has nothing recent. client is the mailbox's egress; nil means the
// package default.
func oauth2Bearer(ctx context.Context, clientID, refreshToken string, client *http.Client) (mintedToken, error) {
	return bearerFor(ctx, "imap", clientID, refreshToken, client)
}

// graphBearer returns a usable Graph access token for one mailbox.
//
// It is a separate token from the IMAP one even though both come from the same
// refresh token: a bearer token is minted for one resource, and the token
// endpoint refuses a scope the original grant never asked for. Graph therefore
// names its scope explicitly, while the IMAP exchange sends none.
func graphBearer(ctx context.Context, clientID, refreshToken string, client *http.Client) (mintedToken, error) {
	return bearerFor(ctx, "graph", clientID, refreshToken, client)
}

// bearerFor mints (or reuses) one access token. kind separates the two
// resources in the cache: an IMAP token is not a Graph token, and handing one to
// the other is a 401 that looks like a bad credential.
func bearerFor(ctx context.Context, kind, clientID, refreshToken string, client *http.Client) (mintedToken, error) {
	clientID = strings.TrimSpace(clientID)
	refreshToken = strings.TrimSpace(refreshToken)
	if clientID == "" {
		return mintedToken{}, errors.New("no OAuth2 application id is configured for this mailbox")
	}
	if refreshToken == "" {
		return mintedToken{}, errors.New("no OAuth2 refresh token is stored for this mailbox")
	}
	// The key includes the refresh token so that replacing it takes effect at
	// once instead of after the previous token expires.
	key := kind + "\x00" + clientID + "\x00" + refreshToken
	accessTokens.mu.Lock()
	cached, ok := accessTokens.tokens[key]
	accessTokens.mu.Unlock()
	if ok && time.Now().Add(oauth2RenewBefore).Before(cached.expires) {
		return mintedToken{access: cached.value, refresh: cached.refresh, expires: cached.expires}, nil
	}
	minted, errMint := mintAccessToken(ctx, kind, clientID, refreshToken, client)
	if errMint != nil {
		return mintedToken{}, errMint
	}
	accessTokens.mu.Lock()
	// Drop what has already expired: entries are small, but a process that runs
	// for months should not accumulate every token it ever minted.
	for stored, token := range accessTokens.tokens {
		if time.Now().After(token.expires) {
			delete(accessTokens.tokens, stored)
		}
	}
	accessTokens.tokens[key] = cachedToken{value: minted.access, refresh: minted.refresh, expires: minted.expires}
	accessTokens.mu.Unlock()
	return minted, nil
}

// persistRefreshToken writes a rotated refresh token back to the entry the
// mailbox reads it from.
//
// This is what keeps a stored mailbox readable without an operator revisiting it:
// Microsoft's refresh tokens expire 90 days after their last use, and spending one
// resets that window. Without the write-back, the copy in the store would age out
// even though the account is in daily use.
//
// The write is deliberately best effort. The read that triggered it already holds
// a working access token, so a failure here must not fail the read; the next read
// tries again with the value it has. entry is a secret-store entry name, never a
// value, so naming it in a log line is safe.
func persistRefreshToken(entry, spent, rotated string) {
	entry = strings.TrimSpace(entry)
	rotated = strings.TrimSpace(rotated)
	if entry == "" || rotated == "" || rotated == strings.TrimSpace(spent) {
		return
	}
	store := secretstore.Default()
	if store == nil || !store.Unlocked() {
		return
	}
	if errSet := store.Set(entry, rotated); errSet != nil {
		logrus.WithError(errSet).WithField("entry", entry).
			Warn("email: the rotated refresh token could not be written back")
	}
}

// mintAccessToken exchanges a refresh token for an access token for one
// resource, and reports when it expires.
//
// The IMAP exchange sends no scope: the refresh grant carries the permissions it
// was issued with, so the token the operator stores must already have been
// granted IMAP.AccessAsUser.All. Graph names its scope because that is the only
// way to ask for a Graph token — the same refresh token is refused when a scope
// outside its original grant is named.
//
// The client id goes in the body rather than in a Basic header, because this is
// a public client: there is no secret to send, and Microsoft reads the id from
// the form.
func mintAccessToken(ctx context.Context, kind, clientID, refreshToken string, client *http.Client) (mintedToken, error) {
	if kind != "graph" {
		return oauth2AccessToken(ctx, oauth2TokenURL, clientID, refreshToken, client)
	}
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("scope", graphScope)
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, oauth2TokenURL, strings.NewReader(form.Encode()))
	if errRequest != nil {
		return mintedToken{}, fmt.Errorf("the token request could not be built: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, errDo := clientOr(graphHTTPClient, client).Do(request)
	if errDo != nil {
		return mintedToken{}, fmt.Errorf("the token endpoint could not be reached: %w", errDo)
	}
	defer func() { _ = response.Body.Close() }()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes))
	if errRead != nil {
		return mintedToken{}, fmt.Errorf("the token response could not be read: %w", errRead)
	}
	var payload struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &payload)
	if response.StatusCode != http.StatusOK || strings.TrimSpace(payload.AccessToken) == "" {
		// The body is handed to the error describer, which quotes only the
		// error code: a response body is not a place a credential may reach.
		return mintedToken{}, describeTokenError(&oauth2.RetrieveError{
			ErrorCode:        payload.Error,
			ErrorDescription: payload.ErrorDescription,
			Response:         response,
			Body:             body,
		}, "graph")
	}
	expires := time.Now().Add(oauth2AssumedLifetime)
	if payload.ExpiresIn > 0 {
		expires = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	}
	return mintedToken{access: payload.AccessToken, refresh: payload.RefreshToken, expires: expires}, nil
}

// oauth2AccessToken exchanges a refresh token for an access token, and reports
// when it expires.
//
// The refresh grant carries the permissions it was issued with, so no scope is
// sent: the token the operator stores must already have been granted
// IMAP.AccessAsUser.All. The client id goes in the body rather than in a Basic
// header, because this is a public client — there is no secret to send, and
// Microsoft reads the id from the form.
func oauth2AccessToken(ctx context.Context, tokenURL, clientID, refreshToken string, client *http.Client) (mintedToken, error) {
	config := oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{TokenURL: tokenURL, AuthStyle: oauth2.AuthStyleInParams},
	}
	// x/oauth2 reads its HTTP client from the context, so the mailbox's exit
	// travels with the exchange rather than being fixed package-wide.
	if client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	token, errToken := config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if errToken != nil {
		return mintedToken{}, describeTokenError(errToken, "imap")
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return mintedToken{}, errors.New("the token endpoint returned no access token")
	}
	// The exchange succeeds even when the grant only covers Graph: without a
	// named scope Microsoft hands back whatever the grant has, and the IMAP
	// server then answers a bare "AUTHENTICATE failed". Reporting that as a bad
	// credential sends the operator looking for a new mailbox when the fix is to
	// pick the other receiving method, so the granted scopes are checked here.
	if granted, ok := token.Extra("scope").(string); ok && strings.TrimSpace(granted) != "" &&
		!strings.Contains(strings.ToLower(granted), "imap") {
		return mintedToken{}, errors.New("the refresh token was not granted IMAP access; choose Graph as the receiving method")
	}
	expires := token.Expiry
	if expires.IsZero() {
		expires = time.Now().Add(oauth2AssumedLifetime)
	}
	// x/oauth2 keeps whatever refresh token the endpoint returned, so a rotation
	// arrives here without extra parsing.
	return mintedToken{access: token.AccessToken, refresh: token.RefreshToken, expires: expires}, nil
}

// describeTokenError turns a refused exchange into something an operator can act
// on.
//
// Only Microsoft's error code is repeated. The description is free text that can
// echo the request, and this string ends up in a channel row and in the probe's
// detail — neither is a place a credential may appear.
//
// The one description fragment that is read is AADSTS70000/65001: that is the
// answer for "the grant does not cover the scope this exchange asked for", which
// is not an expired credential and must not be reported as one — the operator's
// next step is the other receiving method, not a new mailbox.
func describeTokenError(err error, kind string) error {
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) {
		// A transport failure: no response was read, so there is nothing to
		// quote and nothing secret to leak.
		return fmt.Errorf("the token endpoint could not be reached: %w", err)
	}
	switch retrieve.ErrorCode {
	case "invalid_grant":
		if strings.Contains(retrieve.ErrorDescription, "AADSTS70000") ||
			strings.Contains(retrieve.ErrorDescription, "AADSTS65001") {
			if kind == "graph" {
				return errors.New("the refresh token was not granted Graph access")
			}
			return errors.New("the refresh token was not granted IMAP access; choose Graph as the receiving method")
		}
		return errors.New("the refresh token was rejected: it has expired or been revoked")
	case "invalid_client":
		return errors.New("the application id was rejected")
	case "unauthorized_client":
		return errors.New("this application is not allowed to read mail for this account")
	case "invalid_request", "invalid_scope":
		return errors.New("the token request was refused")
	}
	if retrieve.ErrorCode != "" {
		return fmt.Errorf("the token endpoint answered %q", retrieve.ErrorCode)
	}
	if retrieve.Response != nil {
		return fmt.Errorf("the token endpoint answered %d", retrieve.Response.StatusCode)
	}
	return errors.New("the token endpoint answered without a reason")
}
