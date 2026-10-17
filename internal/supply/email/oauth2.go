package email

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// OAuth2 is the only way into a Microsoft mailbox: its IMAP server answers
// LOGINDISABLED and advertises AUTH=XOAUTH2 alone, so a password — even an app
// password, which is basic authentication by another name — is refused before
// it is ever checked. What the operator stores instead is a refresh token, which
// is exchanged here for a short-lived access token that the SASL exchange
// carries.
//
// Nothing in this file logs or returns a token, a refresh token, or a client
// id's secret half. The only thing that leaves it is a bearer token handed
// straight to the IMAP client.

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

// cachedToken is one minted access token and when it stops being usable.
type cachedToken struct {
	value   string
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
// the cache has nothing recent.
func oauth2Bearer(ctx context.Context, clientID, refreshToken string) (string, error) {
	clientID = strings.TrimSpace(clientID)
	refreshToken = strings.TrimSpace(refreshToken)
	if clientID == "" {
		return "", errors.New("no OAuth2 application id is configured for this mailbox")
	}
	if refreshToken == "" {
		return "", errors.New("no OAuth2 refresh token is stored for this mailbox")
	}
	// The key includes the refresh token so that replacing it takes effect at
	// once instead of after the previous token expires.
	key := clientID + "\x00" + refreshToken
	accessTokens.mu.Lock()
	cached, ok := accessTokens.tokens[key]
	accessTokens.mu.Unlock()
	if ok && time.Now().Add(oauth2RenewBefore).Before(cached.expires) {
		return cached.value, nil
	}
	value, expires, errMint := oauth2AccessToken(ctx, oauth2TokenURL, clientID, refreshToken)
	if errMint != nil {
		return "", errMint
	}
	accessTokens.mu.Lock()
	// Drop what has already expired: entries are small, but a process that runs
	// for months should not accumulate every token it ever minted.
	for stored, token := range accessTokens.tokens {
		if time.Now().After(token.expires) {
			delete(accessTokens.tokens, stored)
		}
	}
	accessTokens.tokens[key] = cachedToken{value: value, expires: expires}
	accessTokens.mu.Unlock()
	return value, nil
}

// oauth2AccessToken exchanges a refresh token for an access token, and reports
// when it expires.
//
// The refresh grant carries the permissions it was issued with, so no scope is
// sent: the token the operator stores must already have been granted
// IMAP.AccessAsUser.All. The client id goes in the body rather than in a Basic
// header, because this is a public client — there is no secret to send, and
// Microsoft reads the id from the form.
func oauth2AccessToken(ctx context.Context, tokenURL, clientID, refreshToken string) (string, time.Time, error) {
	config := oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{TokenURL: tokenURL, AuthStyle: oauth2.AuthStyleInParams},
	}
	token, errToken := config.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if errToken != nil {
		return "", time.Time{}, describeTokenError(errToken)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return "", time.Time{}, errors.New("the token endpoint returned no access token")
	}
	expires := token.Expiry
	if expires.IsZero() {
		expires = time.Now().Add(oauth2AssumedLifetime)
	}
	return token.AccessToken, expires, nil
}

// describeTokenError turns a refused exchange into something an operator can act
// on.
//
// Only Microsoft's error code is repeated. The description is free text that can
// echo the request, and this string ends up in a channel row and in the probe's
// detail — neither is a place a credential may appear.
func describeTokenError(err error) error {
	var retrieve *oauth2.RetrieveError
	if !errors.As(err, &retrieve) {
		// A transport failure: no response was read, so there is nothing to
		// quote and nothing secret to leak.
		return fmt.Errorf("the token endpoint could not be reached: %w", err)
	}
	switch retrieve.ErrorCode {
	case "invalid_grant":
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
