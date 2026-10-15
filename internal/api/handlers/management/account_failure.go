package management

import (
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Failure classes answer "what should be done about this failure", which is why
// a failed quota probe and an exhausted account are different classes: one calls
// for another probe, the other for another account.
const (
	failureClassAuth     = "auth"
	failureClassQuota    = "quota"
	failureClassRisk     = "risk"
	failureClassRate     = "rate"
	failureClassNetwork  = "network"
	failureClassRequest  = "request"
	failureClassUpstream = "upstream"
)

// credentialFailureCodeClasses maps an error code to a failure class. It is an
// explicit table on purpose: the codes are the fixed vocabulary the host and its
// plugins emit as Error.Code, and guessing a class from an arbitrary string would
// turn a provider's wording into routing behaviour. Every key below has a
// producer in this repository.
//
// A generic code carries no class and therefore stays out of this table. Both
// plugins report "the provider refused" as upstream_error (or
// upstream_business_error) with the upstream status attached, and zcode folds its
// numeric business codes into that status before the host ever sees them. Pinning
// those codes to a class here would hide the status, which is the only signal
// that separates rate limiting from a request fault from an upstream outage.
var credentialFailureCodeClasses = map[string]string{
	// Host scheduler codes.
	coreauth.ErrorCodeRequestScoped:       failureClassRequest,
	coreauth.ErrorCodeConnectionLifecycle: failureClassNetwork,
	coreauth.ErrorCodeTransientTransport:  failureClassNetwork,

	// Host refresh and result codes.
	"unauthorized":    failureClassAuth,
	"model_not_found": failureClassRequest,

	// Plugin codes. Loomy has no numeric error vocabulary, so each of its strings
	// is placed here by hand; zcode's credential faults arrive as the same shape.
	"invalid_auth":       failureClassAuth,
	"session_expired":    failureClassAuth,
	"missing_credential": failureClassAuth,
	"invalid_request":    failureClassRequest,
	"missing_phone":      failureClassRequest,
	"not_found":          failureClassRequest,
	"sms_unavailable":    failureClassUpstream,
	"sms_failed":         failureClassUpstream,
	"sms_no_number":      failureClassUpstream,
}

// credentialStatusMessageClasses maps the status messages the host writes itself
// to a failure class. Only exact matches count; a status message that is not in
// this table is reported without a class rather than guessed at. Every key here
// is a literal the cooldown and refresh paths assign to Auth.StatusMessage, so a
// plugin that puts its own text there cannot steer the class.
//
// "disabled via management API" is deliberately absent: an operator-disabled
// credential is not a failure, and the view reports that state separately.
var credentialStatusMessageClasses = map[string]string{
	"invalid_grant":                        failureClassAuth,
	"invalid grant (retrying)":             failureClassAuth,
	"unauthorized":                         failureClassAuth,
	"unauthorized (refresh token invalid)": failureClassAuth,
	"disabled":                             failureClassAuth,
	"disabled (invalid grant)":             failureClassAuth,
	"token expired":                        failureClassAuth,
	"quota exhausted":                      failureClassQuota,
	"quota":                                failureClassQuota,
	"credential_quota":                     failureClassQuota,
	"payment_required":                     failureClassQuota,
	"cloudflare challenge":                 failureClassRisk,
	"not_found":                            failureClassRequest,
	"transient upstream error":             failureClassUpstream,
	"request failed":                       failureClassUpstream,
}

// credentialFailureClass classifies a credential's last failure. It reads the
// structured error first, then the status message the host wrote, then the HTTP
// status the provider returned. A failure it cannot place is an upstream fault,
// which is the honest default: it says "the provider refused, we do not know
// why" without claiming the credential itself is bad.
//
// It returns "" when there is no failure to classify.
func credentialFailureClass(lastErr *coreauth.Error, statusMessage string) string {
	if lastErr != nil {
		if class, ok := credentialFailureCodeClasses[strings.ToLower(strings.TrimSpace(lastErr.Code))]; ok {
			return class
		}
		if class := failureClassFromHTTPStatus(lastErr.HTTPStatus); class != "" {
			return class
		}
	}
	if class, ok := credentialStatusMessageClasses[strings.TrimSpace(statusMessage)]; ok {
		return class
	}
	if lastErr != nil {
		return failureClassUpstream
	}
	return ""
}

// failureClassFromHTTPStatus places a provider response by its status code. It
// only runs on a structured error, where the status came from the provider.
func failureClassFromHTTPStatus(status int) string {
	switch {
	case status == 401 || status == 403:
		return failureClassAuth
	case status == 402:
		return failureClassQuota
	case status == 429:
		return failureClassRate
	case status == 408:
		return failureClassNetwork
	case status >= 400 && status < 500:
		return failureClassRequest
	case status >= 500:
		return failureClassUpstream
	}
	return ""
}

// Patterns that strip anything able to carry a secret out of a failure reason
// live in internal/logging: the reason goes through the same redaction and
// bounding the logs use, because a plugin can embed an upstream response body in
// a status message.
