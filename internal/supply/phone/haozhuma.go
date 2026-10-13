package phone

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// haozhumaDefaultEndpoint is the SMS API host. The vendor publishes three
// equivalent hosts (api.haozhuma.cn, api.haozhuma.com and api.haozhuyun.com)
// behind the same token; all three answer identically.
const haozhumaDefaultEndpoint = "https://api.haozhuma.cn"

// HaozhumaSecret is the decrypted shape of the "haozhuma" host secret.
type HaozhumaSecret struct {
	// User is the API account name. Only needed when Token is absent: the token
	// is then fetched once and cached.
	User string `json:"api_user,omitempty"`
	// Pass is the API password used by api=login.
	Pass string `json:"api_pass,omitempty"`
	// Token is the account-level fixed token: the value every other call
	// authenticates with. It never changes unless the password does.
	Token string `json:"token,omitempty"`
	// Cookie is the web session cookie (PHPSESSID=...). The web surface needs
	// it to list joined channels; without it channel refresh is skipped and the
	// cached list is used.
	Cookie string `json:"cookie,omitempty"`
	// WebUser and WebPass are the operator's browser sign-in for the web
	// surface. They are a different account from the API key above: the API
	// credential rents numbers, while the web account is what mints the session
	// cookie. They are only needed when the cookie must be refreshed
	// automatically; a pasted cookie works without them.
	WebUser string `json:"web_user,omitempty"`
	WebPass string `json:"web_pass,omitempty"`
	// Endpoint overrides the API host, e.g. https://api.haozhuma.com.
	Endpoint string `json:"endpoint,omitempty"`
	// WebBase overrides the web host, e.g. https://h5.haozhuma.com.
	WebBase string `json:"web_base,omitempty"`
}

// ParseHaozhumaSecret decodes the host secret value. The value is a JSON object
// so the credential can carry more than a token without a schema change.
func ParseHaozhumaSecret(value string) (HaozhumaSecret, error) {
	var secret HaozhumaSecret
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return secret, fmt.Errorf("%w: haozhuma secret is empty", ErrCredential)
	}
	if errUnmarshal := json.Unmarshal([]byte(trimmed), &secret); errUnmarshal != nil {
		return secret, fmt.Errorf("%w: haozhuma secret is not a JSON object", ErrCredential)
	}
	return secret, nil
}

// ParseHaozhumaCookie decodes the separate web-session secret into the Cookie
// and optional WebBase fields. The value may be either a JSON object ({"cookie":
// "...", "web_base": "..."}) or the bare cookie string, so an operator can paste
// whatever the browser gives them.
func ParseHaozhumaCookie(value string) (HaozhumaSecret, error) {
	var secret HaozhumaSecret
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return secret, fmt.Errorf("%w: haozhuma cookie secret is empty", ErrCredential)
	}
	if strings.HasPrefix(trimmed, "{") {
		if errUnmarshal := json.Unmarshal([]byte(trimmed), &secret); errUnmarshal != nil {
			return secret, fmt.Errorf("%w: haozhuma cookie secret is not a JSON object", ErrCredential)
		}
		return secret, nil
	}
	secret.Cookie = trimmed
	return secret, nil
}

// Haozhuma is the haozhuma (豪猪) provider.
//
// The vendor runs two surfaces: a documented SMS API (fixed token, no login
// flow, what this provider uses) and an undocumented web API that additionally
// exposes channel search/join. Only the SMS API is used for renting, so a
// provider never needs a browser session.
type Haozhuma struct {
	secret   HaozhumaSecret
	http     *http.Client
	endpoint string

	mu    sync.Mutex
	token string
}

// NewHaozhuma builds a provider from a decrypted secret.
func NewHaozhuma(secret HaozhumaSecret, client *http.Client) (*Haozhuma, error) {
	secret.User = strings.TrimSpace(secret.User)
	secret.Pass = strings.TrimSpace(secret.Pass)
	secret.Token = strings.TrimSpace(secret.Token)
	if secret.Token == "" && (secret.User == "" || secret.Pass == "") {
		return nil, fmt.Errorf("%w: haozhuma needs a token, or a user and password to fetch one", ErrCredential)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(secret.Endpoint), "/")
	if endpoint == "" {
		endpoint = haozhumaDefaultEndpoint
	}
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Haozhuma{secret: secret, http: client, endpoint: endpoint}, nil
}

// ID implements Provider.
func (h *Haozhuma) ID() string { return "haozhuma" }

// Endpoint returns the resolved API host, for diagnostics.
func (h *Haozhuma) Endpoint() string { return h.endpoint }

// reply is the shared envelope of every haozhuma SMS API response. The vendor
// returns the business fields at the top level, next to code and msg, rather
// than nesting them under a data key.
type reply struct {
	Code json.RawMessage `json:"code"`
	Msg  string          `json:"msg"`
	// SMS and YZM are getMessage's.
	SMS string `json:"sms"`
	YZM string `json:"yzm"`
	// Phone, SID, SP and GSD are getPhone's.
	Phone string          `json:"phone"`
	SID   json.RawMessage `json:"sid"`
	SP    string          `json:"sp"`
	GSD   string          `json:"phone_gsd"`
	UID   json.RawMessage `json:"uid"`
	// Money is getSummary's.
	Money string `json:"money"`
	// Token is login's.
	Token string `json:"token"`
}

// codeString normalises the code field, which the vendor sends as either a
// number or a string depending on the endpoint.
func (r reply) codeString() string {
	return strings.Trim(strings.TrimSpace(string(r.Code)), `"`)
}

// ok reports whether the reply is a success. The vendor uses 0 and 200 across
// different endpoints.
func (r reply) ok() bool {
	switch r.codeString() {
	case "0", "200":
		return true
	default:
		return false
	}
}

// jsonText renders a possibly-string, possibly-number JSON scalar as text.
func jsonText(raw json.RawMessage) string {
	return strings.Trim(strings.TrimSpace(string(raw)), `"`)
}

// get performs one GET against the SMS API and decodes the envelope. A
// non-success code becomes an error carrying the vendor's own message.
func (h *Haozhuma) get(ctx context.Context, params url.Values, withToken bool) (reply, error) {
	if withToken {
		token, errToken := h.ensureToken(ctx)
		if errToken != nil {
			return reply{}, errToken
		}
		params.Set("token", token)
	}
	requestURL := h.endpoint + "/sms/?" + params.Encode()
	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if errReq != nil {
		return reply{}, errReq
	}
	resp, errDo := h.http.Do(req)
	if errDo != nil {
		return reply{}, fmt.Errorf("sms/haozhuma: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()

	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return reply{}, fmt.Errorf("sms/haozhuma: read body: %w", errRead)
	}
	var decoded reply
	if errUnmarshal := json.Unmarshal(body, &decoded); errUnmarshal != nil {
		return reply{}, fmt.Errorf("sms/haozhuma: HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	if !decoded.ok() {
		message := strings.TrimSpace(decoded.Msg)
		if message == "" {
			message = "code=" + decoded.codeString()
		}
		return decoded, fmt.Errorf("sms/haozhuma: %s", message)
	}
	return decoded, nil
}

// ensureToken returns the fixed token, fetching it from the API account and
// password once when the secret carries credentials instead of a token.
//
// The token is stable ("it does not change unless the password does"), so it is
// fetched once and cached in memory for the process lifetime.
func (h *Haozhuma) ensureToken(ctx context.Context) (string, error) {
	if token := strings.TrimSpace(h.secret.Token); token != "" {
		return token, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.token != "" {
		return h.token, nil
	}
	token, errLogin := h.login(ctx)
	if errLogin != nil {
		return "", errLogin
	}
	h.token = token
	return token, nil
}

// login performs the api=login call.
func (h *Haozhuma) login(ctx context.Context) (string, error) {
	if h.secret.User == "" || h.secret.Pass == "" {
		return "", fmt.Errorf("%w: haozhuma needs a token, or api_user and api_pass", ErrCredential)
	}
	params := url.Values{}
	params.Set("api", "login")
	params.Set("user", h.secret.User)
	params.Set("pass", h.secret.Pass)

	decoded, errGet := h.get(ctx, params, false)
	if errGet != nil {
		return "", errGet
	}
	token := strings.TrimSpace(decoded.Token)
	if token == "" {
		return "", fmt.Errorf("%w: haozhuma login returned no token", ErrCredential)
	}
	return token, nil
}

// Balance implements Provider.
func (h *Haozhuma) Balance(ctx context.Context) (float64, error) {
	params := url.Values{}
	params.Set("api", "getSummary")
	decoded, errGet := h.get(ctx, params, true)
	if errGet != nil {
		return 0, errGet
	}
	value, errParse := strconv.ParseFloat(strings.TrimSpace(decoded.Money), 64)
	if errParse != nil {
		return 0, fmt.Errorf("sms/haozhuma: balance %q is not a number", decoded.Money)
	}
	return value, nil
}

// Rent implements Provider. A non-empty uid pins the rental to that channel; an
// empty one lets the platform pick among the joined channels.
func (h *Haozhuma) Rent(ctx context.Context, project Project, uid string) (Number, error) {
	params := url.Values{}
	params.Set("api", "getPhone")
	params.Set("sid", strings.TrimSpace(project.SID))
	if channel := firstNonEmpty(uid, project.Code); channel != "" {
		params.Set("uid", channel)
	}
	decoded, errGet := h.get(ctx, params, true)
	if errGet != nil {
		return Number{}, errGet
	}
	return h.number(decoded, project), nil
}

// AcquirePhone implements Provider: re-occupy one exact number.
func (h *Haozhuma) AcquirePhone(ctx context.Context, project Project, phone string) (Number, error) {
	params := url.Values{}
	params.Set("api", "getPhone")
	params.Set("sid", strings.TrimSpace(project.SID))
	params.Set("phone", strings.TrimSpace(phone))
	decoded, errGet := h.get(ctx, params, true)
	if errGet != nil {
		return Number{}, errGet
	}
	return h.number(decoded, project), nil
}

// number reads the getPhone payload into a Number.
func (h *Haozhuma) number(decoded reply, project Project) Number {
	sid := jsonText(decoded.SID)
	if sid == "" {
		sid = project.SID
	}
	return Number{
		Phone:   strings.TrimSpace(decoded.Phone),
		SID:     sid,
		Code:    jsonText(decoded.UID),
		Carrier: strings.TrimSpace(decoded.SP),
		Region:  strings.TrimSpace(decoded.GSD),
	}
}

// Read implements Provider.
func (h *Haozhuma) Read(ctx context.Context, project Project, phone string) (Message, error) {
	params := url.Values{}
	params.Set("api", "getMessage")
	params.Set("sid", strings.TrimSpace(project.SID))
	params.Set("phone", strings.TrimSpace(phone))
	decoded, errGet := h.get(ctx, params, true)
	if errGet != nil {
		// "No message yet" is the ordinary polling outcome and arrives through
		// the same error path as a real failure, so anything that would not fail
		// every call is reported as not-ready instead.
		if IsFatal(errGet) {
			return Message{}, errGet
		}
		return Message{}, ErrNotReady
	}
	code := strings.TrimSpace(decoded.YZM)
	text := strings.TrimSpace(decoded.SMS)
	if code == "" && text == "" {
		return Message{}, ErrNotReady
	}
	return Message{Ready: true, Code: code, Text: text}, nil
}

// Release implements Provider.
func (h *Haozhuma) Release(ctx context.Context, project Project, phone string) error {
	params := url.Values{}
	params.Set("api", "cancelRecv")
	params.Set("sid", strings.TrimSpace(project.SID))
	params.Set("phone", strings.TrimSpace(phone))
	_, errGet := h.get(ctx, params, true)
	return errGet
}

// Blacklist implements Provider.
func (h *Haozhuma) Blacklist(ctx context.Context, project Project, phone string) error {
	params := url.Values{}
	params.Set("api", "addBlacklist")
	params.Set("sid", strings.TrimSpace(project.SID))
	params.Set("phone", strings.TrimSpace(phone))
	_, errGet := h.get(ctx, params, true)
	return errGet
}

// firstNonEmpty returns the first non-blank candidate.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// truncate shortens a string for an error message.
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// MaskIdentifier renders an account name as a recognisable but non-revealing
// label, so the panel can show "which account is stored" without ever receiving
// the account itself.
//
// The shape is first two and last two runes around a fixed-width gap: short
// values collapse to a bare mask, and long values keep their ends. It is a
// display aid, not a security boundary — the store remains the boundary.
func MaskIdentifier(value string) string {
	runes := []rune(strings.TrimSpace(value))
	switch {
	case len(runes) == 0:
		return ""
	case len(runes) <= 4:
		return "••••"
	case len(runes) <= 6:
		return string(runes[:1]) + "••••"
	default:
		return string(runes[:2]) + "••••" + string(runes[len(runes)-2:])
	}
}
