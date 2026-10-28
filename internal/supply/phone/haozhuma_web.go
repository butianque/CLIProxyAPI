package phone

// This file reads haozhuma's web control plane (api.veeto.cn/v1).
//
// The vendor splits its API in two. The documented SMS API (see haozhuma.go)
// rents numbers and reads messages but cannot list channels. The control plane
// can: it lists every channel this account has joined, with the price and the
// stock the platform currently reports for each, and it can join, pause and
// recover channels.
//
// The control plane is a REST service behind the site h5.haozhuma.cn. It
// authenticates with a bearer token minted by its own sign-in (see
// haozhuma_login.go), not with the API token, and it does not bind that token to
// a user agent or an IP, so it is usable from here. Every reply is wrapped in
// {"code","message","data"}; code 0 means success and HTTP 401 means the token
// is no longer valid.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// haozhumaDefaultWebAPI is the control plane's REST base. It is served from
	// its own host, not from the site that fronts it, which is why the site and
	// the API base are two settings rather than one.
	haozhumaDefaultWebAPI = "https://api.veeto.cn/v1"
	// haozhumaWebSite is where a person signs in, for display only.
	haozhumaWebSite = "https://h5.haozhuma.cn"
)

// webAPIBase resolves the control plane base.
//
// web_api names it directly. web_base is the older field and still works as the
// override, except when it points at one of the vendor's own hosts: those named
// the old surface, so following the vendor to its new base is what they meant.
//
// An address that cannot be used at all falls back to the default.
func (h *Haozhuma) webAPIBase() string {
	if base, errBase := normalizeEndpoint(h.secret.WebAPI); errBase == nil && base != "" {
		return base
	}
	if base, errBase := normalizeEndpoint(h.secret.WebBase); errBase == nil && base != "" && !isVendorHost(base) {
		return base
	}
	return haozhumaDefaultWebAPI
}

// vendorHosts are the addresses the vendor itself publishes. A stored web_base
// naming one of them is not an override; it is a value written before the
// control plane moved, and the new base is what it meant.
var vendorHosts = map[string]bool{
	"haozhuma.com":      true,
	"haozhuma.cn":       true,
	"www.haozhuma.com":  true,
	"my.haozhuma.com":   true,
	"h5.haozhuma.com":   true,
	"h5.haozhuma.cn":    true,
	"api.haozhuma.com":  true,
	"api.haozhuma.cn":   true,
	"api.haozhuyun.com": true,
}

// isVendorHost reports whether base names one of the vendor's own hosts.
func isVendorHost(base string) bool {
	parsed, errParse := url.Parse(base)
	if errParse != nil {
		return false
	}
	return vendorHosts[strings.ToLower(parsed.Hostname())]
}

// webToken returns the bearer token the control plane accepts.
//
// A value pasted from the browser console is accepted with or without the
// "Bearer " prefix. The old surface authenticated with a PHPSESSID cookie, so a
// value in cookie form is reported as needing a fresh sign-in instead of being
// sent as a token and rejected as an anonymous request.
func (h *Haozhuma) webToken() (string, error) {
	raw := strings.TrimSpace(h.secret.Cookie)
	if raw == "" {
		return "", fmt.Errorf("%w: haozhuma channel calls need a web session", ErrCredential)
	}
	if strings.Contains(raw, "PHPSESSID=") || strings.Contains(raw, ";") {
		return "", fmt.Errorf("%w: the stored haozhuma web session is a cookie from the old site; sign in again at %s to get a token", ErrCredential, haozhumaWebSite)
	}
	token := raw
	if rest, ok := strings.CutPrefix(token, "Bearer "); ok {
		token = strings.TrimSpace(rest)
	}
	return token, nil
}

// webEnvelope is the reply shape every control-plane call shares.
type webEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// webCall performs one authenticated control-plane call and decodes data into
// out.
//
// A rejected token becomes ErrCredential so the caller can tell "sign in again"
// from "the platform is broken" and keep using its cached channel list.
func (h *Haozhuma) webCall(ctx context.Context, method, path string, body, out any) error {
	token, errToken := h.webToken()
	if errToken != nil {
		return errToken
	}
	return h.webCallWithToken(ctx, token, method, path, body, out)
}

// webCallWithToken is webCall against an explicit token, used to verify a fresh
// sign-in before it is stored. An empty token sends no Authorization header,
// which is what the public captcha endpoint needs.
func (h *Haozhuma) webCallWithToken(ctx context.Context, token, method, path string, body, out any) error {
	envelope, status, errRaw := h.webRaw(ctx, token, method, path, body)
	if errRaw != nil {
		return errRaw
	}
	if status == http.StatusUnauthorized || envelope.Code == http.StatusUnauthorized {
		return fmt.Errorf("%w: haozhuma web session rejected; sign in again", ErrCredential)
	}
	if envelope.Code != 0 {
		message := strings.TrimSpace(envelope.Message)
		if message == "" {
			message = "code " + strconv.Itoa(envelope.Code)
		}
		return fmt.Errorf("sms/haozhuma web: %s %s: %s", method, path, message)
	}
	if out == nil || len(envelope.Data) == 0 {
		return nil
	}
	if errUnmarshal := json.Unmarshal(envelope.Data, out); errUnmarshal != nil {
		return fmt.Errorf("sms/haozhuma web: decode %s: %w", path, errUnmarshal)
	}
	return nil
}

// webRaw performs one control-plane call and returns the undecoded envelope with
// the HTTP status, so a caller that has to read the vendor's own error code can
// do so instead of matching on text.
func (h *Haozhuma) webRaw(ctx context.Context, token, method, path string, body any) (webEnvelope, int, error) {
	var reader io.Reader
	if body != nil {
		encoded, errMarshal := json.Marshal(body)
		if errMarshal != nil {
			return webEnvelope{}, 0, errMarshal
		}
		reader = bytes.NewReader(encoded)
	}
	req, errReq := http.NewRequestWithContext(ctx, method, h.webAPIBase()+path, reader)
	if errReq != nil {
		return webEnvelope{}, 0, errReq
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, errDo := h.http.Do(req)
	if errDo != nil {
		return webEnvelope{}, 0, fmt.Errorf("sms/haozhuma web: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if errRead != nil {
		return webEnvelope{}, resp.StatusCode, fmt.Errorf("sms/haozhuma web: read reply: %w", errRead)
	}
	var envelope webEnvelope
	if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
		// A gateway that answers 401 with an HTML or empty body still means the
		// session is gone, so report it as the vendor's own 401 instead of an
		// opaque transport error the caller cannot classify.
		if resp.StatusCode == http.StatusUnauthorized {
			return webEnvelope{Code: http.StatusUnauthorized}, resp.StatusCode, nil
		}
		return webEnvelope{}, resp.StatusCode, fmt.Errorf("sms/haozhuma web: %s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(string(raw), 200))
	}
	return envelope, resp.StatusCode, nil
}

// webBindingRow is one joined channel. The control plane serves the same row
// shape for the joined list and the project catalogue.
type webBindingRow struct {
	Code        string   `json:"code"`
	ProjectID   string   `json:"projectId"`
	ProjectName string   `json:"projectName"`
	Price       string   `json:"price"`
	Available   int      `json:"available"`
	Operators   []string `json:"operators"`
	Provinces   []string `json:"provinces"`
	Prefixes    []string `json:"prefixes"`
	SegmentType string   `json:"segmentType"`
	Contact     string   `json:"contact"`
	Status      string   `json:"status"`
}

// quote converts one row into a Quote. Status is "joined" or "paused"; any other
// value counts as enabled, so an unknown state never silently hides a usable
// channel.
func (r webBindingRow) quote() Quote {
	price, _ := strconv.ParseFloat(strings.TrimSpace(r.Price), 64)
	return Quote{
		UID:        strings.TrimSpace(r.Code),
		Name:       strings.TrimSpace(r.ProjectName),
		Price:      price,
		Stock:      r.Available,
		Carriers:   strings.Join(r.Operators, "|"),
		Paragraphs: strings.Join(r.Prefixes, "|"),
		Contact:    strings.TrimSpace(r.Contact),
		Paused:     strings.EqualFold(strings.TrimSpace(r.Status), "paused"),
	}
}

// Channels lists the channels this account has joined, ordered cheapest first.
//
// It needs the web session token; without one it reports ErrCredential so the
// caller keeps using its cached list rather than treating the account as broken.
func (h *Haozhuma) Channels(ctx context.Context) ([]Quote, error) {
	token, errToken := h.webToken()
	if errToken != nil {
		return nil, errToken
	}
	const pageSize = 100
	quotes := make([]Quote, 0, 16)
	for page := 1; page <= 20; page++ {
		var payload struct {
			List  []webBindingRow `json:"list"`
			Total int             `json:"total"`
		}
		path := "/bindings?page=" + strconv.Itoa(page) + "&size=" + strconv.Itoa(pageSize)
		if errCall := h.webCallWithToken(ctx, token, http.MethodGet, path, nil, &payload); errCall != nil {
			return nil, errCall
		}
		for _, row := range payload.List {
			if quote := row.quote(); quote.UID != "" {
				quotes = append(quotes, quote)
			}
		}
		if len(payload.List) < pageSize || len(quotes) >= payload.Total {
			break
		}
	}
	SortQuotes(quotes)
	return quotes, nil
}

// ProjectRef is one project the account can rent from.
type ProjectRef struct {
	// Name is the human label, e.g. "讯飞".
	Name string `json:"name"`
	// ID is the numeric project id, which is what the SMS API calls sid and what
	// every channel code is prefixed with.
	ID string `json:"project_id"`
	// Hash is the control plane's project handle, used to list the project's
	// channels.
	Hash string `json:"hash"`
}

// SearchProjects finds projects by name keyword.
//
// The search matches names only: searching by project id or by hash answers
// "项目不存在".
func (h *Haozhuma) SearchProjects(ctx context.Context, keyword string) ([]ProjectRef, error) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return nil, fmt.Errorf("sms/haozhuma web: a project name keyword is required")
	}
	var payload struct {
		List []struct {
			ID   string `json:"id"`
			Hash string `json:"sid"`
			Name string `json:"name"`
		} `json:"list"`
	}
	path := "/projects/search?keyword=" + url.QueryEscape(keyword) + "&size=50"
	if errCall := h.webCall(ctx, http.MethodGet, path, nil, &payload); errCall != nil {
		return nil, errCall
	}
	out := make([]ProjectRef, 0, len(payload.List))
	for _, row := range payload.List {
		out = append(out, ProjectRef{
			Name: strings.TrimSpace(row.Name),
			ID:   strings.TrimSpace(row.ID),
			Hash: strings.TrimSpace(row.Hash),
		})
	}
	return out, nil
}

// FindProject resolves the handle the channel list needs.
//
// The control plane searches by name only, so the keyword has to be the project
// name. The results carry both handles; the numeric id is matched and the hash
// is taken from the same row.
func (h *Haozhuma) FindProject(ctx context.Context, projectID, keyword string) (ProjectRef, error) {
	projectID = strings.TrimSpace(projectID)
	keyword = strings.TrimSpace(keyword)
	if projectID == "" {
		return ProjectRef{}, fmt.Errorf("sms/haozhuma web: a project id is required")
	}
	if keyword == "" {
		return ProjectRef{}, fmt.Errorf("sms/haozhuma web: a project name keyword is required to look up project %s", projectID)
	}
	refs, errSearch := h.SearchProjects(ctx, keyword)
	if errSearch != nil {
		return ProjectRef{}, errSearch
	}
	for _, ref := range refs {
		if ref.ID == projectID || ref.Hash == projectID {
			return ref, nil
		}
	}
	return ProjectRef{}, fmt.Errorf("sms/haozhuma web: project %s not found under keyword %q (%d results)", projectID, keyword, len(refs))
}

// ProjectKeyword reads the project name out of a channel label.
//
// Older labels bracketed the id ("[21614]讯飞"); the control plane serves the
// bare name. Anything between the first pair of brackets is the id, so it is
// skipped and the rest is the name.
func ProjectKeyword(label string) string {
	rest := strings.TrimSpace(label)
	if i := firstIndexAny(rest, ']', '】'); i >= 0 {
		_, size := decodeRuneAt(rest, i)
		rest = rest[i+size:]
	}
	if i := firstIndexAny(rest, '[', '【'); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}

// firstIndexAny returns the byte index of the first occurrence of any needle.
func firstIndexAny(value string, needles ...rune) int {
	best := -1
	for _, needle := range needles {
		index := strings.IndexRune(value, needle)
		if index < 0 {
			continue
		}
		if best < 0 || index < best {
			best = index
		}
	}
	return best
}

// decodeRuneAt returns the rune starting at byte index and its byte width.
func decodeRuneAt(value string, index int) (rune, int) {
	for _, r := range value[index:] {
		return r, len(string(r))
	}
	return 0, 0
}

// isProjectHash reports whether value has the shape of the control plane's
// project handle.
//
// The catalogue is addressed by that handle, never by the numeric id, and the
// service answers a numeric id with an empty list rather than an error. Checking
// the shape here turns that silence into a message.
func isProjectHash(value string) bool {
	if len(value) != 16 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// AllChannels lists every channel of a project, whether or not this account has
// joined it, with the supplier's list price.
//
// A joined channel is one this account already pays for; the rest carry the
// list price and can be joined.
func (h *Haozhuma) AllChannels(ctx context.Context, projectHash string) ([]Quote, error) {
	hash := strings.TrimSpace(projectHash)
	if !isProjectHash(hash) {
		return nil, fmt.Errorf("sms/haozhuma web: project handle %q is not usable; pass the project name and let it be looked up", hash)
	}
	var rows []webBindingRow
	if errCall := h.webCall(ctx, http.MethodGet, "/projects/"+url.PathEscape(hash)+"/public-codes", nil, &rows); errCall != nil {
		return nil, errCall
	}
	out := make([]Quote, 0, len(rows))
	for _, row := range rows {
		quote := row.quote()
		if quote.UID == "" {
			continue
		}
		out = append(out, quote)
	}
	SortQuotes(out)
	return out, nil
}

// JoinChannels joins the given channels to this account.
//
// Joining is free and reversible; the control plane takes a batch of codes, so
// the request is split to keep a single call small. Whichever channels the
// platform accepts are reported back, so a partial success is visible instead of
// being swallowed.
func (h *Haozhuma) JoinChannels(ctx context.Context, uids []string) ([]string, error) {
	if _, errToken := h.webToken(); errToken != nil {
		return nil, errToken
	}
	joined := make([]string, 0, len(uids))
	var lastErr error
	for start := 0; start < len(uids); start += 10 {
		end := min(start+10, len(uids))
		batch := uids[start:end]
		var payload struct {
			Results []struct {
				Code    string `json:"code"`
				OK      bool   `json:"ok"`
				Message string `json:"message"`
			} `json:"results"`
		}
		body := map[string]any{"codes": batch}
		if errCall := h.webCall(ctx, http.MethodPost, "/bindings", body, &payload); errCall != nil {
			lastErr = errCall
			continue
		}
		for _, row := range payload.Results {
			code := strings.TrimSpace(row.Code)
			if row.OK && code != "" {
				joined = append(joined, code)
				continue
			}
			if message := strings.TrimSpace(row.Message); message != "" {
				lastErr = fmt.Errorf("sms/haozhuma web: join %s: %s", code, message)
			}
		}
	}
	if len(joined) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return joined, nil
}

// SetChannelOpen switches one or more joined channels on or off upstream.
//
// The control plane takes one batch action of pause, recover or delete with the
// codes it applies to. Pausing is how the account narrows the platform's
// automatic picker to cheap channels: the platform rents only from joined *and*
// enabled channels, so pausing everything above the ceiling makes even a blind
// rental land on a cheap one. The call is free and reversible.
func (h *Haozhuma) SetChannelOpen(ctx context.Context, action string, uids []string) ([]string, error) {
	if _, errToken := h.webToken(); errToken != nil {
		return nil, errToken
	}
	action = strings.TrimSpace(action)
	var upstream string
	switch action {
	case "pause":
		upstream = "pause"
	case "recover":
		upstream = "recover"
	case "del":
		upstream = "delete"
	default:
		return nil, fmt.Errorf("sms/haozhuma web: unsupported channel action %q", action)
	}
	affected := make([]string, 0, len(uids))
	var lastErr error
	for start := 0; start < len(uids); start += 10 {
		end := min(start+10, len(uids))
		batch := uids[start:end]
		var payload struct {
			Affected int `json:"affected"`
		}
		body := map[string]any{"action": upstream, "codes": batch}
		if errCall := h.webCall(ctx, http.MethodPost, "/bindings/batch", body, &payload); errCall != nil {
			lastErr = errCall
			continue
		}
		affected = append(affected, batch...)
	}
	if len(affected) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return affected, nil
}
