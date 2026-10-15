package phone

// This file reads haozhuma's web surface (h5.haozhuma.com/api.php).
//
// The vendor splits its API in two. The documented SMS API (see haozhuma.go)
// rents numbers and reads messages but cannot list channels. The web API can:
// type=3 returns every channel this account has joined, with the price and the
// stock the platform currently reports for each.
//
// The web API is authenticated by a browser session cookie (PHPSESSID) rather
// than the API token, and it does not bind that cookie to a user agent or an IP,
// so it is usable from here. Web sign-in itself is behind a click-order captcha
// and cannot be automated, but the cookie outlives a password change only until
// it expires; the operator refreshes it occasionally.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// haozhumaDefaultWebBase is the web surface host.
const haozhumaDefaultWebBase = "https://h5.haozhuma.com"

// webBase resolves the web host.
//
// A web_base written without a scheme is completed the same way the API
// endpoint is, so "h5.haozhuma.com" reaches the web surface instead of failing
// as a scheme-less URL. An address that cannot be used at all falls back to the
// platform host, which is the host this surface would use anyway.
func (h *Haozhuma) webBase() string {
	base, errBase := normalizeEndpoint(h.secret.WebBase)
	if errBase != nil || base == "" {
		return haozhumaDefaultWebBase
	}
	return base
}

// Channels lists the channels this account has joined, ordered cheapest first.
//
// It needs the session cookie from the secret; without one it reports
// ErrCredential so the caller keeps using its cached list rather than treating
// the account as broken.
func (h *Haozhuma) Channels(ctx context.Context) ([]Quote, error) {
	var payload struct {
		Code json.RawMessage `json:"code"`
		Msg  string          `json:"msg"`
		Data []webChannelRow `json:"data"`
	}
	if errGet := h.webGet(ctx, "type=3", &payload); errGet != nil {
		return nil, errGet
	}
	if strings.Trim(strings.TrimSpace(string(payload.Code)), `"`) != "200" {
		message := strings.TrimSpace(payload.Msg)
		if message == "" {
			message = "channel list rejected"
		}
		return nil, fmt.Errorf("%w: haozhuma web session: %s", ErrCredential, message)
	}

	quotes := make([]Quote, 0, len(payload.Data))
	for _, row := range payload.Data {
		quote := row.quote()
		if quote.UID == "" {
			continue
		}
		quotes = append(quotes, quote)
	}
	SortQuotes(quotes)
	return quotes, nil
}

// webChannelRow is one row of type=3.
type webChannelRow struct {
	UID      string `json:"uid"`
	Name     string `json:"mc"`
	Price    string `json:"yhj"`
	Stock    string `json:"zxky"`
	Carriers string `json:"yyy"`
	Prefixes string `json:"hd"`
	Contact  string `json:"lxfs"`
	State    string `json:"djzt"`
}

// quote converts one web row into a Quote. The stock arrives as a label such as
// "可用数量:19", so only its digits are meaningful. The state arrives as a label
// such as "已对接" (enabled) or "已暂停" (switched off); anything other than the
// paused label counts as enabled, so an unknown state never silently hides a
// usable channel.
func (r webChannelRow) quote() Quote {
	price, _ := strconv.ParseFloat(strings.TrimSpace(r.Price), 64)
	return Quote{
		UID:        strings.TrimSpace(r.UID),
		Name:       strings.TrimSpace(r.Name),
		Price:      price,
		Stock:      leadingInt(r.Stock),
		Carriers:   strings.TrimSpace(r.Carriers),
		Paragraphs: strings.TrimSpace(r.Prefixes),
		Contact:    strings.TrimSpace(r.Contact),
		Paused:     isPausedState(r.State),
	}
}

// isPausedState reports whether a 对接状态 label means the channel is switched
// off. The platform's own wording is "已暂停"; anything else (notably "已对接")
// means enabled.
func isPausedState(state string) bool {
	return strings.Contains(strings.TrimSpace(state), "暂停")
}

// leadingInt extracts the trailing integer from a label such as "可用数量:19".
func leadingInt(label string) int {
	digits := strings.Builder{}
	seen := false
	for _, r := range label {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
			seen = true
		case seen:
			value, _ := strconv.Atoi(digits.String())
			return value
		}
	}
	value, _ := strconv.Atoi(digits.String())
	return value
}

// ProjectRef is one project the account can rent from.
type ProjectRef struct {
	// Name is the human label, e.g. "【21614】讯飞".
	Name string `json:"name"`
	// ID is the numeric project id, which is what the SMS API calls sid.
	ID string `json:"project_id"`
	// Hash is the web surface's project handle, the hex inside the name, used to
	// list the project's channels.
	Hash string `json:"hash"`
}

// SearchProjects finds projects by name keyword.
//
// The web surface only searches by name: searching by project id or by hash
// returns "没有该项目". The returned label embeds both handles — the numeric
// project id and, in brackets, the hash — so both are extracted here.
func (h *Haozhuma) SearchProjects(ctx context.Context, keyword string) ([]ProjectRef, error) {
	var payload struct {
		Code json.RawMessage `json:"code"`
		Msg  string          `json:"msg"`
		Data []struct {
			Name string `json:"name"`
			Hash string `json:"sid"`
		} `json:"data"`
	}
	if errGet := h.webGet(ctx, "type=30&gjc="+url.QueryEscape(keyword), &payload); errGet != nil {
		return nil, errGet
	}
	if strings.Trim(strings.TrimSpace(string(payload.Code)), `"`) != "1" {
		return nil, fmt.Errorf("sms/haozhuma web: project search %q: %s", keyword, strings.TrimSpace(payload.Msg))
	}
	out := make([]ProjectRef, 0, len(payload.Data))
	for _, row := range payload.Data {
		name := strings.TrimSpace(row.Name)
		id := ""
		if value := leadingInt(name); value > 0 {
			id = strconv.Itoa(value)
		}
		out = append(out, ProjectRef{
			Name: name,
			ID:   id,
			Hash: strings.TrimSpace(row.Hash),
		})
	}
	return out, nil
}

// FindProject resolves the hash the channel list needs.
//
// The web surface searches by name only: searching by the project id, or by the
// hash itself, answers "没有该项目". The label it returns carries both handles —
// "【21614】讯飞 [8e41d296bf0c4969]" — so the results are matched on the numeric
// id and the hash is taken from the match.
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
		if ref.ID == projectID {
			return ref, nil
		}
	}
	return ProjectRef{}, fmt.Errorf("sms/haozhuma web: project %s not found under keyword %q (%d results)", projectID, keyword, len(refs))
}

// ProjectKeyword reads the project name out of a channel label.
//
// The two surfaces bracket the project id differently: the joined list uses
// "[21614]讯飞", while the project search uses "【21614】讯飞   [8e41d296bf0c4969]".
// So the id group is skipped by its closing bracket (either style) and the name
// is everything up to the next opening one.
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

// AllChannels lists every channel of a project, whether or not this account has
// joined it, with the supplier's list price.
//
// A joined channel is one this account already pays for; the rest carry the
// list price and can be joined.
func (h *Haozhuma) AllChannels(ctx context.Context, projectHash string) ([]Quote, error) {
	var payload struct {
		Code json.RawMessage `json:"code"`
		Msg  string          `json:"msg"`
		Data []struct {
			UID      string `json:"uid"`
			Name     string `json:"mc"`
			Price    string `json:"yhj"`
			Stock    string `json:"zxky"`
			Carriers string `json:"yyy"`
			Prefixes string `json:"hd"`
			Contact  string `json:"lxfs"`
			Open     string `json:"open"`
		} `json:"data"`
	}
	if errGet := h.webGet(ctx, "type=8&sid="+url.QueryEscape(projectHash), &payload); errGet != nil {
		return nil, errGet
	}
	if strings.Trim(strings.TrimSpace(string(payload.Code)), `"`) != "1" {
		return nil, fmt.Errorf("sms/haozhuma web: channel list: %s", strings.TrimSpace(payload.Msg))
	}
	out := make([]Quote, 0, len(payload.Data))
	for _, row := range payload.Data {
		price, _ := strconv.ParseFloat(strings.TrimSpace(row.Price), 64)
		out = append(out, Quote{
			UID:        strings.TrimSpace(row.UID),
			Name:       strings.TrimSpace(row.Name),
			Price:      price,
			Stock:      leadingInt(row.Stock),
			Carriers:   strings.TrimSpace(row.Carriers),
			Paragraphs: strings.TrimSpace(row.Prefixes),
			Contact:    strings.TrimSpace(row.Contact),
		})
	}
	SortQuotes(out)
	return out, nil
}

// JoinChannels joins the given channels to this account.
//
// Joining is free and reversible; the web surface batches at most ten per call,
// so the request is split. Whichever channels the surface accepts are reported
// back, so a partial success is visible instead of being swallowed.
func (h *Haozhuma) JoinChannels(ctx context.Context, uids []string) ([]string, error) {
	if cookie := strings.TrimSpace(h.secret.Cookie); cookie == "" {
		return nil, fmt.Errorf("%w: joining channels needs a web session cookie", ErrCredential)
	}
	joined := make([]string, 0, len(uids))
	var lastErr error
	for start := 0; start < len(uids); start += 10 {
		end := min(start+10, len(uids))
		batch := uids[start:end]
		var payload struct {
			Code json.RawMessage `json:"code"`
			Msg  string          `json:"msg"`
			Data []struct {
				UID    string `json:"uid"`
				Status string `json:"status"`
			} `json:"data"`
		}
		query := "type=43&djm=" + url.QueryEscape(strings.Join(batch, ","))
		if errGet := h.webGet(ctx, query, &payload); errGet != nil {
			lastErr = errGet
			continue
		}
		code := strings.Trim(strings.TrimSpace(string(payload.Code)), `"`)
		if code != "200" {
			lastErr = fmt.Errorf("sms/haozhuma web: join channels: %s", strings.TrimSpace(payload.Msg))
			continue
		}
		for _, row := range payload.Data {
			if uid := strings.TrimSpace(row.UID); uid != "" {
				joined = append(joined, uid)
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
// The platform exposes it as type=41 with an `open` action of pause, recover or
// del and a comma-separated uid list. Pausing is how the account narrows the
// platform's automatic picker to cheap channels: the platform rents only from
// joined *and* enabled channels, so pausing everything above the ceiling makes
// even a blind rental land on a cheap one. The call is free and reversible.
//
// Joining batches at ten per call; pausing uses the same bound.
func (h *Haozhuma) SetChannelOpen(ctx context.Context, action string, uids []string) ([]string, error) {
	if cookie := strings.TrimSpace(h.secret.Cookie); cookie == "" {
		return nil, fmt.Errorf("%w: switching channels needs a web session cookie", ErrCredential)
	}
	action = strings.TrimSpace(action)
	switch action {
	case "pause", "recover", "del":
	default:
		return nil, fmt.Errorf("sms/haozhuma web: unsupported channel action %q", action)
	}
	affected := make([]string, 0, len(uids))
	var lastErr error
	for start := 0; start < len(uids); start += 10 {
		end := min(start+10, len(uids))
		batch := uids[start:end]
		var payload struct {
			Code json.RawMessage `json:"code"`
			Msg  string          `json:"msg"`
		}
		query := "type=41&open=" + url.QueryEscape(action) + "&uid=" + url.QueryEscape(strings.Join(batch, ","))
		if errGet := h.webGet(ctx, query, &payload); errGet != nil {
			lastErr = errGet
			continue
		}
		if strings.Trim(strings.TrimSpace(string(payload.Code)), `"`) != "200" {
			lastErr = fmt.Errorf("sms/haozhuma web: %s channels: %s", action, strings.TrimSpace(payload.Msg))
			continue
		}
		affected = append(affected, batch...)
	}
	if len(affected) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return affected, nil
}

// webGet performs one GET against the web surface and decodes JSON into into.
func (h *Haozhuma) webGet(ctx context.Context, query string, into any) error {
	cookie := strings.TrimSpace(h.secret.Cookie)
	if cookie == "" {
		return fmt.Errorf("%w: haozhuma web call needs a session cookie", ErrCredential)
	}
	return h.webGetWithCookie(ctx, cookie, query, into)
}

// webLoginURL is where the operator signs in to refresh the cookie, for display
// in an error message.
func (h *Haozhuma) webLoginURL() string {
	base := h.webBase()
	if parsed, errParse := url.Parse(base); errParse == nil && parsed.Host != "" {
		return base
	}
	return haozhumaDefaultWebBase
}
