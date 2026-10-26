package email

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// This file reads a mailbox through Microsoft Graph instead of IMAP.
//
// Why a second transport exists: what a refresh token can do is decided by the
// grant it was issued with, not by the mailbox. A token minted for Graph scopes
// (Mail.ReadWrite, Mail.Send, User.ReadWrite) is refused by the IMAP server with
// a plain "AUTHENTICATE failed", and the token endpoint refuses to mint an IMAP
// token from it — the same credential, a different answer depending on who is
// asked. A channel that only speaks IMAP therefore cannot use such a token at
// all, and reporting it as a bad credential would be wrong.
//
// The read is deliberately the same shape as the IMAP one: same folder choice,
// same address matching, same code extraction. Only the transport differs, so a
// caller never needs to know which one produced a message.

const (
	// graphBaseURL is Graph's fixed endpoint. A channel stores no endpoint of its
	// own for this transport, because there is nothing to configure.
	graphBaseURL = "https://graph.microsoft.com/v1.0"
	// graphScope asks for a Graph token. It must be named: the token endpoint
	// refuses a scope the original grant never asked for, so a silent request
	// would be answered for whatever the grant happened to cover.
	graphScope = "https://graph.microsoft.com/.default"
	// graphMessageSelect is the smallest projection that still answers every
	// question a verification read asks: who sent it, who it was addressed to,
	// when it arrived, what it says, and the trace headers a forward leaves.
	graphMessageSelect = "id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,internetMessageHeaders"
	// graphFolderLimit caps the folder listing. A mailbox has tens of folders,
	// not thousands; the cap only stops a paging loop that never ends.
	graphFolderLimit = 100
	// graphBodyBytes bounds one message body. Graph returns the whole text, and
	// a newsletter runs to tens of kilobytes; nothing beyond this is read for a
	// code.
	graphBodyBytes = maxBodyBytes
)

// graphHTTPClient is the client every Graph call uses. The timeout covers one
// request; the caller's context still bounds the whole read.
var graphHTTPClient = &http.Client{Timeout: dialTimeout}

// AuthGraph is declared in mailbox.go next to the other modes; this comment
// records why it is not simply "oauth2": the credential is the same refresh
// token, but the resource it buys is different, and the two are not
// interchangeable.

// graphSession is one mailbox opened through Graph.
type graphSession struct {
	account  string
	clientID string
	refresh  string
	token    string

	// secretName is the store entry the refresh token came from. A rotation is
	// written back there; an empty name means the credential was supplied
	// directly (a probe), so there is nothing to write back to.
	secretName string

	// http is the mailbox's exit. Graph holds no connection of its own, so this
	// is the only thing that decides where the reads come from.
	http *http.Client

	// folders maps a lowercased display name to the folder id Graph wants in the
	// path. It is filled on first use: a scan asks for two folders, and listing
	// them once is cheaper than resolving each name with its own request.
	folders map[string]string
	mu      sync.Mutex
}

// dialGraphSession mints the first token and returns the session.
//
// The token is minted here rather than on the first read so a credential that
// cannot be exchanged fails at dial time — which is what the probe reports, and
// what makes "cannot log in" a different answer from "cannot read".
func dialGraphSession(ctx context.Context, target Target) (Session, error) {
	if strings.TrimSpace(target.Account) == "" {
		return nil, fmt.Errorf("%w: no mailbox account", ErrProbeUnready)
	}
	if strings.TrimSpace(target.ClientID) == "" {
		return nil, fmt.Errorf("%w: no OAuth2 application id", ErrProbeUnready)
	}
	if strings.TrimSpace(target.Password) == "" {
		return nil, fmt.Errorf("%w: no mailbox credential", ErrProbeUnready)
	}
	client, errClient := clientForEgress(target.Egress)
	if errClient != nil {
		return nil, fmt.Errorf("%w: %v", ErrProbeUnready, errClient)
	}
	token, errToken := graphBearer(ctx, target.ClientID, target.Password, client)
	if errToken != nil {
		return nil, fmt.Errorf("%w: %v", dialRefusal(errToken), errToken)
	}
	// A rotation has to reach the store as soon as it is seen: the value the
	// session carries is the one that works, and leaving the old one behind would
	// make the mailbox unreadable after the next restart.
	persistRefreshToken(target.SecretName, target.Password, token.refresh)
	refresh := target.Password
	if strings.TrimSpace(token.refresh) != "" {
		refresh = token.refresh
	}
	return &graphSession{
		account:    target.Account,
		clientID:   target.ClientID,
		refresh:    refresh,
		secretName: target.SecretName,
		token:      token.access,
		http:       client,
	}, nil
}

// Mailboxes lists the account's folders by display name.
//
// The names are the ones a person sees in Outlook, and the same names the IMAP
// path reports for a Microsoft mailbox, so the caller's junk-folder heuristic
// works without a second rule.
func (s *graphSession) Mailboxes(ctx context.Context) ([]string, error) {
	ids, names, errList := s.listFolders(ctx)
	if errList != nil {
		return nil, errList
	}
	s.mu.Lock()
	s.folders = ids
	s.mu.Unlock()
	return names, nil
}

// Recent reads the messages of one folder that arrived after a point.
//
// Graph has no UID, so a position here is an arrival time: "strictly later than
// the one already handed out". Strictness is what keeps a poll from returning
// the same message twice. The validity is always zero, because Graph has no
// folder generation to invalidate a position.
func (s *graphSession) Recent(ctx context.Context, mailbox string, since time.Time, after FolderPosition, limit int) ([]Mail, uint32, error) {
	target, errTarget := s.folderTarget(ctx, mailbox)
	if errTarget != nil {
		return nil, 0, errTarget
	}
	query := url.Values{}
	if strings.TrimSpace(after.Received) != "" {
		query.Set("$filter", "receivedDateTime gt "+strings.TrimSpace(after.Received))
	} else {
		query.Set("$filter", "receivedDateTime ge "+since.UTC().Format(time.RFC3339))
	}
	query.Set("$select", graphMessageSelect)
	query.Set("$orderby", "receivedDateTime desc")
	if limit > 0 {
		query.Set("$top", fmt.Sprint(limit))
	}
	address := graphBaseURL + "/me/mailFolders/" + url.PathEscape(target) + "/messages?" + query.Encode()

	var payload struct {
		Value []graphMessage `json:"value"`
	}
	if errGet := s.get(ctx, address, &payload); errGet != nil {
		return nil, 0, errGet
	}
	mails := make([]Mail, 0, len(payload.Value))
	for _, message := range payload.Value {
		mails = append(mails, message.toMail(mailbox))
	}
	return mails, 0, nil
}

// Close ends the session. Graph holds no connection of its own, so there is
// nothing to tear down; the method exists to satisfy Session.
func (s *graphSession) Close() error {
	return nil
}

// folderTarget turns a folder name into what Graph accepts in the path: a
// well-known name when the folder is one, otherwise the id of that display name.
func (s *graphSession) folderTarget(ctx context.Context, mailbox string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(mailbox))
	if name == "" {
		name = "inbox"
	}
	if wellKnown, ok := graphWellKnownFolders[name]; ok {
		return wellKnown, nil
	}
	s.mu.Lock()
	known := s.folders
	s.mu.Unlock()
	if known == nil {
		ids, _, errList := s.listFolders(ctx)
		if errList != nil {
			return "", errList
		}
		s.mu.Lock()
		s.folders = ids
		s.mu.Unlock()
		known = ids
	}
	if id, ok := known[name]; ok {
		return id, nil
	}
	// A folder the account does not have is not a read failure worth stopping
	// the whole scan: the caller reads the next folder instead.
	return "", fmt.Errorf("email: the mailbox has no folder %q", mailbox)
}

// listFolders reads the folder list once, as an id map and as display names.
func (s *graphSession) listFolders(ctx context.Context) (map[string]string, []string, error) {
	address := fmt.Sprintf("%s/me/mailFolders?$select=displayName&$top=%d", graphBaseURL, graphFolderLimit)
	var payload struct {
		Value []struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if errGet := s.get(ctx, address, &payload); errGet != nil {
		return nil, nil, errGet
	}
	ids := make(map[string]string, len(payload.Value))
	names := make([]string, 0, len(payload.Value))
	for _, folder := range payload.Value {
		ids[strings.ToLower(strings.TrimSpace(folder.DisplayName))] = folder.ID
		names = append(names, folder.DisplayName)
	}
	return ids, names, nil
}

// get performs one authenticated GET and decodes the JSON answer.
//
// A 401 is re-minted once: a token can expire between the dial and a later
// folder read, and failing there would report a healthy mailbox as broken.
func (s *graphSession) get(ctx context.Context, address string, into any) error {
	for attempt := 0; attempt < 2; attempt++ {
		request, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if errRequest != nil {
			return fmt.Errorf("email: the Graph request could not be built: %w", errRequest)
		}
		request.Header.Set("Authorization", "Bearer "+s.token)
		request.Header.Set("Accept", "application/json")
		// Ask for the plain-text body: the code is in the text, and reducing HTML
		// after the fact would throw away exactly the whitespace that separates a
		// code from the words around it.
		request.Header.Set("Prefer", `outlook.body-content-type="text"`)
		response, errDo := clientOr(graphHTTPClient, s.http).Do(request)
		if errDo != nil {
			return fmt.Errorf("email: Graph could not be reached: %w", errDo)
		}
		body, errRead := io.ReadAll(io.LimitReader(response.Body, maxMailBytes))
		_ = response.Body.Close()
		if errRead != nil {
			return fmt.Errorf("email: the Graph answer could not be read: %w", errRead)
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			minted, errToken := graphBearer(ctx, s.clientID, s.refresh, s.http)
			if errToken != nil {
				return fmt.Errorf("%w: %v", ErrLoginRejected, errToken)
			}
			persistRefreshToken(s.secretName, s.refresh, minted.refresh)
			if strings.TrimSpace(minted.refresh) != "" {
				s.refresh = minted.refresh
			}
			s.token = minted.access
			continue
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("email: Graph answered %d: %s", response.StatusCode, graphErrorText(body))
		}
		if errUnmarshal := json.Unmarshal(body, into); errUnmarshal != nil {
			return fmt.Errorf("email: the Graph answer could not be parsed: %w", errUnmarshal)
		}
		return nil
	}
	return fmt.Errorf("%w: Graph refused the access token", ErrLoginRejected)
}

// graphErrorText pulls Graph's own message out of an error body. It is a short
// human sentence; the body is not otherwise repeated, because it can echo the
// request that was sent.
func graphErrorText(body []byte) string {
	var failure struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if errUnmarshal := json.Unmarshal(body, &failure); errUnmarshal != nil {
		return "no reason was given"
	}
	message := strings.TrimSpace(failure.Error.Message)
	if index := strings.IndexByte(message, '\n'); index >= 0 {
		message = message[:index]
	}
	if len(message) > 200 {
		message = message[:200]
	}
	if message == "" {
		return failure.Error.Code
	}
	return message
}

// graphWellKnownFolders are the folder names Graph accepts directly in a path,
// keyed the way a display name looks when lowercased.
var graphWellKnownFolders = map[string]string{
	"inbox":                "inbox",
	"junk":                 "junkemail",
	"junk email":           "junkemail",
	"junk e-mail":          "junkemail",
	"deleted items":        "deleteditems",
	"trash":                "deleteditems",
	"drafts":               "drafts",
	"sent items":           "sentitems",
	"outbox":               "outbox",
	"archive":              "archive",
	"conversation history": "conversationhistory",
}

// graphMessage is one message as Graph returns it under graphMessageSelect.
type graphMessage struct {
	ID           string           `json:"id"`
	Subject      string           `json:"subject"`
	ReceivedTime string           `json:"receivedDateTime"`
	From         *graphRecipient  `json:"from"`
	ToRecipients []graphRecipient `json:"toRecipients"`
	CcRecipients []graphRecipient `json:"ccRecipients"`
	Body         graphBody        `json:"body"`
	Headers      []graphHeader    `json:"internetMessageHeaders"`
}

// graphRecipient is one entry of a recipient list.
type graphRecipient struct {
	EmailAddress graphEmailAddress `json:"emailAddress"`
}

// graphEmailAddress is the address half of a Graph recipient or sender.
type graphEmailAddress struct {
	Address string `json:"address"`
}

// graphBody is a message body, either text or HTML.
type graphBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

// graphHeader is one internet message header.
type graphHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// toMail reduces a Graph message to the same shape the IMAP parser produces.
//
// UID is left at zero: it is an IMAP concept (stable within one folder), and
// Graph identifies a message by its own id instead. Nothing downstream reads it.
func (m graphMessage) toMail(mailbox string) Mail {
	from := ""
	if m.From != nil {
		from = m.From.EmailAddress.Address
	}
	displayed := make([]string, 0, len(m.ToRecipients)+len(m.CcRecipients))
	parts := make([]string, 0, 8+len(m.Headers))
	for _, recipient := range m.ToRecipients {
		address := recipient.EmailAddress.Address
		displayed = append(displayed, address)
		parts = append(parts, address)
	}
	for _, recipient := range m.CcRecipients {
		address := recipient.EmailAddress.Address
		displayed = append(displayed, address)
		parts = append(parts, address)
	}
	// A forwarded message keeps the original recipient in a trace header, so the
	// same set of headers the IMAP path reads is collected here. Graph returns
	// the headers it considers interesting, which for a forwarded message
	// includes the delivery trace.
	for _, header := range m.Headers {
		if !isRecipientHeader(header.Name) {
			continue
		}
		trimmed := strings.TrimSpace(header.Value)
		if trimmed == "" {
			continue
		}
		parts = append(parts, trimmed)
		// Only the addressing headers name a recipient a person would show; a
		// Received line is for matching, not for display.
		if !showsRecipient(header.Name) {
			continue
		}
		displayed = append(displayed, addressesIn(trimmed)...)
	}
	text := m.Body.Content
	if len(text) > graphBodyBytes {
		text = text[:graphBodyBytes]
	}
	// The links are read from the raw body, before htmlToText drops the tags:
	// a Graph message that hands out a sign-in link instead of a code is
	// unreadable once the href is gone.
	var links []string
	if strings.EqualFold(m.Body.ContentType, "html") {
		links = extractLinks(text, "")
		text = htmlToText(text)
	} else {
		links = extractLinks("", text)
	}
	date, _ := time.Parse(time.RFC3339, strings.TrimSpace(m.ReceivedTime))
	return Mail{
		Mailbox:  mailbox,
		From:     from,
		To:       dedupeAddresses(displayed),
		Subject:  m.Subject,
		Text:     text,
		Date:     date,
		Code:     ExtractCode(m.Subject, text),
		Links:    links,
		haystack: strings.ToLower(strings.Join(append(parts, from), "\n")),
	}
}

// isRecipientHeader reports whether a header can name the address a message was
// sent to.
func isRecipientHeader(name string) bool {
	for _, candidate := range recipientHeaders {
		if strings.EqualFold(candidate, name) {
			return true
		}
	}
	return false
}

// showsRecipient reports whether a recipient header carries an address worth
// displaying. Received and Return-Path lines name a server, not a recipient, so
// they only feed the matching haystack.
func showsRecipient(name string) bool {
	switch {
	case strings.EqualFold(name, "To"),
		strings.EqualFold(name, "Cc"),
		strings.EqualFold(name, "Delivered-To"),
		strings.EqualFold(name, "X-Original-To"):
		return true
	}
	return false
}

// dedupeAddresses keeps the first occurrence of each address, case-insensitively.
func dedupeAddresses(addresses []string) []string {
	seen := make(map[string]bool, len(addresses))
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		trimmed := strings.TrimSpace(address)
		key := strings.ToLower(trimmed)
		if trimmed == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, trimmed)
	}
	return out
}

var _ Session = (*graphSession)(nil)
