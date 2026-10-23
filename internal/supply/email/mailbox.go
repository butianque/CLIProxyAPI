// Package email is the host-side email supply source: it reads a real mailbox
// over IMAP and hands out verification codes from what it finds there.
//
// The shape it serves is "one mailbox, many addresses". A catch-all domain
// forwards every "*@example.com" into a single mailbox, so the addresses are
// infinite while the connection is one; that is why a read takes an address to
// look for instead of being bound to one. This is also why an IMAP source needs
// no pool: nothing is rented and nothing is returned.
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/mail"
)

// Errors that a caller has to tell apart. A rejected login is a credential
// problem, and reporting it as an unreachable mailbox sends the operator
// looking at their network instead of their authorization code.
var (
	ErrLoginRejected = errors.New("email: the mailbox rejected the login")
	ErrProbeUnready  = errors.New("email: the mailbox credential is not usable")
	ErrCredential    = errors.New("email: the mailbox credential is not available")
)

const (
	// dialTimeout bounds the connection handshake only. Once a mailbox is open,
	// the caller's context bounds the work.
	dialTimeout = 20 * time.Second
	// maxMailBytes skips a message that is almost certainly not a verification
	// mail. A code is never carried in a 2 MB attachment.
	maxMailBytes = 2 << 20
	// maxBodyBytes bounds one message part. Bodies are read for their text, and
	// a truncated body still contains the code when it is near the top.
	maxBodyBytes = 256 << 10
	// defaultPort is used when the stored endpoint has no port.
	defaultPort = "993"
)

// Mail is one message read out of a mailbox, reduced to what a verification
// flow needs. The raw message is deliberately not kept: it is large, it can
// contain attachments, and nothing downstream reads it.
type Mail struct {
	// Mailbox is the folder the message was found in.
	Mailbox string
	// ChannelID is the configured channel whose mailbox carried it.
	ChannelID string
	// UID is the message's IMAP UID, stable within its folder.
	UID uint32
	// From is the sender address.
	From string
	// To lists the recipient addresses the message carries, in header order.
	To []string
	// Subject is the decoded subject.
	Subject string
	// Text is the plain-text body, or the HTML body reduced to text.
	Text string
	// Date is the message date, falling back to the internal date.
	Date time.Time
	// Code is the verification code the message states, or "".
	Code string

	// haystack is every address-bearing string the message carries, lowercased,
	// used for the "was this addressed to me" question. Forwarding rewrites the
	// To header and leaves the original recipient in a trace header, so matching
	// has to look at all of them rather than at To alone.
	haystack string
}

// Mentions reports whether the message was addressed to address, in any of the
// forms a forwarded message carries.
func (m Mail) Mentions(address string) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return true
	}
	return strings.Contains(m.haystack, address)
}

// AuthMode is how a mailbox session proves who it is.
type AuthMode string

const (
	// AuthPassword sends the mailbox's authorization code, which is what an
	// IMAP LOGIN command carries.
	AuthPassword AuthMode = ""
	// AuthOAuth2 sends a bearer token minted from a refresh token. Microsoft
	// mailboxes refuse LOGIN outright — their server answers LOGINDISABLED and
	// advertises AUTH=XOAUTH2 alone — so this is the only way into them.
	AuthOAuth2 AuthMode = "oauth2"
	// AuthGraph reads the same mailbox through Microsoft Graph's REST API
	// instead of IMAP. It is not a second way to authenticate — the credential
	// is still a refresh token — but a different resource: a token whose grant
	// covers Graph scopes is refused by the IMAP server, and the token endpoint
	// will not mint an IMAP token from it.
	AuthGraph AuthMode = "graph"
)

// Target is one configured mailbox the host can read.
type Target struct {
	// ChannelID is the channel the target came from, reported back so a caller
	// can tell which configuration produced an answer.
	ChannelID string
	// Label is the channel's display name.
	Label string
	// Host is "host" or "host:port".
	Host string
	// Account is the mailbox's login name.
	Account string
	// Auth is how the session authenticates. The zero value is a password,
	// which is what every non-Microsoft mailbox needs.
	Auth AuthMode
	// ClientID is the OAuth2 application the refresh token belongs to. Only
	// read when Auth is AuthOAuth2.
	ClientID string
	// Password is the authorization code, or — under AuthOAuth2 — the refresh
	// token. It is filled in right before dialling and never stored on the
	// target.
	Password string
	// Domain is the catch-all domain whose mail lands in this mailbox.
	Domain string
	// Usage is "personal" or "self-domain".
	Usage string
	// SecretName is the secret-store entry the credential is read from.
	SecretName string
	// Egress is the proxy this mailbox exits through, resolved from the
	// channel's connection and falling back to the supply-wide setting. Empty
	// inherits the process environment.
	Egress string
}

// Covers reports whether an address could arrive at this mailbox: either it is
// the mailbox's own address, or it belongs to the catch-all domain.
func (t Target) Covers(address string) bool {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(t.Account), address) {
		return true
	}
	domain := strings.ToLower(strings.TrimSpace(t.Domain))
	if domain == "" {
		return false
	}
	return strings.HasSuffix(address, "@"+domain)
}

// Session is one open mailbox connection. The provider depends on this rather
// than on the IMAP client, so its read logic can be exercised without a server.
type Session interface {
	// Mailboxes lists the folders the account holds.
	Mailboxes(ctx context.Context) ([]string, error)
	// Recent reads the messages of one folder that arrived after a point, and
	// reports the folder's validity so the caller can tell a position that still
	// holds from one that a mailbox reset invalidated.
	Recent(ctx context.Context, mailbox string, since time.Time, after FolderPosition, limit int) ([]Mail, uint32, error)
	// Close ends the session.
	Close() error
}

// imapSession is the IMAP implementation of Session.
type imapSession struct {
	client *imapclient.Client
}

// dialSession opens an authenticated session with the protocol the target names.
func dialSession(ctx context.Context, target Target) (Session, error) {
	if target.Auth == AuthGraph {
		return dialGraphSession(ctx, target)
	}
	address := strings.TrimSpace(target.Host)
	if address == "" {
		return nil, errors.New("email: the mailbox has no host")
	}
	host, port, errSplit := net.SplitHostPort(address)
	if errSplit != nil {
		host, port = address, defaultPort
	}
	dial, errDialer := dialForEgress(target.Egress)
	if errDialer != nil {
		return nil, fmt.Errorf("email: the mailbox exit is misconfigured: %w", errDialer)
	}
	conn, errDial := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if errDial != nil {
		return nil, fmt.Errorf("email: cannot reach %s: %w", address, errDial)
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
	if errHandshake := tlsConn.HandshakeContext(ctx); errHandshake != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("email: TLS handshake with %s failed: %w", host, errHandshake)
	}
	client := imapclient.New(tlsConn, nil)
	if errGreeting := client.WaitGreeting(); errGreeting != nil {
		_ = client.Close()
		return nil, fmt.Errorf("email: no IMAP greeting from %s: %w", host, errGreeting)
	}
	// Some providers answer LOGIN with "Unsafe Login" unless the client
	// identifies itself first. ID is best effort: a server that does not offer
	// it simply skips this step.
	if _, errCaps := client.Capability().Wait(); errCaps == nil && client.Caps().Has(imap.CapID) {
		_, _ = client.ID(&imap.IDData{Name: "CLIProxyAPI", Vendor: "hlyrouter"}).Wait()
	}
	if errLogin := authenticate(ctx, client, target); errLogin != nil {
		_ = client.Close()
		return nil, errLogin
	}
	return &imapSession{client: client}, nil
}

// authenticate proves the session's identity by the method the target names.
func authenticate(ctx context.Context, client *imapclient.Client, target Target) error {
	switch target.Auth {
	case AuthGraph:
		// dialSession never gets here for a Graph target; refusing loudly keeps a
		// future caller from sending a Graph token to an IMAP LOGIN.
		return errors.New("email: a Graph mailbox is not opened over IMAP")
	case AuthOAuth2:
		// The token exchange is an outbound HTTP call of its own, so it has to
		// take the mailbox's exit too; minting it from the host's default route
		// would leak the address the rest of the session avoids.
		httpClient, errClient := clientForEgress(target.Egress)
		if errClient != nil {
			return fmt.Errorf("%w: %v", ErrProbeUnready, errClient)
		}
		token, errToken := oauth2Bearer(ctx, target.ClientID, target.Password, httpClient)
		if errToken != nil {
			return fmt.Errorf("%w: %v", ErrLoginRejected, errToken)
		}
		if errAuth := client.Authenticate(xoauth2Client{account: target.Account, token: token}); errAuth != nil {
			return fmt.Errorf("%w: %v", ErrLoginRejected, errAuth)
		}
		return nil
	}
	if errLogin := client.Login(target.Account, target.Password).Wait(); errLogin != nil {
		return fmt.Errorf("%w: %v", ErrLoginRejected, errLogin)
	}
	return nil
}

// Mailboxes lists the account's folders.
func (s *imapSession) Mailboxes(ctx context.Context) ([]string, error) {
	if errCtx := ctx.Err(); errCtx != nil {
		return nil, errCtx
	}
	listed, errList := s.client.List("", "*", nil).Collect()
	if errList != nil {
		return nil, errList
	}
	names := make([]string, 0, len(listed))
	for _, item := range listed {
		if item == nil || item.Mailbox == "" {
			continue
		}
		names = append(names, item.Mailbox)
	}
	return names, nil
}

// Recent reads the messages of one folder that arrived after a point.
//
// The whole message is fetched in one round trip per folder rather than
// fetching headers and then bodies: a verification mail is small, and two round
// trips per candidate would make a poll slow enough to miss short-lived codes.
//
// When the caller hands back a position in this same folder, the search becomes
// "newer than that UID" instead of "since that date", so a poll costs one SEARCH
// and one FETCH of what actually arrived rather than re-reading the window. A
// changed UIDVALIDITY invalidates every stored UID, so the position is dropped
// and the window is searched again; the validity is returned either way, which
// is how the caller learns that it happened.
func (s *imapSession) Recent(ctx context.Context, mailbox string, since time.Time, after FolderPosition, limit int) ([]Mail, uint32, error) {
	if errCtx := ctx.Err(); errCtx != nil {
		return nil, 0, errCtx
	}
	selected, errSelect := s.client.Select(mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if errSelect != nil {
		return nil, 0, errSelect
	}
	validity := selected.UIDValidity
	if selected.NumMessages == 0 {
		return nil, validity, nil
	}
	criteria := &imap.SearchCriteria{Since: since}
	if after.UID > 0 && after.UIDValidity == validity {
		var newer imap.UIDSet
		// A zero stop is "*", so this is "the UID after the one already read,
		// through the newest message".
		newer.AddRange(imap.UID(after.UID+1), 0)
		criteria.UID = []imap.UIDSet{newer}
	}
	// A plain SEARCH is deliberate. Asking for RETURN (ALL) would require
	// ESEARCH, which many providers (QQ among them) do not advertise, and a
	// rejected SEARCH reads as "no mail" instead of as a failure. The classic
	// "* SEARCH" reply carries every matching UID anyway.
	found, errSearch := s.client.Search(criteria, nil).Wait()
	if errSearch != nil {
		return nil, validity, errSearch
	}
	uids := found.AllUIDs()
	if len(uids) == 0 {
		return nil, validity, nil
	}
	// UIDs ascend with arrival, so the tail is the newest mail.
	if limit > 0 && len(uids) > limit {
		uids = uids[len(uids)-limit:]
	}
	section := &imap.FetchItemBodySection{Peek: true}
	buffers, errFetch := s.client.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{
		UID:         true,
		RFC822Size:  true,
		BodySection: []*imap.FetchItemBodySection{section},
	}).Collect()
	if errFetch != nil {
		return nil, validity, errFetch
	}
	mails := make([]Mail, 0, len(buffers))
	for _, buffer := range buffers {
		if buffer == nil || buffer.RFC822Size > maxMailBytes {
			continue
		}
		raw := buffer.FindBodySection(section)
		if len(raw) == 0 {
			continue
		}
		parsed, errParse := parseMail(raw)
		if errParse != nil {
			// One unreadable message must not hide the rest of the folder.
			continue
		}
		parsed.Mailbox = mailbox
		parsed.UID = uint32(buffer.UID)
		mails = append(mails, parsed)
	}
	return mails, validity, nil
}

// Close ends the session.
func (s *imapSession) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	_ = s.client.Logout().Wait()
	return s.client.Close()
}

// parseMail reduces one raw message to what a verification flow needs.
func parseMail(raw []byte) (Mail, error) {
	reader, errReader := mail.CreateReader(bytes.NewReader(raw))
	if errReader != nil {
		return Mail{}, errReader
	}
	defer func() { _ = reader.Close() }()

	subject, _ := reader.Header.Subject()
	from := ""
	if senders, errSenders := reader.Header.AddressList("From"); errSenders == nil && len(senders) > 0 {
		from = senders[0].Address
	}
	recipients, haystack := collectRecipients(&reader.Header)
	date, _ := reader.Header.Date()

	var plain, html string
	for {
		part, errPart := reader.NextPart()
		if errPart != nil {
			break
		}
		inline, ok := part.Header.(*mail.InlineHeader)
		if !ok {
			continue
		}
		contentType, _, _ := inline.ContentType()
		contentType = strings.ToLower(contentType)
		body, errRead := io.ReadAll(io.LimitReader(part.Body, maxBodyBytes))
		if errRead != nil {
			continue
		}
		switch {
		case strings.HasPrefix(contentType, "text/html"):
			if html == "" {
				html = string(body)
			}
		case strings.HasPrefix(contentType, "text/plain"), contentType == "":
			if plain == "" {
				plain = string(body)
			}
		}
	}
	if plain == "" {
		plain = htmlToText(html)
	}
	return Mail{
		From:     from,
		To:       recipients,
		Subject:  subject,
		Text:     plain,
		Date:     date,
		Code:     ExtractCode(subject, plain),
		haystack: haystack,
	}, nil
}

// recipientHeaders are the headers a forwarded message may carry its original
// recipient in. Forwarding rewrites To and leaves the original behind, so a
// match on To alone would miss exactly the mail this package exists to read.
var recipientHeaders = []string{
	"To",
	"Cc",
	"Delivered-To",
	"X-Original-To",
	"X-Forwarded-To",
	"X-Envelope-To",
	"Return-Path",
	"Received",
}

// collectRecipients gathers every address-bearing header into a display list
// and a lowercased haystack for matching.
func collectRecipients(header *mail.Header) ([]string, string) {
	var displayed []string
	var parts []string
	seen := make(map[string]bool)
	for _, name := range recipientHeaders {
		fields := header.FieldsByKey(name)
		for fields.Next() {
			trimmed := strings.TrimSpace(fields.Value())
			if trimmed == "" {
				continue
			}
			parts = append(parts, trimmed)
			// The display list only carries real addresses; Received and
			// Return-Path lines are for matching, not for showing.
			if name == "To" || name == "Cc" || name == "Delivered-To" || name == "X-Original-To" {
				for _, address := range addressesIn(trimmed) {
					key := strings.ToLower(address)
					if seen[key] {
						continue
					}
					seen[key] = true
					displayed = append(displayed, address)
				}
			}
		}
	}
	return displayed, strings.ToLower(strings.Join(parts, "\n"))
}

// addressesIn extracts the addresses of a header value, keeping the raw value
// when it cannot be parsed (a malformed header still tells us who it names).
func addressesIn(value string) []string {
	if parsed, errParse := mail.ParseAddressList(value); errParse == nil && len(parsed) > 0 {
		addresses := make([]string, 0, len(parsed))
		for _, address := range parsed {
			addresses = append(addresses, address.Address)
		}
		return addresses
	}
	if parsed, errParse := mail.ParseAddress(value); errParse == nil && parsed.Address != "" {
		return []string{parsed.Address}
	}
	return []string{strings.TrimSpace(value)}
}

// junkMailboxes picks the folders a forwarded verification mail may have been
// filed into.
//
// A forwarded message is exactly what a provider likes to sort into junk, so
// reading INBOX alone would silently miss codes while the operator sees the
// mail sitting in their mailbox. Folder names are decoded from modified UTF-7
// first, because a Chinese provider names its junk folder in Chinese and
// hard-coding one provider's encoding of that would break on the next one.
func junkMailboxes(all []string) []string {
	picked := []string{"INBOX"}
	for _, name := range all {
		if strings.EqualFold(name, "INBOX") {
			continue
		}
		lower := strings.ToLower(decodeMailboxName(name))
		switch {
		case strings.Contains(lower, "junk"),
			strings.Contains(lower, "spam"),
			strings.Contains(lower, "bulk"),
			strings.Contains(lower, "trash"),
			strings.Contains(lower, "垃圾"),
			strings.Contains(lower, "廣告"),
			strings.Contains(lower, "广告"):
			picked = append(picked, name)
		}
	}
	return picked
}

// decodeMailboxName turns a modified UTF-7 mailbox name (RFC 3501 §5.1.3) into
// plain UTF-8. Names without an escape are returned unchanged.
func decodeMailboxName(name string) string {
	if !strings.Contains(name, "&") {
		return name
	}
	var out strings.Builder
	for i := 0; i < len(name); {
		if name[i] != '&' {
			out.WriteByte(name[i])
			i++
			continue
		}
		end := strings.IndexByte(name[i:], '-')
		if end < 0 {
			out.WriteString(name[i:])
			break
		}
		chunk := name[i+1 : i+end]
		i += end + 1
		if chunk == "" {
			out.WriteByte('&')
			continue
		}
		// Modified UTF-7 uses "," where standard base64 uses "/", and omits
		// padding.
		raw, errDecode := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(chunk, ",", "/"))
		if errDecode != nil {
			out.WriteString("&" + chunk + "-")
			continue
		}
		for j := 0; j+1 < len(raw); j += 2 {
			out.WriteRune(rune(binary.BigEndian.Uint16(raw[j : j+2])))
		}
	}
	return out.String()
}

// htmlToText reduces an HTML body to text. It is deliberately crude: the only
// consumer is the code extractor, which needs the digits and the words around
// them, not the layout.
func htmlToText(html string) string {
	if html == "" {
		return ""
	}
	var out strings.Builder
	depth := 0
	for i := 0; i < len(html); i++ {
		if html[i] != '<' {
			if depth == 0 {
				out.WriteByte(html[i])
			}
			continue
		}
		end := strings.IndexByte(html[i:], '>')
		if end < 0 {
			break
		}
		tag := strings.ToLower(strings.TrimSpace(html[i+1 : i+end]))
		i += end
		switch {
		case strings.HasPrefix(tag, "script"), strings.HasPrefix(tag, "style"):
			depth++
		case strings.HasPrefix(tag, "/script"), strings.HasPrefix(tag, "/style"):
			if depth > 0 {
				depth--
			}
		case strings.HasPrefix(tag, "br"), strings.HasPrefix(tag, "/p"),
			strings.HasPrefix(tag, "/div"), strings.HasPrefix(tag, "/tr"),
			strings.HasPrefix(tag, "/td"):
			out.WriteByte(' ')
		}
	}
	return collapseSpaces(htmlUnescape(out.String()))
}

// htmlUnescape resolves the entities a code-bearing sentence can carry.
func htmlUnescape(text string) string {
	replacer := strings.NewReplacer(
		"&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">",
		"&quot;", `"`, "&#39;", "'", "&apos;", "'",
	)
	return replacer.Replace(text)
}

// collapseSpaces folds runs of whitespace into single spaces, so a code split
// across HTML nodes still reads as one token.
func collapseSpaces(text string) string {
	fields := strings.Fields(text)
	return strings.Join(fields, " ")
}

// sortNewestFirst orders mail by date, newest first.
func sortNewestFirst(mails []Mail) {
	sort.SliceStable(mails, func(i, j int) bool { return mails[i].Date.After(mails[j].Date) })
}
