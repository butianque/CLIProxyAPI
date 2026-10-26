package management

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
)

// This file is the email supply surface: what mailboxes are configured, what
// arrived in them, and how an operator stores a mailbox credential.
//
// It reports mail as it is. A message that states no code is still listed,
// because "the mail arrived but carried no code" is a different problem from
// "the mail never arrived", and an inbox view that hid the first would send the
// operator looking at their catch-all rules for nothing.

// emailInboxLimit caps how many messages one inbox request returns.
const emailInboxLimit = 50

// emailPreviewBytes bounds the body excerpt a listing carries. The code is what
// matters; the preview exists so a message can be recognised.
const emailPreviewBytes = 240

// emailProvider returns the configured email provider.
func emailProvider() (*email.ProviderImpl, error) {
	provider, errProvider := supply.ProviderFor(supply.KindEmail)
	if errProvider != nil {
		return nil, errProvider
	}
	concrete, ok := provider.(*email.ProviderImpl)
	if !ok {
		return nil, supply.ErrUnavailable
	}
	return concrete, nil
}

// GetSupplyEmailStatus reports the configured mailboxes. It never returns a
// credential value, and it never opens a connection: reachability is the probe's
// question, not this one's.
func (h *Handler) GetSupplyEmailStatus(c *gin.Context) {
	payload := gin.H{"status": "ok", "enabled": false, "locked": false, "channels": []gin.H{}}
	provider, errProvider := emailProvider()
	if errProvider != nil {
		c.JSON(http.StatusOK, payload)
		return
	}
	views, errViews := provider.TargetViews()
	if errViews != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errViews.Error()})
		return
	}
	status, errStatus := provider.Status(c.Request.Context())
	if errStatus != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStatus.Error()})
		return
	}
	channels := make([]gin.H, 0, len(views))
	for _, view := range views {
		channels = append(channels, gin.H{
			"channel_id":     view.ChannelID,
			"label":          view.Label,
			"mailbox":        view.Mailbox,
			"host":           view.Host,
			"transport":      view.Transport,
			"domain":         view.Domain,
			"usage":          view.Usage,
			"secret_name":    view.SecretName,
			"has_credential": view.HasCredential,
		})
	}
	payload["enabled"] = status.Enabled
	payload["locked"] = status.Locked
	payload["channels"] = channels
	c.JSON(http.StatusOK, payload)
}

// GetSupplyEmailInbox returns recent mail from the configured mailboxes.
//
// The address parameter narrows the listing to mail addressed to one address;
// without it the listing is the mailboxes' recent mail, which is what an inbox
// view shows before anything is searched for. The scope parameter names which
// table that listing covers: the channel mailboxes (the default) or the pool
// identities, because the panel shows them as two tables and each one asks for
// its own mail.
func (h *Handler) GetSupplyEmailInbox(c *gin.Context) {
	provider, errProvider := emailProvider()
	if errProvider != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "error",
			"error":   "no email mailbox is configured",
			"code":    "email_unavailable",
			"enabled": false,
		})
		return
	}
	limit := emailInboxLimit
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if parsed, errAtoi := strconv.Atoi(raw); errAtoi == nil && parsed > 0 {
			limit = min(parsed, emailInboxLimit)
		}
	}
	address := strings.TrimSpace(c.Query("address"))
	scope := strings.TrimSpace(c.Query("scope"))
	reading, errInbox := provider.Inbox(c.Request.Context(), address, scope, limit)
	if errInbox != nil {
		// An unknown scope is the caller's mistake, not a mailbox failure: it is
		// refused before any mailbox is opened, and saying so keeps the operator
		// from reading a bad query parameter as a broken mailbox.
		if errors.Is(errInbox, email.ErrInboxScope) {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "unknown inbox scope"})
			return
		}
		// A read that could not run is not an empty inbox: reporting it as one
		// would hide a broken mailbox behind a convincing "no mail".
		payload := gin.H{"status": "error", "error": errInbox.Error(), "enabled": true}
		if errors.Is(errInbox, supply.ErrUnavailable) {
			payload["code"] = "email_unavailable"
			payload["enabled"] = false
		}
		c.JSON(http.StatusBadGateway, payload)
		return
	}
	messages := make([]gin.H, 0, len(reading.Mails))
	for _, mail := range reading.Mails {
		messages = append(messages, mailView(mail))
	}
	// The per-mailbox part answers "what does each channel's mailbox hold",
	// which is what a channel row shows; the message list answers "what arrived
	// lately", which is what a reader shows.
	mailboxes := make([]gin.H, 0, len(reading.Mailboxes))
	for _, box := range reading.Mailboxes {
		entry := gin.H{
			"channel_id": box.ChannelID,
			"label":      box.Label,
			"mailbox":    box.Account,
			"domain":     box.Domain,
			"count":      box.Count,
			"error":      box.Err,
		}
		if box.Latest != nil {
			entry["latest"] = mailView(*box.Latest)
		}
		mailboxes = append(mailboxes, entry)
	}
	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"enabled":      true,
		"address":      address,
		"window_hours": int(reading.Window / time.Hour),
		"messages":     messages,
		"mailboxes":    mailboxes,
	})
}

// emailWaitSeconds caps how long one read may wait for mail. A waiting read
// holds a mailbox connection open, so an unbounded wait would let a few scripts
// tie up every connection the provider allows.
const emailWaitSeconds = 60

// PostSupplyEmailGrab hands out one address from the pool.
//
// This is the machine surface: a script asks for an address, uses it to
// register, and asks this same service what arrived. The answer is the pool's,
// not the caller's — a catch-all domain yields a fresh alias, a bought mailbox
// yields itself — so a script never has to know which kind of mailbox it got.
//
// An explicit address re-occupies the one a previous run used, which is how a
// re-authentication gets back onto the same mailbox. The optional usage narrows
// the choice to "personal" (a bought mailbox) or "self-domain" (a catch-all
// alias) without changing anything else about the answer.
func (h *Handler) PostSupplyEmailGrab(c *gin.Context) {
	provider, errProvider := emailProvider()
	if errProvider != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "error",
			"error":   "no email mailbox is configured",
			"code":    "email_unavailable",
			"enabled": false,
		})
		return
	}
	var body struct {
		Project string `json:"project"`
		Address string `json:"address"`
		Usage   string `json:"usage"`
	}
	// The body is optional: no body at all means "whatever the pool prefers".
	_ = c.ShouldBindJSON(&body)
	identity, errGrab := provider.Grab(c.Request.Context(), supply.GrabOptions{
		Purpose: strings.TrimSpace(body.Project),
		Address: strings.TrimSpace(body.Address),
		Usage:   strings.TrimSpace(body.Usage),
	})
	if errGrab != nil {
		payload := gin.H{"status": "error", "error": errGrab.Error(), "code": "grab_failed"}
		status := http.StatusBadGateway
		if errors.Is(errGrab, supply.ErrUnknownIdentity) {
			// The address exists nowhere in this service: the caller's right
			// answer is its manual path, not a retry.
			status = http.StatusNotFound
			payload["code"] = "unknown_identity"
		}
		if errors.Is(errGrab, supply.ErrUnavailable) {
			status = http.StatusServiceUnavailable
			payload["code"] = "email_unavailable"
		}
		c.JSON(status, payload)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"address":    identity.Address,
		"domain":     supply.AddressDomain(identity.Address),
		"channel_id": identity.Code,
		"project":    strings.TrimSpace(body.Project),
	})
}

// GetSupplyEmailCode reports what arrived for one address after a position.
//
// The position is the caller's: it comes back unchanged when nothing new
// arrived, and advances past the newest message when something did. Keeping it
// on the caller's side means two consumers reading the same mailbox cannot take
// mail away from each other, and a restart loses nothing.
//
// wait keeps the mailbox open and looks again on the same connection, so a
// script asks once instead of rebuilding a session every few seconds. A wait
// that expires with no mail is not an error: it is ready=false.
func (h *Handler) GetSupplyEmailCode(c *gin.Context) {
	provider, errProvider := emailProvider()
	if errProvider != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "error",
			"error":   "no email mailbox is configured",
			"code":    "email_unavailable",
			"enabled": false,
		})
		return
	}
	address := strings.TrimSpace(c.Query("address"))
	if address == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "error",
			"error":  "an address is required",
			"code":   "address_required",
		})
		return
	}
	var wait time.Duration
	if raw := strings.TrimSpace(c.Query("wait")); raw != "" {
		if seconds, errAtoi := strconv.Atoi(raw); errAtoi == nil && seconds > 0 {
			wait = time.Duration(min(seconds, emailWaitSeconds)) * time.Second
		}
	}
	result, errRead := provider.ReadAfter(c.Request.Context(), address, strings.TrimSpace(c.Query("cursor")), wait)
	if errRead != nil {
		payload := gin.H{"status": "error", "error": errRead.Error(), "code": "read_failed"}
		status := http.StatusBadGateway
		switch {
		case errors.Is(errRead, email.ErrCursor):
			// A position this build cannot read is the caller's bug, and
			// starting over is the fix.
			status = http.StatusBadRequest
			payload["code"] = "cursor_invalid"
		case errors.Is(errRead, supply.ErrUnknownIdentity):
			status = http.StatusNotFound
			payload["code"] = "unknown_identity"
		case errors.Is(errRead, supply.ErrUnavailable):
			status = http.StatusServiceUnavailable
			payload["code"] = "email_unavailable"
		case errors.Is(errRead, email.ErrLoginRejected):
			payload["code"] = "login_rejected"
		case errors.Is(errRead, email.ErrCredential):
			payload["code"] = "credential_unavailable"
		}
		c.JSON(status, payload)
		return
	}
	messages := make([]gin.H, 0, len(result.Mails))
	for _, mail := range result.Mails {
		messages = append(messages, mailView(mail))
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"address":  address,
		"domain":   supply.AddressDomain(address),
		"mailbox":  result.Mailbox,
		"ready":    len(result.Mails) > 0,
		"code":     result.Code,
		"cursor":   result.Cursor,
		"reset":    result.Reset,
		"messages": messages,
	})
}

// mailView renders one message without a credential and without a guess.
//
// It carries the links but not the body: the list can hold fifty messages, and
// repeating every body would turn one listing into megabytes. A preview plus the
// extracted code and links is what a reader needs to recognise a message and to
// act on it.
func mailView(mail email.Mail) gin.H {
	received := ""
	if !mail.Date.IsZero() {
		received = mail.Date.Format(time.RFC3339)
	}
	return gin.H{
		"channel_id":  mail.ChannelID,
		"mailbox":     mail.Mailbox,
		"from":        mail.From,
		"to":          mail.To,
		"subject":     mail.Subject,
		"received_at": received,
		"code":        mail.Code,
		"preview":     previewText(mail.Text),
		"links":       mail.Links,
	}
}

// PostSupplyEmailCredential stores one mailbox's credential: the authorization
// code for a password login, or the OAuth2 refresh token for a Microsoft
// mailbox.
//
// The value goes straight into the secret store; it is never echoed, logged, or
// written into the channel document. The mailbox names the entry (see
// email.CredentialName), so the operator never has to invent a name — and the
// panel cannot get the name wrong, because it never sends one. The method is
// named because the two kinds of value live in different entries: a refresh
// token stored under the password entry would be handed to an IMAP LOGIN.
func (h *Handler) PostSupplyEmailCredential(c *gin.Context) {
	var body struct {
		Name       string `json:"name"`
		Account    string `json:"account"`
		Nature     string `json:"nature"`
		Secret     string `json:"secret"`
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		// The mailbox names the entry: the operator only supplies the login, and
		// the panel does not have to invent a name for the credential.
		if supply.Nature(strings.ToLower(strings.TrimSpace(body.Nature))).UsesRefreshToken() {
			name = supply.EmailOAuth2CredentialName(body.Account)
		} else {
			name = supply.EmailCredentialName(body.Account)
		}
	}
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "the mailbox account is required"})
		return
	}
	if strings.TrimSpace(body.Secret) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "a credential value is required"})
		return
	}
	vault, errGate := gateSupplyWrite(c, body.Passphrase)
	if errGate {
		return
	}
	if errSet := vault.Set(name, body.Secret); errSet != nil {
		c.JSON(errStatus(errSet), gin.H{"status": "error", "error": errSet.Error()})
		return
	}
	// The mailbox provider reads its secrets per call, but the registry caches
	// the provider, so a rebuild is what makes the new value visible at once.
	reloadSupply()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "name": name, "stored": true})
}

// previewText reduces a body to one line for a listing.
//
// The cut is by rune, not by byte: a body is usually Chinese, and slicing a
// multi-byte rune in half would leave a replacement character at the end of
// every truncated preview.
func previewText(text string) string {
	trimmed := strings.Join(strings.Fields(text), " ")
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= emailPreviewBytes {
		return trimmed
	}
	cut := 0
	for index := range trimmed {
		if index > emailPreviewBytes {
			break
		}
		cut = index
	}
	return trimmed[:cut] + "…"
}
