package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
)

// This file imports mailboxes that arrived as nothing but addresses.
//
// A bought batch is often sold as accounts alone: the seller hands over an
// address and a password, and neither is a credential any Microsoft transport
// accepts. The read path needs a refresh token, and the only way to get one
// without already having one is the OAuth2 device authorization grant — the
// operator reads a short code, types it on Microsoft's page, and signs in once.
//
// That single sign-in per mailbox is the whole manual cost, and it cannot be
// removed: the code exists so that a person proves on Microsoft's own page that
// they hold the account. Everything around it is automatic — asking for the
// code, showing it, polling, exchanging it, checking which account actually
// signed in, and writing the token and the pool identity.
//
// Why the write is system-level rather than session-level: a sign-in can take up
// to fifteen minutes, while a session's secret-store grant lives ten. The gate
// still runs when the batch is started, so an operator's passphrase is what
// authorises the batch; the write that finishes later uses the same store access
// the mailbox read path already uses. A store that is locked when the sign-in
// lands does not lose the token: the flow parks it and the batch stops, so one
// unlock and one save finish that account instead of another trip through
// Microsoft's sign-in page.

const (
	// authorizeClientID is the public client every sign-in uses.
	//
	// It is a well-known first-party application, not one of ours: a public
	// client has no secret to leak, and registering an application for this would
	// mean maintaining a consent record for no benefit. The scope asked for is
	// narrow (read one mailbox, read one identity, stay offline), so a token
	// minted through it can do exactly what this feature needs and nothing else.
	authorizeClientID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
	// authorizeFlowTTL is how long a finished flow stays readable. The panel
	// reads the result right after it lands; keeping it longer only accumulates
	// memory and account names.
	authorizeFlowTTL = 30 * time.Minute
	// authorizeMaxFlows bounds the registry, oldest finished first.
	authorizeMaxFlows = 50
	// authorizeMaxAccounts bounds one batch. A sign-in is a human action, so a
	// longer list would be a list nobody finishes in one sitting.
	authorizeMaxAccounts = 50
	// authorizeDefaultInterval is the first poll interval, used before the
	// endpoint has named one.
	authorizeDefaultInterval = 5 * time.Second
	// authorizeStartTimeout bounds the one network call that happens before the
	// answer is written: asking for the first code.
	authorizeStartTimeout = 30 * time.Second
)

// The states one flow moves through. The panel renders these directly, so they
// are wire values, not internal ones.
const (
	authorizeWaiting        = "waiting"
	authorizeVerifying      = "verifying"
	authorizeSaving         = "saving"
	authorizeDone           = "done"
	authorizeMismatch       = "mismatch"
	authorizeDenied         = "denied"
	authorizeExpired        = "expired"
	authorizeFailed         = "failed"
	authorizeCancelled      = "cancelled"
	authorizeAwaitingUnlock = "awaiting_unlock"
)

// emailAuthorizeFlow is one account's sign-in.
type emailAuthorizeFlow struct {
	ID         string
	Account    string
	Status     string
	Detail     string
	UserCode   string
	VerifyURL  string
	ExpiresAt  time.Time
	Interval   time.Duration
	FinishedAt time.Time

	// held is a refresh token whose sign-in succeeded but which could not be
	// written because the store was locked. It lives in memory only, and is
	// dropped as soon as the write happens.
	held         string
	heldClientID string
}

// terminal reports whether a flow will not change again.
func (f emailAuthorizeFlow) terminal() bool {
	switch f.Status {
	case authorizeDone, authorizeMismatch, authorizeDenied, authorizeExpired, authorizeFailed, authorizeCancelled:
		return true
	}
	return false
}

// settled reports whether a flow will not move on its own: it either finished or
// it is waiting for an operator to unlock the store. Both stop the batch and both
// are safe to forget after the TTL, which is what keeps a parked token from living
// in memory forever.
func (f emailAuthorizeFlow) settled() bool {
	return f.terminal() || f.Status == authorizeAwaitingUnlock
}

// emailAuthorizeView is one flow as the panel reads it. It carries no credential:
// the short code is meant to be read out, and everything else is a state.
type emailAuthorizeView struct {
	ID        string `json:"id"`
	Account   string `json:"account"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	UserCode  string `json:"user_code,omitempty"`
	VerifyURL string `json:"verify_url,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
	Interval  int    `json:"interval,omitempty"`
}

// emailAuthorizeRegistry holds the flows in flight.
//
// One batch runs at a time. Two concurrent batches would mean two codes and two
// sign-ins against the same exit address in the same minute, which is the pattern
// Microsoft's abuse scoring watches for — and a person cannot usefully read two
// codes at once either.
type emailAuthorizeRegistry struct {
	mu      sync.Mutex
	order   []string
	flows   map[string]*emailAuthorizeFlow
	running bool
	stop    context.CancelFunc
	// done closes when the running batch has returned. Tests wait on it so a
	// finished test cannot leave a goroutine behind that touches the registry.
	done chan struct{}

	// The three network steps are fields so a test can drive the state machine
	// without Microsoft in the loop. Nil means the real endpoints; a test sets
	// them before it starts a batch, which is what makes the assignment safe
	// against the goroutine that reads them.
	startSignIn func(ctx context.Context, egress, clientID string) (email.DeviceAuthorization, error)
	pollSignIn  func(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error)
	identify    func(ctx context.Context, egress, accessToken string) (email.GraphIdentity, error)
}

// begin asks for one code.
func (r *emailAuthorizeRegistry) begin(ctx context.Context, egress, clientID string) (email.DeviceAuthorization, error) {
	if r.startSignIn != nil {
		return r.startSignIn(ctx, egress, clientID)
	}
	return email.RequestMailboxAuthorization(ctx, egress, clientID)
}

// poll redeems the code once.
func (r *emailAuthorizeRegistry) poll(ctx context.Context, egress, clientID, deviceCode string) (email.DeviceToken, error) {
	if r.pollSignIn != nil {
		return r.pollSignIn(ctx, egress, clientID, deviceCode)
	}
	return email.PollMailboxAuthorization(ctx, egress, clientID, deviceCode)
}

// whoAmI asks which account signed in.
func (r *emailAuthorizeRegistry) whoAmI(ctx context.Context, egress, accessToken string) (email.GraphIdentity, error) {
	if r.identify != nil {
		return r.identify(ctx, egress, accessToken)
	}
	return email.VerifyMailboxAccount(ctx, egress, accessToken)
}

// emailAuthorizes is the process-wide registry. It is deliberately not a Handler
// field: the flows outlive one request, and the Handler is constructed in tests
// with a struct literal that has no room for lazily built state.
var emailAuthorizes = &emailAuthorizeRegistry{flows: map[string]*emailAuthorizeFlow{}}

// errAuthorizeBusy is what a second batch gets while one is still waiting.
var errAuthorizeBusy = errors.New("a sign-in batch is already waiting; cancel it first")

// PostSupplyEmailAuthorize starts one batch of sign-ins.
//
// It answers as soon as the first code exists; the waiting happens in the
// background, so nothing here holds a request open for fifteen minutes.
func (h *Handler) PostSupplyEmailAuthorize(c *gin.Context) {
	var body struct {
		Accounts   string `json:"accounts"`
		ClientID   string `json:"client_id"`
		Passphrase string `json:"passphrase"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	accounts, errAccounts := parseAuthorizeAccounts(body.Accounts)
	if errAccounts != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errAccounts.Error()})
		return
	}
	clientID := strings.TrimSpace(body.ClientID)
	if clientID == "" {
		clientID = authorizeClientID
	}
	if !looksLikeClientID(clientID) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "the application id is not an application id"})
		return
	}
	if supply.DefaultPool() == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "error", "error": "the supply pool is not configured"})
		return
	}
	// The gate runs once for the whole batch. It is what turns "this session may
	// write credentials" into "this operator asked for these mailboxes now".
	if _, alreadyAnswered := gateSupplyWrite(c, body.Passphrase); alreadyAnswered {
		return
	}
	// The batch outlives this request: it waits on a person, not on a connection.
	// A detached context with its own deadline keeps a dropped connection from
	// turning the click into a no-op after Microsoft has already been asked.
	startCtx, cancelStart := context.WithTimeout(
		context.WithoutCancel(c.Request.Context()), authorizeStartTimeout)
	defer cancelStart()
	ids, errStart := emailAuthorizes.start(startCtx, accounts, clientID, h.supplyExit(), h.attachAuthorizedMailbox)
	if errStart != nil {
		// A second batch is a conflict like a locked store, so the flag is what
		// tells them apart: the panel attaches to the batch already waiting
		// instead of asking for a passphrase.
		if errors.Is(errStart, errAuthorizeBusy) {
			c.JSON(http.StatusConflict, gin.H{
				"status": "error",
				"error":  errStart.Error(),
				"busy":   true,
			})
			return
		}
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": errStart.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "flows": emailAuthorizes.views(ids)})
}

// GetSupplyEmailAuthorize reports every flow the panel may still show.
func (h *Handler) GetSupplyEmailAuthorize(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "flows": emailAuthorizes.views(nil)})
}

// PostSupplyEmailAuthorizeCancel stops the running batch.
//
// Cancelling one flow cancels the batch it belongs to: the codes were requested
// one after another, so leaving the rest of the batch running would start the
// next sign-in moments after the operator asked for it to stop.
func (h *Handler) PostSupplyEmailAuthorizeCancel(c *gin.Context) {
	if errCancel := emailAuthorizes.cancel(strings.TrimSpace(c.Param("id"))); errCancel != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": errCancel.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "flows": emailAuthorizes.views(nil)})
}

// PostSupplyEmailAuthorizeCommit finishes a sign-in whose token could not be
// written because the store was locked.
//
// The point of it is that the operator does not have to sign in again: the token
// is already in memory, and all that was missing was the passphrase.
func (h *Handler) PostSupplyEmailAuthorizeCommit(c *gin.Context) {
	var body struct {
		Passphrase string `json:"passphrase"`
	}
	_ = c.ShouldBindJSON(&body)
	flow, ok := emailAuthorizes.get(strings.TrimSpace(c.Param("id")))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "no such sign-in"})
		return
	}
	if flow.Status != authorizeAwaitingUnlock {
		c.JSON(http.StatusConflict, gin.H{"status": "error", "error": "this sign-in is not waiting to be stored"})
		return
	}
	if _, alreadyAnswered := gateSupplyWrite(c, body.Passphrase); alreadyAnswered {
		return
	}
	if errCommit := h.attachAuthorizedMailbox(flow.Account, flow.heldClientID, flow.held); errCommit != nil {
		c.JSON(errStatus(errCommit), gin.H{"status": "error", "error": errCommit.Error()})
		return
	}
	emailAuthorizes.finish(flow.ID, authorizeDone, "")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "flows": emailAuthorizes.views(nil)})
}

// attachAuthorizedMailbox stores one signed-in mailbox: the refresh token under
// its own entry, then the pool identity that points at it.
//
// Credential first, identity second, the same order the paste import uses: an
// identity that exists without a credential is a row that looks configured and
// can never authenticate.
func (h *Handler) attachAuthorizedMailbox(account, clientID, refreshToken string) error {
	account = strings.TrimSpace(account)
	refreshToken = strings.TrimSpace(refreshToken)
	if account == "" || refreshToken == "" {
		return errors.New("the sign-in produced no credential to store")
	}
	store := secretstore.Default()
	if store == nil {
		return errors.New("the secret store is disabled")
	}
	if !store.Unlocked() {
		return secretstore.ErrLocked
	}
	pool := supply.DefaultPool()
	if pool == nil {
		return errors.New("the supply pool is not configured")
	}
	entry := supply.EmailOAuth2CredentialName(account)
	// A system-level write, which is the same access the read path uses
	// (readCredential in the email package). The session gate already ran when the
	// batch started; repeating it here would be asking a request that no longer
	// exists.
	if errSet := store.Set(entry, refreshToken); errSet != nil {
		return errSet
	}
	box := supply.Mailbox{
		// The authorization asks for Graph scopes, so the mailbox is read through
		// Graph. There is no endpoint to store: Graph answers at one.
		Nature:   supply.NatureGraph,
		ClientID: clientID,
		Secret:   entry,
	}
	// Attaching replaces the whole mailbox block, so a password entry an earlier
	// paste import recorded has to be carried over or it would be silently lost.
	// It is what a person signing in to the mailbox's own web page needs.
	if existing, found := pool.Get(supply.KindEmail, account); found && existing.Mailbox != nil {
		box.Password = existing.Mailbox.Password
	}
	pool.AttachMailbox(supply.KindEmail, account, box, time.Now().Unix())
	if errSave := pool.Save(supply.PoolPath(supplyStateDir(h))); errSave != nil {
		return errSave
	}
	reloadSupply()
	return nil
}

// start registers one flow per account and walks them in order.
//
// The first code is requested before the answer is written. The panel has nothing
// to show until it exists, and a poll every few seconds would make the operator
// wait for it; one round trip to Microsoft before replying is the cheaper trade.
func (r *emailAuthorizeRegistry) start(ctx context.Context, accounts []string, clientID, egress string, commit func(account, clientID, refresh string) error) ([]string, error) {
	// The slot is reserved before the network call, so two panels starting at once
	// cannot both reach Microsoft.
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil, errAuthorizeBusy
	}
	// A parked sign-in still holds a token that only a save can finish. Starting
	// another batch would drop it, so it blocks the slot exactly like a running
	// one — and the panel answers that the same way, by showing the parked one.
	for _, id := range r.order {
		if flow, ok := r.flows[id]; ok && flow.Status == authorizeAwaitingUnlock {
			r.mu.Unlock()
			return nil, errAuthorizeBusy
		}
	}
	r.running = true
	r.mu.Unlock()

	first, errFirst := r.begin(ctx, egress, clientID)
	if errFirst != nil {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
		return nil, errFirst
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(time.Now())
	// The rows of earlier batches have already been read by the panel, and
	// keeping them would make this batch read "3 of 5" while showing five rows
	// from the last one.
	r.dropSettledLocked()
	now := time.Now()
	ids := make([]string, 0, len(accounts))
	for index, account := range accounts {
		id := newAuthorizeID()
		flow := &emailAuthorizeFlow{
			ID:       id,
			Account:  account,
			Status:   authorizeWaiting,
			Interval: authorizeDefaultInterval,
		}
		if index == 0 {
			flow.UserCode = first.UserCode
			flow.VerifyURL = first.VerifyURL
			flow.ExpiresAt = now.Add(first.ExpiresIn)
			if first.Interval > 0 {
				flow.Interval = first.Interval
			}
		}
		r.flows[id] = flow
		r.order = append(r.order, id)
		ids = append(ids, id)
	}
	batchCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.stop = cancel
	r.done = done
	go r.run(batchCtx, done, ids, accounts, clientID, egress, first, commit)
	return ids, nil
}

// run walks a batch. It stops as soon as one flow is cancelled, because the codes
// are requested one after another and the operator asked for the batch to stop.
func (r *emailAuthorizeRegistry) run(ctx context.Context, done chan struct{}, ids, accounts []string, clientID, egress string, first email.DeviceAuthorization, commit func(account, clientID, refresh string) error) {
	defer func() {
		r.mu.Lock()
		r.running = false
		r.stop = nil
		r.done = nil
		r.mu.Unlock()
		close(done)
	}()
	for index, account := range accounts {
		var prepared *email.DeviceAuthorization
		if index == 0 {
			// The first code was requested before the batch was answered.
			prepared = &first
		}
		if !r.runOne(ctx, ids[index], account, clientID, egress, prepared, commit) {
			r.markRest(ids[index+1:], authorizeCancelled, "the batch stopped")
			return
		}
	}
}

// runOne drives one account from "ask for a code" to "stored", and reports
// whether the batch may continue. A prepared authorization is one that was
// already requested by the caller.
func (r *emailAuthorizeRegistry) runOne(ctx context.Context, id, account, clientID, egress string, prepared *email.DeviceAuthorization, commit func(account, clientID, refresh string) error) bool {
	authorization := email.DeviceAuthorization{}
	if prepared != nil {
		authorization = *prepared
	} else {
		var errStart error
		authorization, errStart = r.begin(ctx, egress, clientID)
		if errStart != nil {
			// One account failing to start is not a reason to drop the rest of
			// the batch: the operator can retry just that one afterwards.
			r.finish(id, authorizeFailed, errStart.Error())
			return true
		}
		r.update(id, func(flow *emailAuthorizeFlow) {
			flow.UserCode = authorization.UserCode
			flow.VerifyURL = authorization.VerifyURL
			flow.ExpiresAt = time.Now().Add(authorization.ExpiresIn)
			flow.Interval = authorization.Interval
		})
	}

	token, status, detail := r.awaitSignIn(ctx, id, clientID, egress, authorization)
	if token.RefreshToken == "" {
		r.finish(id, status, detail)
		return status != authorizeCancelled
	}

	// Which account signed in is not something the token says. Asking is the only
	// thing that keeps a request naming one address from storing another
	// account's credential under it.
	r.update(id, func(flow *emailAuthorizeFlow) { flow.Status = authorizeVerifying })
	identity, errIdentify := r.whoAmI(ctx, egress, token.AccessToken)
	if errIdentify != nil {
		r.finish(id, authorizeFailed, errIdentify.Error())
		return true
	}
	if !identityMatches(identity, account) {
		r.finish(id, authorizeMismatch, "the sign-in was for "+strings.Join(identity.Addresses(), " / ")+", not "+account)
		return true
	}

	r.update(id, func(flow *emailAuthorizeFlow) { flow.Status = authorizeSaving })
	if errCommit := commit(account, clientID, token.RefreshToken); errCommit != nil {
		if errors.Is(errCommit, secretstore.ErrLocked) || errors.Is(errCommit, secretstore.ErrUnauthorized) {
			// The sign-in was real and the token is good; only the write is
			// missing. Parking it means one unlock finishes the batch instead of
			// one more trip through Microsoft's sign-in page.
			r.update(id, func(flow *emailAuthorizeFlow) {
				flow.Status = authorizeAwaitingUnlock
				flow.Detail = "the sign-in succeeded; unlock the secret store to store it"
				flow.FinishedAt = time.Now()
				flow.held = token.RefreshToken
				flow.heldClientID = clientID
			})
			// Stop here rather than walk on. Every later account would need the
			// same sign-in and would then park the same way, and the panel can
			// only show one code at a time — the rest would be codes nobody ever
			// reads, followed by credentials nobody can write. One unlock, one
			// commit, and the remaining accounts are started again.
			return false
		}
		r.finish(id, authorizeFailed, errCommit.Error())
		return true
	}
	r.finish(id, authorizeDone, "")
	return true
}

// awaitSignIn polls the endpoint until the person finishes, declines, or the code
// expires. It reports the token on success, and a status plus a detail otherwise.
func (r *emailAuthorizeRegistry) awaitSignIn(ctx context.Context, id, clientID, egress string, authorization email.DeviceAuthorization) (email.DeviceToken, string, string) {
	interval := authorization.Interval
	if interval <= 0 {
		interval = authorizeDefaultInterval
	}
	deadline := time.Now().Add(authorization.ExpiresIn)
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return email.DeviceToken{}, authorizeCancelled, "the batch was cancelled"
		case <-timer.C:
		}
		if time.Now().After(deadline) {
			return email.DeviceToken{}, authorizeExpired, "the sign-in code expired before it was used"
		}
		token, errPoll := r.poll(ctx, egress, clientID, authorization.DeviceCode)
		switch {
		case errPoll == nil:
			return token, "", ""
		case errors.Is(errPoll, email.ErrDevicePending):
			// Nobody has finished yet: keep the same rhythm.
		case errors.Is(errPoll, email.ErrDeviceSlowDown):
			// The endpoint asked for a slower rhythm (RFC 8628 §3.5), and it
			// means it: ignoring this is how a client gets its code revoked.
			interval += 5 * time.Second
			if interval > time.Minute {
				interval = time.Minute
			}
		case errors.Is(errPoll, context.Canceled), errors.Is(errPoll, context.DeadlineExceeded):
			return email.DeviceToken{}, authorizeCancelled, "the batch was cancelled"
		default:
			return email.DeviceToken{}, authorizeDenied, errPoll.Error()
		}
		timer.Reset(interval)
	}
}

// update changes one flow under the lock.
func (r *emailAuthorizeRegistry) update(id string, change func(flow *emailAuthorizeFlow)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if flow, ok := r.flows[id]; ok {
		change(flow)
	}
}

// finish marks one flow terminal.
func (r *emailAuthorizeRegistry) finish(id, status, detail string) {
	r.update(id, func(flow *emailAuthorizeFlow) {
		flow.Status = status
		flow.Detail = detail
		flow.FinishedAt = time.Now()
		// A finished flow keeps no credential, whatever it was.
		flow.held = ""
		flow.heldClientID = ""
	})
}

// markRest marks the flows a stopped batch will never reach.
func (r *emailAuthorizeRegistry) markRest(ids []string, status, detail string) {
	for _, id := range ids {
		r.update(id, func(flow *emailAuthorizeFlow) {
			if flow.terminal() {
				return
			}
			flow.Status = status
			flow.Detail = detail
			flow.FinishedAt = time.Now()
			flow.held = ""
			flow.heldClientID = ""
		})
	}
}

// cancel stops the running batch.
func (r *emailAuthorizeRegistry) cancel(id string) error {
	r.mu.Lock()
	flow, ok := r.flows[id]
	if !ok {
		r.mu.Unlock()
		return errors.New("no such sign-in")
	}
	cancel := r.stop
	parked := flow.Status == authorizeAwaitingUnlock
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		return nil
	}
	if parked {
		// Nothing is running, but this one still holds a token waiting for a
		// save. Stopping it means dropping that token, which is what was asked.
		r.finish(id, authorizeCancelled, "the sign-in was stopped before it was saved")
		return nil
	}
	// Nothing is running: the flow has already finished, and there is nothing to
	// stop. Reporting success is honest here — the caller wanted it to stop.
	return nil
}

// get returns a copy of one flow, so a caller never reads a field the background
// goroutine is writing.
func (r *emailAuthorizeRegistry) get(id string) (emailAuthorizeFlow, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	flow, ok := r.flows[id]
	if !ok {
		return emailAuthorizeFlow{}, false
	}
	return *flow, true
}

// views renders the flows, newest batch last. A nil selection means every flow
// still worth showing.
func (r *emailAuthorizeRegistry) views(only []string) []emailAuthorizeView {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(time.Now())
	selected := only
	if selected == nil {
		selected = r.order
	}
	now := time.Now()
	out := make([]emailAuthorizeView, 0, len(selected))
	for _, id := range selected {
		flow, ok := r.flows[id]
		if !ok {
			continue
		}
		view := emailAuthorizeView{
			ID:        flow.ID,
			Account:   flow.Account,
			Status:    flow.Status,
			Detail:    flow.Detail,
			UserCode:  flow.UserCode,
			VerifyURL: flow.VerifyURL,
			Interval:  int(flow.Interval / time.Second),
		}
		if !flow.ExpiresAt.IsZero() {
			if remaining := int(flow.ExpiresAt.Sub(now) / time.Second); remaining > 0 {
				view.ExpiresIn = remaining
			}
		}
		out = append(out, view)
	}
	return out
}

// dropSettledLocked forgets the rows of earlier batches. A batch's result is read
// right after it lands, so by the time another batch starts those rows have served
// their purpose — and keeping them would make the new batch's progress count wrong.
// It must be called with the lock held.
func (r *emailAuthorizeRegistry) dropSettledLocked() {
	kept := r.order[:0]
	for _, id := range r.order {
		if flow, ok := r.flows[id]; ok && !flow.settled() {
			kept = append(kept, id)
			continue
		}
		delete(r.flows, id)
	}
	r.order = kept
}

// pruneLocked drops finished flows nobody will read again. It must be called with
// the lock held.
func (r *emailAuthorizeRegistry) pruneLocked(now time.Time) {
	kept := r.order[:0]
	for _, id := range r.order {
		flow, ok := r.flows[id]
		if !ok {
			continue
		}
		if flow.settled() && !flow.FinishedAt.IsZero() && now.Sub(flow.FinishedAt) > authorizeFlowTTL {
			delete(r.flows, id)
			continue
		}
		kept = append(kept, id)
	}
	r.order = kept
	// A cap on top of the time limit: a long-running process whose operator keeps
	// importing would otherwise grow this map forever.
	for len(r.order) > authorizeMaxFlows {
		oldest := r.order[0]
		if flow, ok := r.flows[oldest]; ok && !flow.settled() {
			// Never drop a flow that has not settled: one still has its code on
			// screen, and one parked holds a token an operator can still save.
			break
		}
		delete(r.flows, oldest)
		r.order = r.order[1:]
	}
}

// reset clears the registry and waits for a running batch to return. Tests use
// it; nothing in production calls it.
func (r *emailAuthorizeRegistry) reset() {
	r.mu.Lock()
	stop := r.stop
	done := r.done
	r.order = nil
	r.flows = map[string]*emailAuthorizeFlow{}
	r.running = false
	r.stop = nil
	r.done = nil
	r.mu.Unlock()
	if stop != nil {
		stop()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

// parseAuthorizeAccounts reads the pasted addresses, one per line.
func parseAuthorizeAccounts(text string) ([]string, error) {
	seen := make(map[string]bool, 8)
	out := make([]string, 0, 8)
	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, "\r")))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A line that still carries the paste format's separators is the other
		// mode's input. Accepting it here would silently import nothing while
		// looking like it worked.
		if strings.Contains(trimmed, "----") {
			return nil, errors.New("one address per line: this mode takes accounts only, not credentials")
		}
		if !strings.Contains(trimmed, "@") {
			return nil, fmt.Errorf("%q is not a mailbox address", trimmed)
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil, errors.New("no accounts to sign in")
	}
	if len(out) > authorizeMaxAccounts {
		return nil, fmt.Errorf("at most %d accounts at a time", authorizeMaxAccounts)
	}
	return out, nil
}

// identityMatches reports whether the account that signed in is the one that was
// asked for.
//
// An exact match is not the only correct answer. A personal Microsoft account
// owns one namespace across several domains, so the same person is
// "name@hotmail.com" and "name@outlook.com"; a batch sold under one spelling is
// routinely signed in under another, and refusing that would reject a correct
// sign-in. Two different people can never share a local part across those
// domains, which is what makes the looser comparison safe.
func identityMatches(identity email.GraphIdentity, account string) bool {
	account = strings.ToLower(strings.TrimSpace(account))
	if account == "" {
		return false
	}
	for _, address := range identity.Addresses() {
		if address == account {
			return true
		}
		if local, domain, found := strings.Cut(address, "@"); found &&
			isMicrosoftConsumerDomain(domain) && strings.HasPrefix(account, local+"@") &&
			isMicrosoftConsumerDomain(strings.TrimPrefix(account, local+"@")) {
			return true
		}
	}
	return false
}

// isMicrosoftConsumerDomain reports whether a domain belongs to the shared
// personal-account namespace.
func isMicrosoftConsumerDomain(domain string) bool {
	switch domain {
	case "msn.com", "passport.com":
		return true
	}
	return strings.HasPrefix(domain, "hotmail.") || strings.HasPrefix(domain, "outlook.") ||
		strings.HasPrefix(domain, "live.")
}

// newAuthorizeID makes an identifier for one flow. It is random rather than
// sequential so a panel that reconnects cannot address a flow by guessing.
func newAuthorizeID() string {
	buffer := make([]byte, 8)
	if _, errRead := rand.Read(buffer); errRead != nil {
		// A failure here means the process cannot get randomness at all, which is
		// not a state worth continuing in; the time is enough to be unique.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
