package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// This file is the egress pool surface: the exits this installation owns, and
// who is bound to each one.
//
// It answers two questions and nothing else:
//
//   - which exit is #n, and does it work (last probe)
//   - what is bound to #n (accounts, channels, the supply-wide exit)
//
// Bindings are counted from where they actually live rather than stored here.
// A copy in the pool would be a second source of truth that goes stale as soon
// as an account is deleted by any other path, and a stale count is worse than no
// count: it would make an operator think an exit is in use when it is not.

// errNoEgressID reports a path parameter that is not a pool id.
var errNoEgressID = errors.New("the exit id must be a positive number")

// resolveEgress turns a pool id into the address it names.
func (h *Handler) resolveEgress(id int) (string, error) {
	pool, errPool := h.egressPool()
	if errPool != nil {
		return "", errPool
	}
	return pool.ResolveRef(supply.EgressRef{ID: id})
}

// applyEgressIDs fills each connection's address from the pool id it names.
//
// This runs on the read path rather than being stored, because the pool is the
// authority for an address: resolving once at write time would freeze the
// address and defeat the point of naming an exit by id.
//
// An id that cannot be resolved yields supply.UnresolvedEgress, which the
// transport builder rejects. That is deliberate: failing loudly beats quietly
// probing, or sending, from the host's own address.
//
// The channel is copied before it is filled in. A channel from the store shares
// its connection maps with the store's own state, and writing the resolved
// address back into it would replace the id on disk with an address the next
// time the store was saved.
func (h *Handler) applyEgressIDs(channel supply.Channel) supply.Channel {
	copyBlock := func(block *supply.KindConfig) *supply.KindConfig {
		if block == nil {
			return nil
		}
		copied := *block
		copied.Connections = make(map[supply.Nature]supply.Connection, len(block.Connections))
		for nature, connection := range block.Connections {
			if connection.EgressID > 0 {
				url, errResolve := h.resolveEgress(connection.EgressID)
				if errResolve != nil || strings.TrimSpace(url) == "" {
					url = supply.UnresolvedEgress
				}
				connection.Egress = url
			}
			copied.Connections[nature] = connection
		}
		return &copied
	}
	channel.Phone = copyBlock(channel.Phone)
	channel.Email = copyBlock(channel.Email)
	return channel
}

// egressPool loads the pool from the supply state directory.
func (h *Handler) egressPool() (*supply.EgressPool, error) {
	return supply.LoadEgressPool(supply.EgressPoolPath(supplyStateDir(h)))
}

// egressRef is one thing bound to an exit, as found on disk.
//
// Ref is what the binding actually says: an id ("2") when the target was
// assigned through the pool, or a bare proxy URL when it was typed by hand.
// Both are matched, because an installation that predates the pool has
// addresses, not ids, and those addresses still describe real bindings.
type egressRef struct {
	Ref    string
	Member egressMember
}

// egressMember is one bound identity, rendered for the panel.
type egressMember struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
}

// egressBindingIndex is every binding found in one scan.
type egressBindingIndex struct {
	Refs []egressRef
	// GlobalRef is the process-wide exit: the pool entry the pool designates as
	// default, or a hand-typed address when no default is set. Empty means the
	// process leaves directly.
	GlobalRef string
	// GlobalSource is "pool" when GlobalRef is a pool id, "custom" when it is a
	// hand-typed address, and empty when there is no process-wide exit.
	GlobalSource string
}

// egressBindings scans every place an exit can be named.
//
// The scan is deliberately read-only and tolerant: one unreadable auth file must
// not hide the other bindings, so per-file failures are skipped rather than
// turned into an error.
func (h *Handler) egressBindings() egressBindingIndex {
	index := egressBindingIndex{}
	index.Refs = append(index.Refs, h.accountEgressRefs()...)
	index.Refs = append(index.Refs, h.channelEgressRefs()...)
	if h.cfg == nil {
		return index
	}
	// The process-wide exit is the pool's default. It is read from the pool
	// rather than from the config file because the pool owns the address, and a
	// config document that still carries an older address must not be reported
	// as the exit in force.
	if pool, errPool := h.egressPool(); errPool == nil {
		if id := pool.DefaultID(); id > 0 {
			index.GlobalRef = strconv.Itoa(id)
			index.GlobalSource = "pool"
			return index
		}
	}
	if typed := strings.TrimSpace(h.cfg.ProxyURL); typed != "" && typed != supply.UnresolvedEgress {
		index.GlobalRef = typed
		index.GlobalSource = "custom"
	}
	return index
}

// accountEgressRefs reads the per-credential exit from every auth file.
func (h *Handler) accountEgressRefs() []egressRef {
	if h == nil || h.cfg == nil || strings.TrimSpace(h.cfg.AuthDir) == "" {
		return nil
	}
	entries, errRead := os.ReadDir(h.cfg.AuthDir)
	if errRead != nil {
		return nil
	}
	out := make([]egressRef, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		raw, errReadFile := os.ReadFile(filepath.Join(h.cfg.AuthDir, entry.Name()))
		if errReadFile != nil {
			continue
		}
		var payload map[string]any
		if errJSON := json.Unmarshal(raw, &payload); errJSON != nil {
			continue
		}
		ref := egressRefFromPayload(payload)
		if ref == "" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		provider, _ := payload["type"].(string)
		out = append(out, egressRef{
			Ref:    ref,
			Member: egressMember{Kind: "account", Name: name, Detail: strings.TrimSpace(provider)},
		})
	}
	return out
}

// egressRefFromPayload picks the binding a stored document carries.
//
// egress_id wins when both are present: it is the authoritative reference, and
// the stored proxy_url beside it is a resolved cache that may be out of date.
func egressRefFromPayload(payload map[string]any) string {
	if id, ok := egressIDValue(payload["egress_id"]); ok {
		return strconv.Itoa(id)
	}
	if value, ok := payload["proxy_url"].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

// egressIDValue reads an id that may arrive as a number or as a string.
func egressIDValue(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		id := int(typed)
		return id, id > 0
	case json.Number:
		id, errParse := typed.Int64()
		return int(id), errParse == nil && id > 0
	case string:
		id, errParse := strconv.Atoi(strings.TrimSpace(typed))
		return id, errParse == nil && id > 0
	}
	return 0, false
}

// channelEgressRefs reads the per-connection exit from every channel.
func (h *Handler) channelEgressRefs() []egressRef {
	store, errStore := h.supplyChannels()
	if errStore != nil {
		return nil
	}
	var out []egressRef
	for _, channel := range store.All() {
		for _, kind := range channel.Kinds() {
			block := channel.KindConfigFor(kind)
			if block == nil {
				continue
			}
			for nature, connection := range block.Connections {
				// An id is the authoritative binding; the address beside it is a
				// cache that goes stale when the exit is replaced, so it must not
				// be counted as a second, separate binding.
				ref := strconv.Itoa(connection.EgressID)
				if connection.EgressID <= 0 {
					ref = strings.TrimSpace(connection.Egress)
				}
				if ref == "" {
					continue
				}
				out = append(out, egressRef{
					Ref: ref,
					Member: egressMember{
						Kind:   "channel",
						Name:   channel.Label,
						Detail: string(kind) + " / " + string(nature),
					},
				})
			}
		}
	}
	return out
}

// sameEgress reports whether a stored reference names the same address as url.
//
// Comparison is intentionally shallow — trimmed, trailing slashes dropped,
// scheme compared case-insensitively. Anything cleverer would start guessing
// that two spellings mean one exit, and a wrong guess here silently merges two
// exits in the panel's counts.
func sameEgress(ref, url string) bool {
	ref = strings.TrimRight(strings.TrimSpace(ref), "/")
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if ref == "" || url == "" {
		return false
	}
	return strings.EqualFold(ref, url)
}

// membersFor collects what is bound to one entry.
func (index egressBindingIndex) membersFor(entry supply.EgressEntry) (members []egressMember, globalBound bool) {
	id := strconv.Itoa(entry.ID)
	for _, ref := range index.Refs {
		if ref.Ref == id || sameEgress(ref.Ref, entry.URL) {
			members = append(members, ref.Member)
		}
	}
	if index.GlobalRef != "" && (index.GlobalRef == id || sameEgress(index.GlobalRef, entry.URL)) {
		globalBound = true
	}
	return members, globalBound
}

// countsFor returns how many identities each entry holds, which is what the
// assignment rule needs.
func (index egressBindingIndex) countsFor(entries []supply.EgressEntry) map[int]int {
	counts := make(map[int]int, len(entries))
	for _, entry := range entries {
		members, globalBound := index.membersFor(entry)
		count := len(members)
		if globalBound {
			count++
		}
		counts[entry.ID] = count
	}
	return counts
}

// egressEntryView renders one entry: never the password, only the address shape.
//
// isDefault marks the exit the whole process leaves through. It is passed in
// rather than read here so a list of entries costs one pool read, not one each.
func egressEntryView(entry supply.EgressEntry, isDefault bool) gin.H {
	view := gin.H{
		"id":      entry.ID,
		"url":     proxyutil.Redact(entry.URL),
		"label":   entry.Label,
		"note":    entry.Note,
		"enabled": entry.Enabled,
		"created": entry.Created,
		"default": isDefault,
	}
	if entry.LastProbe != nil {
		view["last_probe"] = gin.H{
			"ok":           entry.LastProbe.OK,
			"ip":           entry.LastProbe.IP,
			"country":      entry.LastProbe.Country,
			"country_code": entry.LastProbe.CountryCode,
			"city":         entry.LastProbe.City,
			"asn":          entry.LastProbe.ASN,
			"org":          entry.LastProbe.Org,
			"error":        entry.LastProbe.Error,
			"latency_ms":   entry.LastProbe.LatencyMS,
			"at":           entry.LastProbe.At,
		}
	}
	return view
}

// egressDefaultID is the pool's designated default, zero when none is set.
func (h *Handler) egressDefaultID() int {
	pool, errPool := h.egressPool()
	if errPool != nil {
		return 0
	}
	return pool.DefaultID()
}

// GetEgressPool lists the pool with its binding counts.
func (h *Handler) GetEgressPool(c *gin.Context) {
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	entries := pool.List()
	index := h.egressBindings()
	counts := index.countsFor(entries)
	defaultID := pool.DefaultID()

	out := make([]gin.H, 0, len(entries))
	for _, entry := range entries {
		view := egressEntryView(entry, entry.ID == defaultID)
		members, globalBound := index.membersFor(entry)
		byKind := map[string]int{}
		for _, member := range members {
			byKind[member.Kind]++
		}
		if globalBound {
			byKind["global"] = 1
		}
		view["counts"] = byKind
		view["total"] = counts[entry.ID]
		out = append(out, view)
	}
	// The global block is what the panel needs to answer "where does everything
	// leave from" without scanning the entries itself: an id when the pool
	// designates one, a redacted address when the installation still spells it
	// out by hand, and neither when the process leaves directly.
	global := gin.H{"source": index.GlobalSource}
	if defaultID > 0 {
		global["default_id"] = defaultID
	}
	if address := strings.TrimSpace(h.cfg.ProxyURL); address != "" && address != supply.UnresolvedEgress {
		global["address"] = proxyutil.Redact(address)
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"entries": out,
		"global":  global,
	})
}

// PostEgressPool adds one exit.
func (h *Handler) PostEgressPool(c *gin.Context) {
	var body struct {
		URL   string `json:"url"`
		Label string `json:"label"`
		Note  string `json:"note"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	entry, errAdd := pool.Add(body.URL, body.Label, body.Note)
	if errAdd != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errAdd.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "entry": egressEntryView(entry, false)})
}

// egressEntryWithCounts renders one entry plus what is bound to it.
//
// Single-entry responses use this; the list endpoint counts every entry from one
// scan instead, because rescanning the auth directory per entry would make the
// pool page cost grow with the number of exits.
func (h *Handler) egressEntryWithCounts(entry supply.EgressEntry) gin.H {
	view := egressEntryView(entry, entry.ID == h.egressDefaultID())
	members, globalBound := h.egressBindings().membersFor(entry)
	byKind := map[string]int{}
	for _, member := range members {
		byKind[member.Kind]++
	}
	if globalBound {
		byKind["global"] = 1
	}
	view["counts"] = byKind
	view["total"] = len(members) + boolToInt(globalBound)
	return view
}

// PatchEgressPool edits one exit.
//
// An omitted url means "keep the stored one": the panel only ever reads the
// address back redacted, so a client that renders and re-submits what it was
// given can never echo the real value. Clearing an exit is a delete, not an
// edit with an empty address.
func (h *Handler) PatchEgressPool(c *gin.Context) {
	id, errID := egressPathID(c)
	if errID != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errID.Error()})
		return
	}
	var body struct {
		URL     *string `json:"url"`
		Label   *string `json:"label"`
		Note    *string `json:"note"`
		Enabled *bool   `json:"enabled"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	existing, found := pool.Get(id)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "no such exit"})
		return
	}
	edit := supply.EgressEdit{Label: body.Label, Note: body.Note, Enabled: body.Enabled}
	// A submitted address that equals the redacted form is the panel echoing
	// what it was shown, not a new address. Treating it as an edit would replace
	// the real password with the literal string "redacted" and take every bound
	// account offline, so it counts as "unchanged".
	if body.URL != nil && !sameEgress(*body.URL, proxyutil.Redact(existing.URL)) && strings.TrimSpace(*body.URL) != "" {
		edit.URL = body.URL
	}
	updated, errUpdate := pool.Update(id, edit)
	if errUpdate != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errUpdate.Error()})
		return
	}
	// Nothing else to notify: consumers ask for the address on each request, so a
	// replaced address is in force from the next one on.
	c.JSON(http.StatusOK, gin.H{"status": "ok", "entry": h.egressEntryWithCounts(updated)})
}

// DeleteEgressPool removes one exit.
//
// It refuses while anything is still bound: deleting an exit that accounts point
// at would leave them resolving to nothing, and the operator would find out from
// a failing signup rather than from this call.
func (h *Handler) DeleteEgressPool(c *gin.Context) {
	id, errID := egressPathID(c)
	if errID != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errID.Error()})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	entry, found := pool.Get(id)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "no such exit"})
		return
	}
	index := h.egressBindings()
	members, globalBound := index.membersFor(entry)
	if total := len(members) + boolToInt(globalBound); total > 0 {
		c.JSON(http.StatusConflict, gin.H{
			"status": "error",
			"error":  "this exit still has identities bound to it; move or unbind them first",
			"counts": total,
		})
		return
	}
	if errDelete := pool.Delete(id); errDelete != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errDelete.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// PostEgressPoolProbe asks an echo service what address one exit presents, and
// remembers the answer.
//
// This is the call that makes the pool more than a list: an exit is bought by
// its address, and the only way to know the address is to ask from the far side.
func (h *Handler) PostEgressPoolProbe(c *gin.Context) {
	id, errID := egressPathID(c)
	if errID != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errID.Error()})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	entry, found := pool.Get(id)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "no such exit"})
		return
	}

	transport, mode, errTransport := proxyutil.BuildHTTPTransport(entry.URL)
	if errTransport != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errTransport.Error()})
		return
	}
	client := &http.Client{Timeout: egressProbeTimeout}
	if transport != nil && (mode == proxyutil.ModeProxy || mode == proxyutil.ModeDirect) {
		client.Transport = transport
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), egressProbeTimeout)
	defer cancel()

	started := time.Now()
	echo, service, errProbe := probeExit(ctx, client)
	elapsed := time.Since(started).Milliseconds()

	probe := supply.EgressProbe{LatencyMS: elapsed, At: time.Now().Unix()}
	if errProbe != nil {
		probe.Error = errProbe.Error()
	} else {
		probe.OK = true
		probe.IP = echo.IP
		probe.Country = echo.Country
		probe.CountryCode = echo.CountryCode
		probe.City = echo.City
		probe.ASN = echo.ASN
		probe.Org = echo.Org
	}
	recorded, errRecord := pool.RecordProbe(id, probe)
	if errRecord != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errRecord.Error()})
		return
	}

	view := egressEntryView(recorded, recorded.ID == h.egressDefaultID())
	view["via"] = service
	if errProbe != nil {
		// No echo service confirmed an address. That is not the same as the exit
		// being broken, so the reason is reported rather than a verdict.
		c.JSON(http.StatusBadGateway, gin.H{"status": "error", "error": errProbe.Error(), "entry": view})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "entry": view})
}

// GetEgressPoolMembers lists exactly what is bound to one exit.
func (h *Handler) GetEgressPoolMembers(c *gin.Context) {
	id, errID := egressPathID(c)
	if errID != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errID.Error()})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	entry, found := pool.Get(id)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "error": "no such exit"})
		return
	}
	members, globalBound := h.egressBindings().membersFor(entry)
	if members == nil {
		members = []egressMember{}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"entry":   egressEntryView(entry, entry.ID == pool.DefaultID()),
		"members": members,
		"global":  globalBound,
	})
}

// PostEgressPoolDefault makes one exit the process-wide default, or clears it
// when id is zero.
//
// This is the whole "one place" promise: with a default set, every request
// leaves through that address, and replacing the address later is one edit in
// the pool rather than one edit per consumer. With no default the installation
// keeps whatever address the config file spells out, which is what an
// installation that never opened the pool has.
func (h *Handler) PostEgressPoolDefault(c *gin.Context) {
	var body struct {
		ID int `json:"id"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	if errSet := pool.SetDefault(body.ID); errSet != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errSet.Error()})
		return
	}
	// The new default is in force from the next request on; no reload needed.
	c.JSON(http.StatusOK, gin.H{"status": "ok", "default_id": body.ID})
}

// PostEgressPoolImport moves the hand-written proxy address into the pool.
//
// An installation that predates the pool spells its exit out in the config file.
// That address is a real exit, so folding it in is one step: take it into the
// list, make it the default, and clear the file's copy. The address then has one
// home, and replacing it later is one edit in the list rather than an edit in a
// file nobody opens.
func (h *Handler) PostEgressPoolImport(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": "no config loaded"})
		return
	}
	typed := strings.TrimSpace(h.cfg.ProxyURL)
	if typed == "" || typed == supply.UnresolvedEgress {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "there is no hand-written address to move"})
		return
	}
	normalized, errURL := supply.NormalizeEgressURL(typed)
	if errURL != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errURL.Error()})
		return
	}
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	// The same address already in the list is the same exit. Point at that row
	// instead of adding a second one that says nothing new.
	target := 0
	for _, entry := range pool.List() {
		if entry.URL == normalized {
			target = entry.ID
			break
		}
	}
	if target == 0 {
		entry, errAdd := pool.Add(normalized, "", "")
		if errAdd != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": errAdd.Error()})
			return
		}
		target = entry.ID
	}
	if errSet := pool.SetDefault(target); errSet != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errSet.Error()})
		return
	}
	// Clear the file's copy so one exit does not end up recorded twice. The pool
	// already owns the address in force, so a failed save leaves traffic correct
	// and only the stale copy behind.
	h.mu.Lock()
	h.cfg.ProxyURL = ""
	h.mu.Unlock()
	// persist answers the request itself. The caller re-reads the list to pick up
	// the new entry, which is where the exit is now visible.
	h.persist(c)
}

// PostEgressPoolNext reports which exit a new identity would be given right now.
//
// It exists so the assignment rule is inspectable: an operator asking "why is
// the next account on #2" gets an answer before the account exists, not after.
func (h *Handler) PostEgressPoolNext(c *gin.Context) {
	pool, errPool := h.egressPool()
	if errPool != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errPool.Error()})
		return
	}
	entries := pool.List()
	index := h.egressBindings()
	next, ok := pool.Next(index.countsFor(entries))
	if !ok {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "entry": nil})
		return
	}
	view := egressEntryView(next, next.ID == pool.DefaultID())
	view["total"] = index.countsFor(entries)[next.ID]
	c.JSON(http.StatusOK, gin.H{"status": "ok", "entry": view})
}

// egressPathID reads the :id path parameter.
func egressPathID(c *gin.Context) (int, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(c.Param("id")), "#")
	id, errParse := strconv.Atoi(raw)
	if errParse != nil || id <= 0 {
		return 0, errNoEgressID
	}
	return id, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
