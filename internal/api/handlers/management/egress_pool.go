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
	// SupplyRef is the supply-wide exit, empty when none is configured.
	SupplyRef string
	// SupplySource says where the supply-wide exit came from, so the panel can
	// tell "inherited from the host proxy" apart from "set on the supply".
	SupplySource string
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
	if h.cfg != nil {
		supplyCfg := h.cfg.Supply.WithDefaults()
		switch {
		case supplyCfg.EgressID > 0:
			index.SupplyRef = strconv.Itoa(supplyCfg.EgressID)
			index.SupplySource = "supply"
		case strings.TrimSpace(supplyCfg.Egress) != "":
			index.SupplyRef = strings.TrimSpace(supplyCfg.Egress)
			index.SupplySource = "supply"
		case strings.TrimSpace(h.cfg.ProxyURL) != "":
			// Not a pool binding, but still the address supply traffic leaves
			// through, so it is reported: otherwise the panel would say "no exit"
			// while supply traffic demonstrably goes somewhere.
			index.SupplyRef = strings.TrimSpace(h.cfg.ProxyURL)
			index.SupplySource = "host"
		}
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
func (index egressBindingIndex) membersFor(entry supply.EgressEntry) (members []egressMember, supplyBound bool) {
	id := strconv.Itoa(entry.ID)
	for _, ref := range index.Refs {
		if ref.Ref == id || sameEgress(ref.Ref, entry.URL) {
			members = append(members, ref.Member)
		}
	}
	if index.SupplyRef != "" && (index.SupplyRef == id || sameEgress(index.SupplyRef, entry.URL)) {
		supplyBound = true
	}
	return members, supplyBound
}

// countsFor returns how many identities each entry holds, which is what the
// assignment rule needs.
func (index egressBindingIndex) countsFor(entries []supply.EgressEntry) map[int]int {
	counts := make(map[int]int, len(entries))
	for _, entry := range entries {
		members, supplyBound := index.membersFor(entry)
		count := len(members)
		if supplyBound {
			count++
		}
		counts[entry.ID] = count
	}
	return counts
}

// egressEntryView renders one entry: never the password, only the address shape.
func egressEntryView(entry supply.EgressEntry) gin.H {
	view := gin.H{
		"id":      entry.ID,
		"url":     proxyutil.Redact(entry.URL),
		"label":   entry.Label,
		"note":    entry.Note,
		"enabled": entry.Enabled,
		"created": entry.Created,
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

	out := make([]gin.H, 0, len(entries))
	for _, entry := range entries {
		view := egressEntryView(entry)
		members, supplyBound := index.membersFor(entry)
		byKind := map[string]int{}
		for _, member := range members {
			byKind[member.Kind]++
		}
		if supplyBound {
			byKind["supply"] = 1
		}
		view["counts"] = byKind
		view["total"] = counts[entry.ID]
		out = append(out, view)
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"entries": out,
		"supply": gin.H{
			"bound":  index.SupplyRef != "",
			"source": index.SupplySource,
		},
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
	c.JSON(http.StatusOK, gin.H{"status": "ok", "entry": egressEntryView(entry)})
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
	view := egressEntryView(updated)
	index := h.egressBindings()
	members, supplyBound := index.membersFor(updated)
	byKind := map[string]int{}
	for _, member := range members {
		byKind[member.Kind]++
	}
	if supplyBound {
		byKind["supply"] = 1
	}
	view["counts"] = byKind
	view["total"] = len(members) + boolToInt(supplyBound)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "entry": view})
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
	members, supplyBound := index.membersFor(entry)
	if total := len(members) + boolToInt(supplyBound); total > 0 {
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

	view := egressEntryView(recorded)
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
	members, supplyBound := h.egressBindings().membersFor(entry)
	if members == nil {
		members = []egressMember{}
	}
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"entry":   egressEntryView(entry),
		"members": members,
		"supply":  supplyBound,
	})
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
	view := egressEntryView(next)
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
