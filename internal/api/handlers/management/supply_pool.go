package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// This file is the cross-kind identity pool's management surface. It answers
// the one question the per-kind surfaces cannot: which identity is behind a
// credential, and which platform did it register on.
//
// The pool itself is written by the supply service (internal/supply); this
// surface only reads it. A record's auth_index is best-effort — it is derived
// from the credential, which does not exist yet at the moment the record is
// written — so when it is absent the reader resolves it from the account name
// against the live credential list.

// GetSupplyPool reports every identity the host has handed out, across kinds.
//
// Optional filters: ?kind=phone|email and ?target=<platform>.
func (h *Handler) GetSupplyPool(c *gin.Context) {
	pool := supply.DefaultPool()
	if pool == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": false, "records": []any{}})
		return
	}
	filterKind := supply.Kind(strings.ToLower(strings.TrimSpace(c.Query("kind"))))
	filterTarget := strings.TrimSpace(c.Query("target"))
	index := h.authIndexByName()
	secrets := secretStatus(c)

	records := pool.All()
	out := make([]gin.H, 0, len(records))
	for _, record := range records {
		if filterKind.Valid() && record.Kind != filterKind {
			continue
		}
		if filterTarget != "" && record.Target != filterTarget {
			continue
		}
		out = append(out, poolRecordView(record, index, secrets))
	}
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"enabled":   true,
		"records":   out,
		"spent_cny": pool.Spent(),
	})
}

// resolveAuthIndex returns a record's credential index: the one it carries, or
// one looked up from its account name against the live credential list. The
// second result reports whether the value had to be resolved, so a reader can
// say where it came from.
//
// Resolution happens on read because the index is derived from the credential,
// and a freshly linked record predates it. Every surface that reports a record
// goes through here, so the same identity shows the same index everywhere.
func resolveAuthIndex(record supply.Record, index map[string]string) (string, bool) {
	if authIndex := strings.TrimSpace(record.AuthIndex); authIndex != "" {
		return authIndex, false
	}
	if record.Account == "" || index == nil {
		return "", false
	}
	found := index[normalizeCredentialName(record.Account)]
	if found == "" {
		return "", false
	}
	return found, true
}

// poolProjectView is one registration as the panel shows it: which platform the
// identity registered on, which account it produced, how that ended, and when it
// was last seen.
type poolProjectView struct {
	Target  string `json:"target"`
	Account string `json:"account,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	At      int64  `json:"at,omitempty"`
}

// poolRecordView renders one record for the panel.
func poolRecordView(record supply.Record, index map[string]string, secrets secretStatusPayload) gin.H {
	authIndex, resolved := resolveAuthIndex(record, index)
	view := gin.H{
		"kind":       string(record.Kind),
		"address":    record.Address,
		"source":     record.Source,
		"target":     record.Target,
		"account":    record.Account,
		"auth_index": authIndex,
		"price":      record.Price,
		"outcome":    record.Outcome,
		"state":      record.State,
		"rents":      record.Rents,
		"spend":      record.Spend,
		"first_seen": record.FirstSeen,
		"last_used":  record.LastUsed,
	}
	if record.ChannelID != "" {
		view["channel_id"] = record.ChannelID
	}
	// An identity that carries its own way of reading mail says so, because the
	// panel cannot infer it: a bought mailbox has no channel to look it up in.
	// Only whether each secret exists is reported, never its value.
	if box := record.Mailbox; box != nil {
		mailbox := gin.H{
			"nature":    string(box.Nature),
			"endpoint":  box.Endpoint,
			"client_id": box.ClientID,
		}
		if secrets.Enabled && secrets.Unlocked {
			mailbox["has_credential"] = contains(secrets.Names, box.Secret)
			mailbox["has_password"] = box.Password != "" && contains(secrets.Names, box.Password)
		}
		view["mailbox"] = mailbox
	}
	if resolved {
		view["auth_index_resolved"] = true
	}
	if len(record.Meta) > 0 {
		view["meta"] = record.Meta
	}
	// The registrations are the identity's history, so the panel can show the
	// accounts one address or number produced. An entry without a target is not
	// a registration and is left out rather than shown as an empty platform.
	projects := make([]poolProjectView, 0, len(record.Registrations))
	for _, registration := range record.Registrations {
		if strings.TrimSpace(registration.Target) == "" {
			continue
		}
		projects = append(projects, poolProjectView{
			Target:  registration.Target,
			Account: registration.Account,
			Outcome: registration.Outcome,
			At:      registration.At,
		})
	}
	if len(projects) > 0 {
		view["projects"] = projects
	}
	return view
}

// PostSupplyPoolAccount records one registration an identity was used for.
//
// The pool is otherwise written by the supply kinds themselves, but a
// registration is the one fact a caller knows better than the host: whoever ran
// the signup knows the platform, the account name and how it ended. This lets
// that be reported instead of guessed, and it is also how an identity handed out
// before the pool kept registrations is backfilled.
//
// The body is {"kind":"phone|email","address":"...","channel_id":"...",
// "target":"...","account":"...","outcome":"..."}. Kind, address and target are
// required: without them there is no identity and no registration to record.
func (h *Handler) PostSupplyPoolAccount(c *gin.Context) {
	var body struct {
		Kind      string `json:"kind"`
		Address   string `json:"address"`
		ChannelID string `json:"channel_id"`
		Target    string `json:"target"`
		Account   string `json:"account"`
		AuthIndex string `json:"auth_index"`
		Outcome   string `json:"outcome"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	kind := supply.Kind(strings.ToLower(strings.TrimSpace(body.Kind)))
	if !kind.Valid() {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "kind must be phone or email"})
		return
	}
	address := strings.TrimSpace(body.Address)
	if address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "address is required"})
		return
	}
	target := strings.TrimSpace(body.Target)
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "target is required"})
		return
	}
	pool := supply.DefaultPool()
	if pool == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": false})
		return
	}
	pool.Register(kind, address, body.ChannelID, target, body.Account, body.AuthIndex, body.Outcome, time.Now().Unix())
	if errSave := pool.Save(supply.PoolPath(supplyStateDir(h))); errSave != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errSave.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// authIndexByName maps a credential name to its runtime auth index. Both the
// credential's file name and its id are indexed, because a record's account may
// match either, and both are normalised so the ".json" suffix and case do not
// decide a match.
func (h *Handler) authIndexByName() map[string]string {
	if h == nil || h.authManager == nil {
		return nil
	}
	auths := h.authManager.List()
	out := make(map[string]string, len(auths)*2)
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		index := strings.TrimSpace(auth.EnsureIndex())
		if index == "" {
			continue
		}
		for _, name := range []string{auth.FileName, auth.ID} {
			if key := normalizeCredentialName(name); key != "" {
				out[key] = index
			}
		}
	}
	return out
}

// normalizeCredentialName reduces a credential name to its comparable form: the
// file name without its ".json" suffix, lower-cased. A pool account is stored
// without the suffix (it is the account name, not a file), so the suffix is
// dropped before comparing.
func normalizeCredentialName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(name, ".json")
}
