package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
)

// This file is the cross-kind identity ledger's management surface. It answers
// the one question the per-kind surfaces cannot: which identity is behind a
// credential, and which platform did it register on.
//
// The ledger itself is written by the supply service (internal/supply); this
// surface only reads it. A record's auth_index is best-effort — it is derived
// from the credential, which does not exist yet at the moment the record is
// written — so when it is absent the reader resolves it from the account name
// against the live credential list.

// GetSupplyLedger reports every identity the host has handed out, across kinds.
//
// Optional filters: ?kind=phone|email and ?target=<platform>.
func (h *Handler) GetSupplyLedger(c *gin.Context) {
	ledger := supply.DefaultLedger()
	if ledger == nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": false, "records": []any{}})
		return
	}
	filterKind := supply.Kind(strings.ToLower(strings.TrimSpace(c.Query("kind"))))
	filterTarget := strings.TrimSpace(c.Query("target"))
	index := h.authIndexByName()

	records := ledger.All()
	out := make([]gin.H, 0, len(records))
	for _, record := range records {
		if filterKind.Valid() && record.Kind != filterKind {
			continue
		}
		if filterTarget != "" && record.Target != filterTarget {
			continue
		}
		out = append(out, ledgerRecordView(record, index))
	}
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"enabled":   true,
		"records":   out,
		"spent_cny": ledger.Spent(),
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

// ledgerRecordView renders one record for the panel.
func ledgerRecordView(record supply.Record, index map[string]string) gin.H {
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
	if resolved {
		view["auth_index_resolved"] = true
	}
	if len(record.Meta) > 0 {
		view["meta"] = record.Meta
	}
	return view
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
// file name without its ".json" suffix, lower-cased. A ledger account is stored
// without the suffix (it is the account name, not a file), so the suffix is
// dropped before comparing.
func normalizeCredentialName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(name, ".json")
}
