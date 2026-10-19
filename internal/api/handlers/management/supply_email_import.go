package management

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
)

// This file imports a batch of mailboxes from the paste an operator gets from a
// mailbox seller: one mailbox per line, four fields separated by "----"
// (account, password, application id, refresh token).
//
// Why a batch route instead of the panel looping over the two existing routes:
// a hundred mailboxes would be two hundred round-trips, a hundred supply
// rebuilds, and a hundred chances to leave a channel without a credential.
// Parsing happens before anything is written, so a malformed line is reported
// without touching the store, and the supply service is rebuilt once at the end.
//
// The password field is parsed and discarded. A Microsoft mailbox answers
// LOGINDISABLED to a password login, so the refresh token is the only thing that
// can authenticate — and storing the password would be keeping a secret that
// cannot be used for anything.

const (
	// importedMailboxHost is where a Microsoft consumer mailbox is read. It is
	// the default rather than the only choice because a seller's batch can be
	// for a different host, and the line format does not carry one.
	defaultImportedMailboxHost = "outlook.office365.com:993"
	// importProbeTimeout bounds one mailbox's probe. The token exchange and the
	// IMAP login each have their own dial timeout; this is the outer stop.
	importProbeTimeout = 25 * time.Second
	// importProbeWorkers is how many mailboxes are checked at once. The probe is
	// network-bound and mostly waiting, so a small pool turns a batch of twenty
	// from half a minute into a few seconds; the cap keeps a thousand-line paste
	// from opening a thousand IMAP connections.
	importProbeWorkers = 6
	// importedLineFields is how many "----" separated fields a line carries.
	importedLineFields = 4
)

// mailboxLine is one parsed line of the paste. A parse failure is carried rather
// than returned so the answer can name the line that was wrong.
type mailboxLine struct {
	Line     int
	Account  string
	ClientID string
	Refresh  string
	Err      error
}

// PostSupplyEmailImport stores a batch of Microsoft mailboxes: one channel per
// mailbox, with the refresh token in the secret store.
//
// A mailbox that cannot be reached is not imported. Creating a channel whose
// credential is already known to be dead would put a row in the table that can
// only ever read nothing, and the operator would have to find it by hand. The
// probe is optional (probe=false) for a batch that is being imported somewhere
// without network access to the provider; the channel table's own probe then
// reports the same verdict later.
func (h *Handler) PostSupplyEmailImport(c *gin.Context) {
	var body struct {
		Text       string `json:"text"`
		Host       string `json:"host"`
		Nature     string `json:"nature"`
		Passphrase string `json:"passphrase"`
		Probe      *bool  `json:"probe"`
	}
	if errBind := c.ShouldBindJSON(&body); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "invalid JSON body"})
		return
	}
	nature, okNature := importMailboxNature(body.Nature)
	if !okNature {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "unknown receiving method"})
		return
	}
	lines := parseMailboxLines(body.Text)
	if len(lines) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "no mailbox lines to import"})
		return
	}
	host := strings.TrimSpace(body.Host)
	if host == "" {
		host = defaultImportedMailboxHost
	}
	// Graph has one endpoint, so a host from the panel is not stored for it.
	if nature == supply.NatureGraph {
		host = ""
	}
	// The gate runs once for the whole batch: it is the same secret store for
	// every mailbox, and asking per line would turn one unlock into a hundred.
	store, alreadyAnswered := gateSupplyWrite(c, body.Passphrase)
	if alreadyAnswered {
		return
	}
	channels, errStore := h.supplyChannels()
	if errStore != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errStore.Error()})
		return
	}
	probe := true
	if body.Probe != nil {
		probe = *body.Probe
	}

	// Probes run first and in parallel, so the writes that follow stay in line
	// order and the answer reads like the paste. A probe that hangs holds its
	// worker, not the whole batch.
	probeDetails := make([]string, len(lines))
	if probe {
		sem := make(chan struct{}, importProbeWorkers)
		var wg sync.WaitGroup
		for index, line := range lines {
			if line.Err != nil {
				continue
			}
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(c.Request.Context(), importProbeTimeout)
				defer cancel()
				var errProbe error
				if nature == supply.NatureGraph {
					_, errProbe = email.ProbeGraph(ctx, line.Account, line.ClientID, line.Refresh)
				} else {
					_, errProbe = email.ProbeOAuth2(ctx, host, line.Account, line.ClientID, line.Refresh)
				}
				if errProbe != nil {
					probeDetails[index] = probeDetail(errProbe)
				}
			})
		}
		wg.Wait()
	}

	imported, updated, failed := 0, 0, 0
	results := make([]gin.H, 0, len(lines))
	for index, line := range lines {
		result := gin.H{"line": line.Line, "account": line.Account}
		if line.Err != nil {
			failed++
			result["outcome"] = "failed"
			result["detail"] = line.Err.Error()
			results = append(results, result)
			continue
		}
		if detail := probeDetails[index]; detail != "" {
			failed++
			result["outcome"] = "failed"
			result["detail"] = detail
			results = append(results, result)
			continue
		}
		// Credential first, channel second — the same order the panel's editor
		// uses. A channel that exists without a credential is a row that looks
		// configured and can never authenticate.
		name := supply.EmailOAuth2CredentialName(line.Account)
		if errSet := store.Set(name, line.Refresh); errSet != nil {
			failed++
			result["outcome"] = "failed"
			result["detail"] = errSet.Error()
			results = append(results, result)
			continue
		}
		existing, found := findMailboxChannel(channels.All(), line.Account)
		channel := supply.Channel{
			ID:       existing.ID,
			Label:    line.Account,
			Category: "third-party",
			Email: &supply.KindConfig{
				Enabled: true,
				Natures: []supply.Nature{nature},
				Connections: map[supply.Nature]supply.Connection{
					nature: {
						Endpoint: host,
						Account:  line.Account,
						ClientID: line.ClientID,
					},
				},
			},
		}
		saved, errSave := channels.Upsert(channel, time.Now().Unix())
		if errSave != nil {
			failed++
			result["outcome"] = "failed"
			result["detail"] = errSave.Error()
			results = append(results, result)
			continue
		}
		if found {
			updated++
			result["outcome"] = "updated"
		} else {
			imported++
			result["outcome"] = "imported"
		}
		result["channel_id"] = saved.ID
		results = append(results, result)
	}
	// One rebuild covers the whole batch: the provider reads its channels and
	// credentials per call, but the registry caches the provider itself.
	if imported+updated > 0 {
		reloadSupply()
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"host":     host,
		"nature":   string(nature),
		"imported": imported,
		"updated":  updated,
		"failed":   failed,
		"results":  results,
	})
}

// importMailboxNature reads the receiving method a batch was pasted for.
//
// The empty answer means the older default: a refresh token spent on IMAP. It
// stays the default because a panel that predates Graph sends nothing, and those
// batches are still IMAP batches.
func importMailboxNature(value string) (supply.Nature, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(supply.NatureOAuth2), "imap":
		return supply.NatureOAuth2, true
	case string(supply.NatureGraph):
		return supply.NatureGraph, true
	}
	return "", false
}

// parseMailboxLines reads the paste into one entry per line. Blank lines and
// lines starting with '#' are skipped so a batch can carry the seller's own
// header without every line being reported as malformed.
func parseMailboxLines(text string) []mailboxLine {
	out := make([]mailboxLine, 0, 16)
	lineNumber := 0
	for _, raw := range strings.Split(text, "\n") {
		lineNumber++
		trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		entry := mailboxLine{Line: lineNumber}
		fields := strings.Split(trimmed, "----")
		if len(fields) != importedLineFields {
			entry.Err = errMailboxLine("expected 4 fields separated by ----")
			out = append(out, entry)
			continue
		}
		entry.Account = strings.ToLower(strings.TrimSpace(fields[0]))
		entry.ClientID = strings.TrimSpace(fields[2])
		entry.Refresh = strings.TrimSpace(fields[3])
		switch {
		case !strings.Contains(entry.Account, "@"):
			entry.Err = errMailboxLine("the first field is not a mailbox address")
		case entry.ClientID == "":
			entry.Err = errMailboxLine("the third field (application id) is empty")
		case !looksLikeClientID(entry.ClientID):
			entry.Err = errMailboxLine("the third field is not an application id")
		case entry.Refresh == "":
			entry.Err = errMailboxLine("the fourth field (refresh token) is empty")
		}
		out = append(out, entry)
	}
	return out
}

// looksLikeClientID reports whether value has the shape of an Azure application
// id. The check exists because the two tokens are both long opaque strings: if a
// batch were written in a different field order, storing the refresh token as
// the application id would fail at token time with "the client id is not
// usable", which reads as a bad credential rather than as a bad line.
func looksLikeClientID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, r := range value {
		switch index {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
			if !isHex {
				return false
			}
		}
	}
	return true
}

// errMailboxLine labels a parse failure with the part of the line that is wrong,
// so the operator can fix the paste instead of guessing.
type errMailboxLine string

func (e errMailboxLine) Error() string { return string(e) }

// probeDetail strips the provider's package prefixes from a probe failure. The
// panel shows this line as it is, and two stacked prefixes ("email: the mailbox
// credential is not usable: email: ...") say nothing an operator needs.
func probeDetail(err error) string {
	text := strings.TrimSpace(err.Error())
	for {
		trimmed := text
		for _, prefix := range []string{
			"email: ",
			"the mailbox credential is not usable: ",
			"the mailbox rejected the login: ",
		} {
			trimmed = strings.TrimPrefix(trimmed, prefix)
		}
		if trimmed == text {
			break
		}
		text = trimmed
	}
	return text
}

// findMailboxChannel returns the channel that already reads account, so a
// re-import refreshes that channel instead of adding a second one for the same
// mailbox.
func findMailboxChannel(channels []supply.Channel, account string) (supply.Channel, bool) {
	wanted := strings.ToLower(strings.TrimSpace(account))
	for _, channel := range channels {
		if channel.Email == nil {
			continue
		}
		for _, nature := range channel.Email.Natures {
			if !nature.IsMailbox() {
				continue
			}
			connection := channel.Email.Connections[nature]
			if strings.ToLower(strings.TrimSpace(connection.Account)) == wanted {
				return channel, true
			}
		}
	}
	return supply.Channel{}, false
}
