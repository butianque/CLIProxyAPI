package management

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
)

// This file imports a batch of mailboxes from the paste an operator gets from a
// mailbox seller: one mailbox per line.
//
// Two line formats are read, because the two transports need different things.
// A token batch (oauth2, graph) carries four "----" separated fields: account,
// password, application id, refresh token. An IMAP batch carries two or three:
// account, password, and optionally host:port; the password is the login itself,
// so there is no application id and no refresh token to carry.
//
// Why a batch route instead of the panel looping over the two existing routes: a
// hundred mailboxes would be two hundred round-trips and a hundred chances to
// leave a mailbox without a credential. Parsing happens before anything is
// written, so a malformed line is reported without touching the store.
//
// What it writes is a pool identity per line, not a channel. A bought mailbox is
// one address with its own credential; a channel is one connection that covers
// many addresses. Filing a bought batch as channels turned the channel table into
// an address book — one row per mailbox, each claiming to be a source of
// identities.
//
// Both secrets are kept for a token batch. The refresh token is what a transport
// authenticates with, and the password is what a person signing in to the
// mailbox's own web page needs; Microsoft refuses the password on IMAP and Graph
// alike, so nothing in the token read path ever spends it. An IMAP batch is the
// other way round: its password is the credential the transport logs in with, and
// the same value is stored under the manual-sign-in entry so the two views of one
// mailbox cannot disagree.

const (
	// importedMailboxHost is where a Microsoft consumer mailbox is read. It is
	// the default rather than the only choice because a seller's batch can be
	// for a different host, and a token line format does not carry one.
	defaultImportedMailboxHost = "outlook.office365.com:993"
	// importProbeTimeout bounds one mailbox's probe. The token exchange and the
	// IMAP login each have their own dial timeout; this is the outer stop.
	importProbeTimeout = 25 * time.Second
	// importProbeWorkers is how many mailboxes are checked at once. The probe is
	// network-bound and mostly waiting, so a small pool turns a batch of twenty
	// from half a minute into a few seconds; the cap keeps a thousand-line paste
	// from opening a thousand IMAP connections.
	importProbeWorkers = 6
	// importedLineFields is how many "----" separated fields a token line
	// carries: account, password, application id, refresh token.
	importedLineFields = 4
	// importedIMAPLineFields is the minimum an IMAP line carries: account and
	// password. A third field names the host, overriding the batch's.
	importedIMAPLineFields = 2
)

// mailboxLine is one parsed line of the paste. A parse failure is carried rather
// than returned so the answer can name the line that was wrong.
type mailboxLine struct {
	Line     int
	Account  string
	Password string
	ClientID string
	Refresh  string
	// Host is the IMAP host this line is read from. It is empty for the token
	// formats, which take the batch host, and for an IMAP line whose host is
	// missing — which is why such a line carries an Err.
	Host string
	Err  error
}

// PostSupplyEmailImport stores a batch of mailboxes as pool identities, with
// every secret in the secret store.
//
// A mailbox that cannot be reached is not imported. Storing an identity whose
// credential is already known to be dead would put a row in the pool that can
// only ever read nothing, and the operator would have to find it by hand. The
// probe is optional (probe=false) for a batch that is being imported somewhere
// without network access to the provider.
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
	batchHost := strings.TrimSpace(body.Host)
	lines := parseMailboxLines(body.Text, nature, batchHost)
	if len(lines) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "error": "no mailbox lines to import"})
		return
	}
	host := batchHost
	switch nature {
	case supply.NatureGraph:
		// Graph has one endpoint, so a host from the panel is not stored for it.
		host = ""
	case supply.NatureIMAP:
		// An IMAP batch names its host per line; the batch value is only the
		// fallback a two-field line takes, and filling in the Outlook default
		// would send another provider's mailbox to a server that never heard of
		// it. A line left with no host at all is marked as failed by the parser.
	default:
		if host == "" {
			host = defaultImportedMailboxHost
		}
	}
	// The gate runs once for the whole batch: it is the same secret store for
	// every mailbox, and asking per line would turn one unlock into a hundred.
	vault, alreadyAnswered := gateSupplyWrite(c, body.Passphrase)
	if alreadyAnswered {
		return
	}
	pool := supply.DefaultPool()
	if pool == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "error",
			"error":  "the supply pool is not configured",
		})
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
				// The probe takes the supply exit: an import runs before any
				// channel exists, so there is no per-channel override to read.
				egress := h.supplyExit()
				switch nature {
				case supply.NatureGraph:
					_, errProbe = email.ProbeGraph(ctx, line.Account, line.ClientID, line.Refresh, egress)
				case supply.NatureIMAP:
					// Each line carries its own host: a paste can mix providers,
					// and probing one line's mailbox against another line's
					// server would report a credential failure that is not there.
					_, errProbe = email.ProbeIMAP(ctx, line.Host, line.Account, line.Password, egress)
				default:
					_, errProbe = email.ProbeOAuth2(ctx, host, line.Account, line.ClientID, line.Refresh, egress)
				}
				if errProbe != nil {
					probeDetails[index] = probeDetail(errProbe)
				}
			})
		}
		wg.Wait()
	}

	now := time.Now().Unix()
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
		// Credential first, identity second — the same order the panel's editor
		// uses. An identity that exists without a credential is a row that looks
		// configured and can never authenticate.
		box, detail := storeImportedMailbox(vault, nature, host, line)
		if detail != "" {
			failed++
			result["outcome"] = "failed"
			result["detail"] = detail
			results = append(results, result)
			continue
		}
		_, created := pool.AttachMailbox(supply.KindEmail, line.Account, box, now)
		if created {
			imported++
			result["outcome"] = "imported"
		} else {
			updated++
			result["outcome"] = "updated"
		}
		results = append(results, result)
	}
	// One save covers the whole batch: the pool is one document, and a save per
	// line would rewrite it a hundred times.
	if imported+updated > 0 {
		if errSave := pool.Save(supply.PoolPath(supplyStateDir(h))); errSave != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "error": errSave.Error()})
			return
		}
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
//
// "imap" used to answer oauth2 as well, because the only IMAP this route could
// write was a token login. It now answers imap: a mailbox that logs in with its
// own password is a different transport with a different line format, and
// silently filing it as a token batch stored a refresh token that did not exist.
func importMailboxNature(value string) (supply.Nature, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(supply.NatureOAuth2):
		return supply.NatureOAuth2, true
	case "imap":
		return supply.NatureIMAP, true
	case string(supply.NatureGraph):
		return supply.NatureGraph, true
	}
	return "", false
}

// parseMailboxLines reads the paste into one entry per line. Blank lines and
// lines starting with '#' are skipped so a batch can carry the seller's own
// header without every line being reported as malformed.
//
// The line format follows the transport: a token batch carries four fields and
// an IMAP batch carries two or three, so the same paste cannot be read the same
// way for both.
func parseMailboxLines(text string, nature supply.Nature, batchHost string) []mailboxLine {
	out := make([]mailboxLine, 0, 16)
	lineNumber := 0
	for _, raw := range strings.Split(text, "\n") {
		lineNumber++
		trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		entry := mailboxLine{Line: lineNumber}
		if nature == supply.NatureIMAP {
			parseIMAPLine(&entry, trimmed, batchHost)
		} else {
			parseTokenLine(&entry, trimmed)
		}
		out = append(out, entry)
	}
	return out
}

// parseTokenLine reads one four-field line: account, password, application id,
// refresh token.
func parseTokenLine(entry *mailboxLine, trimmed string) {
	fields := strings.Split(trimmed, "----")
	if len(fields) != importedLineFields {
		entry.Err = errMailboxLine("expected 4 fields separated by ----")
		return
	}
	entry.Account = strings.ToLower(strings.TrimSpace(fields[0]))
	entry.Password = strings.TrimSpace(fields[1])
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
}

// parseIMAPLine reads one IMAP line: account, password, and an optional host.
//
// The password is the credential the transport logs in with, so there is no
// application id and no refresh token. The host is required either on the line
// or as the batch's, because a mailbox with no host cannot be opened and
// defaulting to the Microsoft server would send another provider's mailbox to a
// host that never heard of it.
func parseIMAPLine(entry *mailboxLine, trimmed, batchHost string) {
	fields := strings.Split(trimmed, "----")
	if len(fields) < importedIMAPLineFields || len(fields) > importedIMAPLineFields+1 {
		entry.Err = errMailboxLine("expected 2 or 3 fields separated by ----")
		return
	}
	entry.Account = strings.ToLower(strings.TrimSpace(fields[0]))
	entry.Password = strings.TrimSpace(fields[1])
	entry.Host = strings.TrimSpace(batchHost)
	if len(fields) == importedIMAPLineFields+1 {
		entry.Host = strings.TrimSpace(fields[2])
	}
	switch {
	case !strings.Contains(entry.Account, "@"):
		entry.Err = errMailboxLine("the first field is not a mailbox address")
	case entry.Password == "":
		entry.Err = errMailboxLine("the second field (password) is empty")
	case entry.Host == "":
		entry.Err = errMailboxLine("no IMAP host: put it on the line or in the host field")
	case !validIMAPHost(entry.Host):
		// A bare hostname is fine: the reader falls back to 993 and implicit TLS,
		// which is what a mail server on a custom domain usually answers. What it
		// cannot do is invent a port for something that is not a host at all.
		entry.Err = errMailboxLine("the IMAP host is not a server address, for example imap.example.com or imap.example.com:993")
	}
}

// validIMAPHost reports whether host is an address the reader can dial.
//
// A bare hostname is valid: dialSession splits host and port with
// net.SplitHostPort and falls back to 993 with implicit TLS when there is no
// port, which is what a mail server on a custom domain usually answers. What is
// rejected is anything that would reach the dialer as a nonsense address — a URL
// whose colon is not a port separator, a path, or a non-numeric port.
func validIMAPHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, "/\\@ ") {
		return false
	}
	name, port, errSplit := net.SplitHostPort(host)
	if errSplit != nil {
		// No port separator at all: the reader dials it on 993.
		return !strings.Contains(host, ":")
	}
	if name == "" {
		return false
	}
	_, errPort := strconv.Atoi(port)
	return errPort == nil
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

// storeImportedMailbox puts one line's secrets into the store and returns the
// mailbox block that names them.
//
// The returned detail is the failure to report for this line; empty means the
// block is ready to attach. Both transports keep the password under the
// manual-sign-in entry, because that is the value a person typing into the
// mailbox's own web page needs, and one mailbox should not have two answers.
func storeImportedMailbox(vault secretWriter, nature supply.Nature, host string, line mailboxLine) (supply.Mailbox, string) {
	if nature == supply.NatureIMAP {
		// The password is the login itself, so it goes under the entry the IMAP
		// reader looks for; the oauth2 entry would hold nothing this transport
		// ever spends.
		secretName := supply.EmailCredentialName(line.Account)
		if errSet := vault.Set(secretName, line.Password); errSet != nil {
			return supply.Mailbox{}, errSet.Error()
		}
		passwordName := supply.EmailPasswordCredentialName(line.Account)
		if errSet := vault.Set(passwordName, line.Password); errSet != nil {
			return supply.Mailbox{}, errSet.Error()
		}
		return supply.Mailbox{
			Nature:   supply.NatureIMAP,
			Endpoint: line.Host,
			Secret:   secretName,
			Password: passwordName,
		}, ""
	}

	tokenName := supply.EmailOAuth2CredentialName(line.Account)
	if errSet := vault.Set(tokenName, line.Refresh); errSet != nil {
		return supply.Mailbox{}, errSet.Error()
	}
	passwordName := supply.EmailPasswordCredentialName(line.Account)
	if line.Password != "" {
		if errSet := vault.Set(passwordName, line.Password); errSet != nil {
			return supply.Mailbox{}, errSet.Error()
		}
	}
	box := supply.Mailbox{
		Nature:   nature,
		Endpoint: host,
		ClientID: line.ClientID,
		Secret:   tokenName,
	}
	if line.Password != "" {
		box.Password = passwordName
	}
	return box, ""
}

// secretWriter is the part of the secret store this file needs. Naming it keeps
// the store's concrete type out of the signature.
type secretWriter interface {
	Set(name, value string) error
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
