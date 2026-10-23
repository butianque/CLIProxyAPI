// Package supply is the host-side account-supply layer: it hands out a
// receivable identity (a phone number or an email address), reads the message
// that identity receives, and keeps a record of which account each identity
// registered. Both supply kinds share this contract; only the implementation
// behind it differs.
//
// It lives in internal/ because it is a host capability, not a plugin
// extension point: plugins reach it through the host.supply.* ABI callbacks
// (mirroring host.secret.*), so they never import this package. That is why
// the protocol implementations can stay private while still being usable from
// any plugin.
package supply

import (
	"context"
	"errors"
	"strings"
)

// ErrUnknownIdentity reports that a caller asked to re-occupy an exact identity
// that this supply service never handed out. It is distinct from a rental
// failure because the caller's right answer is usually to fall back to a manual
// path, not to retry.
var ErrUnknownIdentity = errors.New("supply: identity was not handed out by this service")

// Kind distinguishes the two supply categories. The wire contract (the ABI)
// is shared; the difference is which identity is produced and where its
// message comes from.
type Kind string

const (
	// KindPhone rents a phone number and reads an SMS code.
	KindPhone Kind = "phone"
	// KindEmail hands out an email address and reads a verification mail.
	KindEmail Kind = "email"
)

// Valid reports whether k is a known supply kind.
func (k Kind) Valid() bool {
	return k == KindPhone || k == KindEmail
}

// Identity is one handed-out identity. For a phone kind Address is the number;
// for an email kind it is the address. The other fields are best-effort and
// vary by kind.
type Identity struct {
	Kind Kind `json:"kind"`
	// Address is the number or the email address.
	Address string `json:"address"`
	// Price is the per-rental cost in CNY. Email sources are usually free.
	Price float64 `json:"price,omitempty"`
	// Code is the source's own channel/domain handle, when it reports one.
	Code string `json:"code,omitempty"`
	// Carrier is the phone operator, when known.
	Carrier string `json:"carrier,omitempty"`
	// Region is the phone number's attributed region or the email domain.
	Region string `json:"region,omitempty"`
}

// Message is one read of an identity's inbox. A phone inbox holds at most one
// code; an email inbox can hold several mails, of which Code is the extracted
// verification code when one was recognised.
type Message struct {
	// Ready reports whether a message has arrived.
	Ready bool `json:"ready"`
	// Code is the extracted verification code, when one was found.
	Code string `json:"code,omitempty"`
	// Text is the full message body (or the most relevant mail's body).
	Text string `json:"text,omitempty"`
	// Subject is the mail subject for the email kind; empty for phone.
	Subject string `json:"subject,omitempty"`
	// From is the mail sender for the email kind; empty for phone.
	From string `json:"from,omitempty"`
}

// Status describes the supply service to callers that only need to know
// whether it is usable and which kinds are configured. It never carries a
// credential value.
type Status struct {
	// Enabled reports whether any supply kind is configured.
	Enabled bool `json:"enabled"`
	// Kinds lists the configured kinds.
	Kinds []Kind `json:"kinds,omitempty"`
	// Locked reports that the host secret store is unavailable, so credentials
	// cannot be resolved. Callers must treat this as "unknown", not "absent".
	Locked bool `json:"locked,omitempty"`
}

// GrabOptions carries a request's identity preferences. Zero values mean
// "whatever the source prefers", which is the normal case.
type GrabOptions struct {
	// Purpose names the upstream service the identity is rented for (the
	// platform's project id for phone; empty for email).
	Purpose string `json:"purpose,omitempty"`
	// UID addresses one specific source channel (a phone channel id or an
	// email domain). Empty lets the implementation choose.
	UID string `json:"uid,omitempty"`
	// Address re-occupies one exact identity, which is how a later
	// re-authentication gets back onto a registered number or address.
	Address string `json:"address,omitempty"`
	// Usage narrows the handout to one kind of source: "personal" for an
	// address that exists on its own (a bought mailbox), "self-domain" for an
	// alias of a domain the service operates (a catch-all). Empty accepts both,
	// which is what a caller that only needs "an address" wants.
	Usage string `json:"usage,omitempty"`
}

// AddressDomain returns the domain part of a mail address, lowercased, or "" when
// the value carries none.
//
// It is the namespace an address receives in, and it is the one grouping that
// holds for every email identity: a bought mailbox (name@outlook.com) and a
// catch-all alias (name@example.com) are the same shape — one address that
// forwards somewhere — so the domain is what tells a reader where it receives.
// The part before it is the identity; the domain is never an identity of its own.
func AddressDomain(address string) string {
	trimmed := strings.TrimSpace(address)
	at := strings.LastIndex(trimmed, "@")
	if at < 0 || at == len(trimmed)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(trimmed[at+1:]))
}

// Supply is the host's account-supply service. One instance serves every
// caller; implementations must be safe for concurrent use, because several
// accounts can be registering at once.
type Supply interface {
	// Status reports whether the service is usable and which kinds exist.
	Status(ctx context.Context) (Status, error)
	// Grab hands out one identity of the requested kind.
	Grab(ctx context.Context, kind Kind, opts GrabOptions) (Identity, error)
	// Read reads one identity's inbox once. It is the ordinary polling call,
	// so "no message yet" is not an error: it is reported as Ready=false.
	Read(ctx context.Context, kind Kind, purpose, address string) (Message, error)
	// Link associates an identity with the platform and the account it
	// registered. Providers without a pool may treat it as a no-op.
	Link(ctx context.Context, kind Kind, address, target, account, authIndex string) error
	// Release returns an identity to its source. For kinds without a pool
	// (email domains, IMAP mailboxes) it is a no-op.
	Release(ctx context.Context, kind Kind, address, outcome string) error
}
