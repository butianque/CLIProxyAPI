package email

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A Graph message must land in the same shape the IMAP parser produces, because
// everything downstream — address matching, code extraction, the inbox listing —
// is written against that shape and knows nothing about the transport.
func TestGraphMessageReducesToMail(t *testing.T) {
	message := graphMessage{
		Subject:      "Your code is 483920",
		ReceivedTime: "2026-10-18T22:01:09Z",
		From:         &graphRecipient{EmailAddress: graphEmailAddress{Address: "no-reply@service.example"}},
		ToRecipients: []graphRecipient{{EmailAddress: graphEmailAddress{Address: "box@outlook.com"}}},
		// The cc entry repeats the to entry in a different case: a recipient list
		// is a set of addresses, not a count of headers.
		CcRecipients: []graphRecipient{{EmailAddress: graphEmailAddress{Address: "BOX@outlook.com"}}},
		Body:         graphBody{ContentType: "text", Content: "Use 483920 to sign in."},
		Headers: []graphHeader{
			{Name: "X-Original-To", Value: "alias@forward.example"},
			{Name: "Received", Value: "by mx.example with SMTP"},
		},
	}

	mail := message.toMail("Inbox")

	if mail.Mailbox != "Inbox" {
		t.Fatalf("mailbox = %q, want Inbox", mail.Mailbox)
	}
	if mail.From != "no-reply@service.example" {
		t.Fatalf("from = %q", mail.From)
	}
	if len(mail.To) != 2 || mail.To[0] != "box@outlook.com" || mail.To[1] != "alias@forward.example" {
		t.Fatalf("to = %v, want the two distinct addresses", mail.To)
	}
	if mail.Code != "483920" {
		t.Fatalf("code = %q, want 483920", mail.Code)
	}
	if !mail.Date.Equal(time.Date(2026, 10, 18, 22, 1, 9, 0, time.UTC)) {
		t.Fatalf("date = %v", mail.Date)
	}
	// A forward rewrites To and leaves the original recipient in a trace header,
	// so the match has to see the header too.
	if !mail.Mentions("alias@forward.example") {
		t.Fatalf("a forwarded recipient is not matched; haystack = %q", mail.haystack)
	}
	if mail.Mentions("someone-else@example.com") {
		t.Fatalf("an unrelated address matched; haystack = %q", mail.haystack)
	}
}

// Graph answers an HTML body when the preference is ignored, and a code has to
// be readable from it either way.
func TestGraphHTMLBodyIsReducedToText(t *testing.T) {
	message := graphMessage{
		Subject:      "Verification",
		ReceivedTime: "2026-10-18T22:01:09Z",
		Body:         graphBody{ContentType: "html", Content: "<p>Your code is <b>778899</b></p>"},
	}

	mail := message.toMail("Inbox")

	if strings.Contains(mail.Text, "<") {
		t.Fatalf("html survived as markup: %q", mail.Text)
	}
	if mail.Code != "778899" {
		t.Fatalf("code = %q, want 778899", mail.Code)
	}
}

// Graph accepts a well-known folder name in the path and nothing else: any other
// folder has to be resolved to its id, which is what the cached listing is for.
func TestGraphFolderTargetResolution(t *testing.T) {
	session := &graphSession{folders: map[string]string{"receipts 2026": "AAMk-receipts"}}
	cases := []struct {
		folder string
		want   string
	}{
		{"INBOX", "inbox"},
		{"Inbox", "inbox"},
		{"Junk Email", "junkemail"},
		{"", "inbox"},
		{"Receipts 2026", "AAMk-receipts"},
	}
	for _, testCase := range cases {
		got, errTarget := session.folderTarget(context.Background(), testCase.folder)
		if errTarget != nil {
			t.Fatalf("folderTarget(%q): %v", testCase.folder, errTarget)
		}
		if got != testCase.want {
			t.Errorf("folderTarget(%q) = %q, want %q", testCase.folder, got, testCase.want)
		}
	}

	if _, errTarget := session.folderTarget(context.Background(), "no such folder"); errTarget == nil {
		t.Fatal("an unknown folder resolved to something")
	}
}
