package pluginapi

import (
	"regexp"
	"strings"
)

// This file is the one implementation of "text a plugin wants a human to read".
//
// A plugin reads free-form text from an upstream provider and hands it to the
// host, which shows it to an operator. That text is not trusted: an upstream
// error body can quote the credential that failed, and a provider that echoes a
// request URL can carry its userinfo. The host cannot tell which substring is a
// secret, so the rule has to live where both sides can reach it — in the
// contract package the plugins already import.
//
// Redaction is deliberately coarse. It prefers losing a harmless word to
// printing a live token: an operator reading "API Key [REDACTED]" still learns
// what failed, while a leaked key cannot be un-leaked.

const (
	// userTextRuneLimit bounds user-visible text. A row in a panel has room for
	// a sentence, not for a provider's whole error page.
	userTextRuneLimit = 300
)

var (
	// sensitiveUserTextPattern matches a credential name followed by its value,
	// in the several shapes providers use: key=value, key: value, and quoted.
	sensitiveUserTextPattern = regexp.MustCompile(`(?i)(["']?(?:access[\s_-]*token|refresh[\s_-]*token|id[\s_-]*token|api[\s_-]*key|client[\s_-]*secret|private[\s_-]*key|proxy[\s_-]*authorization|authorization|password|credential|token|secret)["']?\s*[:=]\s*)(?:(?:bearer|basic)\s+[^\s,;]+|"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;&}\]]+)`)
	// authorizationUserTextPattern matches a bare scheme plus credential, where
	// no parameter name precedes the value.
	authorizationUserTextPattern = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[^\s,;]+`)
	// urlUserinfoUserTextPattern matches the userinfo segment of a URL.
	urlUserinfoUserTextPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@`)
)

// RedactUserText collapses runs of whitespace into single spaces and replaces
// credential-shaped values and URL userinfo with a marker. It does not bound the
// length; use SafeUserText when the result is shown to a human.
func RedactUserText(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return ""
	}
	text = urlUserinfoUserTextPattern.ReplaceAllString(text, `${1}[REDACTED]@`)
	text = sensitiveUserTextPattern.ReplaceAllString(text, `${1}"[REDACTED]"`)
	text = authorizationUserTextPattern.ReplaceAllString(text, `${1} [REDACTED]`)
	return text
}

// SafeUserText returns text that is safe to show to an operator: single line,
// credential values redacted, and bounded to a readable length. A plugin that
// puts provider-authored text into a user-visible contract field (a bucket
// description, a failure reason) must pass it through here first.
func SafeUserText(text string) string {
	redacted := RedactUserText(text)
	runes := []rune(redacted)
	if len(runes) <= userTextRuneLimit {
		return redacted
	}
	return string(runes[:userTextRuneLimit]) + "..."
}
