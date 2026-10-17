package email

import (
	"regexp"
	"strings"
)

// Verification codes are extracted by pattern, not by "the first number in the
// message": a body is full of numbers that are not codes (years, prices, order
// ids, tracking numbers), and handing one of those back as the code is worse
// than returning nothing, because the caller cannot tell the difference.
//
// So every pattern requires a keyword next to the value. The keyword may come
// before the value ("your code is 123456", "验证码：123456") or after it
// ("123456 is your verification code").
type codePattern struct {
	pattern *regexp.Regexp
	// needsDigit marks the alphanumeric rule: a token made only of letters is a
	// word, not a code. Go's regexp has no lookahead, so the digit is checked
	// after the match instead.
	needsDigit bool
}

var codePatterns = []codePattern{
	// The value follows its label.
	{pattern: regexp.MustCompile(`(?i)(?:code|passcode|otp|pin|verification|verify|confirm|` +
		`验证码|校验码|确认码|动态码|驗證碼|確認碼|動態碼)[^0-9]{0,24}([0-9]{4,8})`)},
	// The value precedes its label.
	{pattern: regexp.MustCompile(`(?i)([0-9]{4,8})[^0-9]{0,16}(?:is|as)?[^0-9]{0,8}` +
		`(?:your|the)?[^0-9]{0,8}(?:code|otp|pin|verification|验证码|驗證碼)`)},
	// An alphanumeric code is only accepted beside a keyword, and only when it
	// carries at least one digit.
	{pattern: regexp.MustCompile(`(?i)(?:code|passcode|otp|verification|` +
		`验证码|校验码|确认码|驗證碼|確認碼)[^A-Z0-9]{0,24}([A-Z0-9]{5,8})`), needsDigit: true},
}

// ExtractCode returns the verification code a message states, or "" when the
// message does not state one.
//
// The subject is tried first: senders that put the code in the subject are
// telling you it is the code, and that is a stronger signal than anything the
// body can offer.
func ExtractCode(subject, body string) string {
	for _, text := range []string{subject, body} {
		if text == "" {
			continue
		}
		for _, candidate := range codePatterns {
			for _, match := range candidate.pattern.FindAllStringSubmatch(text, 8) {
				if len(match) < 2 || match[1] == "" {
					continue
				}
				if candidate.needsDigit && !strings.ContainsAny(match[1], "0123456789") {
					continue
				}
				return match[1]
			}
		}
	}
	return ""
}
