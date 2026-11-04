package oauth

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	descriptionMax = 120
	redacted       = "[redacted]"
	refusedReason  = "refresh refused"
)

var (
	errorCodeRE   = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)
	tokenRunRE    = regexp.MustCompile(`[A-Za-z0-9._~+/=\-]{32,}`)
	quotedErrorRE = regexp.MustCompile(`"error"\s*:\s*"([A-Za-z0-9_.\-]{1,64})"`)
)

func endpointDetail(body []byte, secrets ...string) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) != nil || !errorCodeRE.MatchString(e.Error) {
		return fmt.Sprintf("body of %d bytes", len(body))
	}
	detail := e.Error
	if d := cleanDescription(e.Description); d != "" {
		detail += ": " + d
	}
	return redact(detail, secrets...)
}

func cleanDescription(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if !reasonChar(r) {
			space = true
			continue
		}
		if r == ' ' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) > descriptionMax {
		out = out[:descriptionMax] + "..."
	}
	return out
}

func redact(s string, secrets ...string) string {
	for _, secret := range secrets {
		if len(secret) >= 8 {
			s = strings.ReplaceAll(s, secret, redacted)
		}
	}
	return tokenRunRE.ReplaceAllString(s, redacted)
}

func scrubReason(reason string, secrets ...string) string {
	if reason == "" || isCleanReason(reason) {
		return redact(reason, secrets...)
	}
	if m := quotedErrorRE.FindStringSubmatch(reason); m != nil {
		return m[1]
	}
	return refusedReason
}

func isCleanReason(reason string) bool {
	if len(reason) > reloginReasonMax {
		return false
	}
	for _, r := range reason {
		if !reasonChar(r) {
			return false
		}
	}
	return true
}

func reasonChar(r rune) bool {
	return r >= 0x20 && r <= 0x7e && !strings.ContainsRune(`"\{}<>&=`, r)
}
