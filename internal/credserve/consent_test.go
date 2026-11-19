//go:build linux

package credserve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// boxPrincipal holds copilot-work by config; anything else must come from a consent grant.
const boxPrincipal = `
[principals.box]
users = ["me"]
credentials = ["copilot-work"]
`

// grantRow is a consent grant for box (or another principal) that is live for an hour,
// or expired when ttl is negative.
func grantRow(principal, credential string, ttl time.Duration) ConsentGrant {
	return ConsentGrant{ID: "g-" + principal + "-" + credential, Principal: principal, Credential: credential,
		ExpiresAt: float64(time.Now().Add(ttl).Unix()), ApprovedBy: "boss"}
}

// grantsFile is a fixture: the grants file's raw bytes (nil = no file).
func grantsFile(rows ...ConsentGrant) []byte {
	b, _ := json.Marshal(map[string]any{"grants": rows})
	return b
}

// consentFile is a temp consent grants file: its path, and put, which replaces
// it atomically (nil removes it). The file may change while serving; the
// config may not, so point a rig at path with withConsent.
func consentFile(t *testing.T) (string, func([]byte)) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grants.json")
	return path, func(raw []byte) {
		t.Helper()
		if raw == nil {
			_ = os.Remove(path)
			return
		}
		if err := os.WriteFile(path+".tmp", raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			t.Fatal(err)
		}
	}
}

func withConsent(path string) func(*rig) { return func(r *rig) { r.cfg.ConsentGrants = path } }

// oversized is a valid grants file one byte past the read bound.
func oversized(row ConsentGrant) []byte {
	pad := ConsentGrant{ID: "pad"}
	raw := grantsFile(row, pad)
	pad.ApprovedBy = strings.Repeat("x", maxConsentFile+1-len(raw))
	return grantsFile(row, pad)
}

// consentRig serves boxPrincipal with consent grants read from a temp file; before
// runs after the consent setting, before serving.
func consentRig(t *testing.T, before ...func(*rig)) (*prig, func([]byte)) {
	t.Helper()
	path, put := consentFile(t)
	return newPrincipalRig(t, "", boxPrincipal, append([]func(*rig){withConsent(path)}, before...)...), put
}

func TestConsentGrants(t *testing.T) {
	for _, c := range []struct {
		name    string
		file    []byte
		cred    string
		setup   func(*rig)
		status  int
		errCode string
		token   string
		used    bool   // a consent-grant use line is logged
		logs    string // and this text too
	}{
		{name: "live grant serves and is audited", file: grantsFile(grantRow("box", instName, time.Hour)),
			status: 200, token: "at-seed", used: true, logs: fmt.Sprintf(`cred: consent-grant use "g-box-%s" principal=box credential=%s`, instName, instName)},
		{name: "expired grant", file: grantsFile(grantRow("box", instName, -time.Second)), status: 403, errCode: "not_granted"},
		{name: "grant for another principal", file: grantsFile(grantRow("someone-else", instName, time.Hour)), status: 403, errCode: "not_granted"},
		{name: "grant for another credential", file: grantsFile(grantRow("box", "something-else", time.Hour)), status: 403, errCode: "not_granted"},
		{name: "empty file", file: grantsFile(), status: 403, errCode: "not_granted"},
		{name: "no file", file: nil, status: 403, errCode: "not_granted", logs: "consent grants unreadable"},
		{name: "oversized file, live grant inside", file: oversized(grantRow("box", instName, time.Hour)), status: 403, errCode: "not_granted", logs: "larger than"},
		{name: "malformed file", file: []byte(`{"grants": [`), status: 403, errCode: "not_granted", logs: "consent grants unreadable"},
		{name: "past expires_at by the clock, row still in the file", file: grantsFile(grantRow("box", instName, time.Hour)),
			setup: func(r *rig) { r.srv.Now = func() time.Time { return time.Now().Add(2 * time.Hour) } }, status: 403, errCode: "not_granted"},
		{name: "consent grants off ignores the file", file: grantsFile(grantRow("box", instName, time.Hour)),
			setup: func(r *rig) { r.cfg.ConsentGrants = "" }, status: 403, errCode: "not_granted"},
		{name: "grant for a name that is no instance", file: grantsFile(grantRow("box", "not-an-instance", time.Hour)),
			cred: "not-an-instance", status: 404, errCode: "unknown_credential", used: true},
		// copilot-work is granted by config and not signed in: past the grant check, not a consent use.
		{name: "static grant is not a consent use", file: grantsFile(), cred: "copilot-work", status: 503, errCode: "credential_stale"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var before []func(*rig)
			if c.setup != nil {
				before = append(before, c.setup)
			}
			p, put := consentRig(t, before...)
			put(c.file)
			cred := c.cred
			if cred == "" {
				cred = instName
			}
			a := p.request("box", http.MethodGet, "/cred/"+cred)
			if a.status != c.status || a.Error != c.errCode || a.Token != c.token {
				t.Fatalf("got %d %q", a.status, a.raw)
			}
			logs := p.logs.String()
			if strings.Contains(logs, "consent-grant use") != c.used || !strings.Contains(logs, c.logs) {
				t.Fatalf("logs (want use=%v, %q): %q", c.used, c.logs, logs)
			}
			if strings.Contains(logs, "at-seed") {
				t.Fatalf("a token reached the log: %q", logs)
			}
		})
	}
}

// The file is read at every use: no restart between a grant appearing and expiring.
func TestConsentGrantsAreReadAtEveryUse(t *testing.T) {
	p, put := consentRig(t)
	for _, step := range []struct {
		file   []byte
		status int
	}{
		{nil, 403},
		{grantsFile(grantRow("box", instName, time.Hour)), 200},
		{grantsFile(grantRow("box", instName, -time.Minute)), 403},
	} {
		put(step.file)
		if a := p.request("box", http.MethodGet, "/cred/"+instName); a.status != step.status {
			t.Fatalf("file %s: got %d %q, want %d", step.file, a.status, a.raw, step.status)
		}
	}
}

func TestConsentGrantsConfig(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ consent, wantErr string }{
		{"/var/lib/grants/grants.json", ""},
		{"", "credentials is required"},
		{"grants.json", "absolute path"},
	} {
		head := fmt.Sprintf("recipient = %q\n", key.Recipient().String())
		if c.consent != "" {
			head += fmt.Sprintf("consent_grants = %q\n", c.consent)
		}
		_, err := ParseConfig([]byte(head + `
[instances.copilot-work]
kind = "copilot"
device_url = "https://github.example/login/device/code"
github_token_url = "https://github.example/login/oauth/access_token"
token_url = "https://api.github.example/copilot_internal/v2/token"
client_id = "Iv1.x"

[principals.box]
users = ["me"]
`))
		if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Fatalf("consent_grants %q: got %v, want %q", c.consent, err, c.wantErr)
		}
	}
}
