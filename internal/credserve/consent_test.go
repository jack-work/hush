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

func writeGrants(t *testing.T, path string, rows ...ConsentGrant) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"grants": rows})
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func consentRig(t *testing.T) (*prig, string) {
	t.Helper()
	p := newPrincipalRig(t, "", boxPrincipal)
	path := filepath.Join(t.TempDir(), "grants.json")
	p.cfg.ConsentGrants = path
	return p, path
}

func live(principal, credential string) ConsentGrant {
	return ConsentGrant{ID: "g-" + principal + "-" + credential, Principal: principal, Credential: credential,
		ExpiresAt: float64(time.Now().Add(time.Hour).Unix()), ApprovedBy: "boss"}
}

func TestConsentGrantServesALiveGrantAndAuditsIt(t *testing.T) {
	p, path := consentRig(t)
	writeGrants(t, path, live("box", instName))
	a := p.request("box", http.MethodGet, "/cred/"+instName)
	if a.status != 200 || a.Token != "at-seed" {
		t.Fatalf("live consent grant: got %d %q", a.status, a.raw)
	}
	logs := p.logs.String()
	want := fmt.Sprintf(`cred: consent-grant use "g-box-%s" principal=box credential=%s`, instName, instName)
	if !strings.Contains(logs, want) || !strings.Contains(logs, `approved_by="boss"`) || !strings.Contains(logs, "-> 200") {
		t.Fatalf("no consent-grant audit line: %q", logs)
	}
	if strings.Contains(logs, "at-seed") {
		t.Fatalf("a token reached the log: %q", logs)
	}
}

func TestConsentGrantRefusals(t *testing.T) {
	expired := live("box", instName)
	expired.ExpiresAt = float64(time.Now().Add(-time.Second).Unix())
	for _, c := range []struct {
		name string
		rows []ConsentGrant
	}{
		{"expired", []ConsentGrant{expired}},
		{"other principal", []ConsentGrant{live("someone-else", instName)}},
		{"other credential", []ConsentGrant{live("box", "something-else")}},
		{"empty file", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, path := consentRig(t)
			writeGrants(t, path, c.rows...)
			a := p.request("box", http.MethodGet, "/cred/"+instName)
			if a.status != http.StatusForbidden || a.Error != "not_granted" || a.Token != "" {
				t.Fatalf("got %d %q, want 403 not_granted", a.status, a.raw)
			}
			if strings.Contains(p.logs.String(), "consent-grant use") {
				t.Fatalf("a refused request was logged as a grant use: %q", p.logs.String())
			}
		})
	}
}

func TestConsentGrantsAreReadAtEveryUse(t *testing.T) {
	p, path := consentRig(t)
	if a := p.request("box", http.MethodGet, "/cred/"+instName); a.status != http.StatusForbidden {
		t.Fatalf("no grants file: got %d %q", a.status, a.raw)
	}
	writeGrants(t, path, live("box", instName))
	if a := p.request("box", http.MethodGet, "/cred/"+instName); a.status != 200 || a.Token != "at-seed" {
		t.Fatalf("grant written after start: got %d %q", a.status, a.raw)
	}
	g := live("box", instName)
	g.ExpiresAt = float64(time.Now().Add(-time.Minute).Unix())
	writeGrants(t, path, g)
	if a := p.request("box", http.MethodGet, "/cred/"+instName); a.status != http.StatusForbidden || a.Token != "" {
		t.Fatalf("grant expired in the file: got %d %q", a.status, a.raw)
	}
}

func TestConsentGrantExpiresByTheClockNotTheFile(t *testing.T) {
	p, path := consentRig(t)
	writeGrants(t, path, live("box", instName))
	p.srv.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if a := p.request("box", http.MethodGet, "/cred/"+instName); a.status != http.StatusForbidden {
		t.Fatalf("a grant past expires_at still in the file: got %d %q", a.status, a.raw)
	}
}

func TestUnreadableConsentGrantsGrantNothing(t *testing.T) {
	p, path := consentRig(t)
	if err := os.WriteFile(path, []byte(`{"grants": [`), 0o644); err != nil {
		t.Fatal(err)
	}
	if a := p.request("box", http.MethodGet, "/cred/"+instName); a.status != http.StatusForbidden {
		t.Fatalf("malformed grants file: got %d %q", a.status, a.raw)
	}
	if !strings.Contains(p.logs.String(), "consent grants unreadable") {
		t.Fatalf("no log of the unreadable file: %q", p.logs.String())
	}
}

func TestConsentGrantsOffIgnoresTheFile(t *testing.T) {
	p, path := consentRig(t)
	writeGrants(t, path, live("box", instName))
	p.cfg.ConsentGrants = ""
	if a := p.request("box", http.MethodGet, "/cred/"+instName); a.status != http.StatusForbidden {
		t.Fatalf("consent_grants unset: got %d %q", a.status, a.raw)
	}
}

func TestConsentGrantForANonInstanceIsUnknown(t *testing.T) {
	p, path := consentRig(t)
	writeGrants(t, path, live("box", "tomb-live-notes"))
	a := p.request("box", http.MethodGet, "/cred/tomb-live-notes")
	if a.status != http.StatusNotFound || a.Error != "unknown_credential" {
		t.Fatalf("grant for a name that is no instance: got %d %q", a.status, a.raw)
	}
}

func TestStaticGrantStillServesWithConsentOn(t *testing.T) {
	p, path := consentRig(t)
	writeGrants(t, path)
	// copilot-work is granted by config; with no sign-in it is not a 403.
	if a := p.request("box", http.MethodGet, "/cred/copilot-work"); a.status == http.StatusForbidden {
		t.Fatalf("static grant refused: got %d %q", a.status, a.raw)
	}
	if strings.Contains(p.logs.String(), "consent-grant use") {
		t.Fatalf("a static grant was logged as a consent grant use: %q", p.logs.String())
	}
}

func TestConsentGrantsConfig(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cfg := func(consent string) string {
		s := fmt.Sprintf("recipient = %q\n", key.Recipient().String())
		if consent != "" {
			s += fmt.Sprintf("consent_grants = %q\n", consent)
		}
		return s + `
[instances.copilot-work]
kind = "copilot"
device_url = "https://github.example/login/device/code"
github_token_url = "https://github.example/login/oauth/access_token"
token_url = "https://api.github.example/copilot_internal/v2/token"
client_id = "Iv1.x"

[principals.box]
users = ["me"]
`
	}
	if _, err := ParseConfig([]byte(cfg("/var/lib/grants/grants.json"))); err != nil {
		t.Fatalf("a consent-only principal with consent_grants: %v", err)
	}
	if _, err := ParseConfig([]byte(cfg(""))); err == nil || !strings.Contains(err.Error(), "credentials is required") {
		t.Fatalf("a principal with nothing and no consent_grants: got %v", err)
	}
	if _, err := ParseConfig([]byte(cfg("grants.json"))); err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("a relative consent_grants: got %v", err)
	}
}
