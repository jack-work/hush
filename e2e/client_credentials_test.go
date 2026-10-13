//go:build !windows

package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jack-work/hush/client"
)

// End-to-end for the client_credentials grant, shaped like Tailscale: a
// stable client secret, a one-hour access token, and no refresh token.
//
// The property that matters most is that the client secret stays inside the
// agent. It never expires, so a leak of it is permanent; a leak of what the
// child receives lasts an hour.

const tsClientSecret = "tskey-client-kABC123CNTRL-canary-0123456789"

// tsTokenServer stands in for api.tailscale.com/api/v2/oauth/token.
func tsTokenServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var mints atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		if form.Get("grant_type") != "client_credentials" || form.Get("client_secret") != tsClientSecret {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		n := mints.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"tskey-minted-`+
			string(rune('0'+n))+`","token_type":"Bearer","expires_in":3600,"scope":"devices:read"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &mints
}

func TestClientCredentialsRegisterMintsAndHidesTheSecret(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	srv, mints := tsTokenServer(t)

	// Registration carries only the durable secret and the endpoint: no
	// access token, no expiry. The agent mints the first session itself.
	reg := w.command("oauth", "register", "tailscale",
		"--grant", client.GrantClientCredentials,
		"--token-url", srv.URL,
		"--client-id", "kABC123CNTRL",
		"--scopes", "devices:read",
		"--client-secret", tsClientSecret)
	if out, err := reg.CombinedOutput(); err != nil {
		t.Fatalf("register: %v\n%s", err, out)
	}
	if mints.Load() != 1 {
		t.Errorf("register should mint once, minted %d", mints.Load())
	}

	tok, meta, err := w.client().OAuthGetFull("tailscale")
	if err != nil {
		t.Fatalf("oauth get: %v", err)
	}
	if !strings.HasPrefix(tok, "tskey-minted-") {
		t.Errorf("got %q, want a minted token", tok)
	}
	if tok == tsClientSecret {
		t.Fatal("the agent handed out the client secret itself")
	}
	if meta[client.MetaScope] != "devices:read" {
		t.Errorf("granted scope not surfaced: %v", meta)
	}
}

// The whole point of (b): a command declaring [oauth] receives a minted,
// expiring token — never the client secret.
func TestClientCredentialsReachesChildAsMintedToken(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	srv, _ := tsTokenServer(t)
	if out, err := w.command("oauth", "register", "tailscale",
		"--grant", client.GrantClientCredentials,
		"--token-url", srv.URL,
		"--client-secret", tsClientSecret).CombinedOutput(); err != nil {
		t.Fatalf("register: %v\n%s", err, out)
	}

	dir := filepath.Join(w.base, "config", "hush", "commands", "ts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	spec := "delivery = \"env\"\n\n[oauth]\ntailscale = \"TAILSCALE_API_TOKEN\"\n"
	if err := os.WriteFile(filepath.Join(dir, "command.toml"), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "echo token=$TAILSCALE_API_TOKEN\nenv | grep -c tskey-client- || true\n"
	if err := os.WriteFile(filepath.Join(dir, "command.sh"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := w.command("ts").CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	s := string(out)

	if !strings.Contains(s, "token=tskey-minted-") {
		t.Errorf("child did not receive a minted token:\n%s", s)
	}
	if strings.Contains(s, tsClientSecret) {
		t.Errorf("THE CLIENT SECRET REACHED THE CHILD:\n%s", s)
	}
}

// A wrong secret is a dead credential, not a flaky one: it must fail at
// registration rather than being accepted and retried forever.
func TestClientCredentialsBadSecretFailsAtRegistration(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	srv, _ := tsTokenServer(t)
	out, err := w.command("oauth", "register", "tailscale",
		"--grant", client.GrantClientCredentials,
		"--token-url", srv.URL,
		"--client-secret", "tskey-client-wrong").CombinedOutput()
	if err == nil {
		t.Fatalf("a rejected secret was accepted:\n%s", out)
	}
}

// The agent must advertise the grant, so a stale agent is diagnosable
// rather than mysteriously refusing a valid registration.
func TestAgentAdvertisesClientCredentials(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	ok, err := w.client().SupportsGrant(client.GrantClientCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		grants, _ := w.client().Grants()
		t.Errorf("agent does not advertise client_credentials; has %v", grants)
	}
}
