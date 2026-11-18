//go:build linux

package credserve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/jack-work/hush/internal/oauth"
)

// prig serves one config on a socket per principal, plus the allow_user
// socket when the config has allow_user.
type prig struct {
	*rig
	clients map[string]*http.Client
}

const otherUID = 4242

func lookupForTest(name string) (uint32, error) {
	switch name {
	case "me":
		return uint32(os.Getuid()), nil
	case "other":
		return otherUID, nil
	}
	return 0, fmt.Errorf("no user %s", name)
}

func principalConfig(t *testing.T, key *age.X25519Identity, tokenURL, allow, extra string) *Config {
	t.Helper()
	head := fmt.Sprintf("recipient = %q\n", key.Recipient().String())
	if allow != "" {
		head += fmt.Sprintf("allow_user = %q\n", allow)
	}
	cfg, err := ParseConfig([]byte(head + fmt.Sprintf(`
[instances.%s]
kind = "anthropic"
authorize_url = "https://claude.example/oauth/authorize"
token_url = %q
redirect_uri = "https://console.example/oauth/code/callback"
client_id = "client-1"
scopes = "user:inference"
audit = true

[instances.copilot-work]
kind = "copilot"
device_url = "https://github.example/login/device/code"
github_token_url = "https://github.example/login/oauth/access_token"
token_url = "https://api.github.example/copilot_internal/v2/token"
client_id = "Iv1.x"
`, instName, tokenURL) + extra))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newPrincipalRig(t *testing.T, allow, extra string) *prig {
	t.Helper()
	ep := newEndpoint(t)
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, ep: ep, key: key, stateDir: t.TempDir(), logs: &syncBuffer{}}
	r.cfg = principalConfig(t, key, ep.srv.URL+"/v1/oauth/token", allow, extra)
	seeder := oauth.NewManager(r.stateDir, nil, key.Recipient(), log.New(io.Discard, "", 0))
	if err := seeder.Register(r.cfg.Instances[instName].OAuthConfig(instName), seedTokens(3600)); err != nil {
		t.Fatal(err)
	}
	seeder.Stop()

	r.mgr = oauth.NewManager(r.stateDir, []age.Identity{key}, key.Recipient(), log.New(r.logs, "", 0))
	r.mgr.SetHTTPClient(FencedClient(r.cfg.EgressHosts(), ep.roots()))
	if err := r.mgr.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.mgr.Stop() })
	var allowUID uint32
	if allow != "" {
		allowUID, _ = lookupForTest(allow)
	}
	r.srv = NewServer(r.cfg, r.mgr, allowUID, log.New(r.logs, "", 0))
	ps, err := ResolvePrincipals(r.cfg, lookupForTest)
	if err != nil {
		t.Fatal(err)
	}
	r.srv.SetPrincipals(ps, allow != "")

	dir, err := os.MkdirTemp("", "credsock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	hs := r.srv.HTTPServer()
	t.Cleanup(func() { hs.Close() })
	p := &prig{rig: r, clients: map[string]*http.Client{}}
	listen := func(label string, wrap func(net.Listener) net.Listener) {
		sock := filepath.Join(dir, label+".sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		go hs.Serve(wrap(ln))
		p.clients[label] = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		}}
	}
	for name := range r.cfg.Principals {
		name := name
		listen(name, func(ln net.Listener) net.Listener { return PrincipalListener(ln, name) })
	}
	listen("legacy", func(ln net.Listener) net.Listener { return ln })
	return p
}

func (p *prig) request(socket, method, path string) answer {
	p.t.Helper()
	req, _ := http.NewRequest(method, "http://minter"+path, nil)
	res, err := p.clients[socket].Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	a := answer{status: res.StatusCode, raw: string(body)}
	if err := json.Unmarshal(body, &a); err != nil {
		p.t.Fatalf("answer %d is not JSON: %q", res.StatusCode, body)
	}
	return a
}

const twoPrincipals = `
[principals.rou2]
users = ["me"]
credentials = ["anthropic-work"]

[principals.keel]
users = ["other"]
credentials = ["anthropic-work", "copilot-work"]
`

func TestPrincipalServesItsGrantedCredential(t *testing.T) {
	p := newPrincipalRig(t, "", twoPrincipals)
	a := p.request("rou2", http.MethodGet, "/cred/"+instName)
	if a.status != 200 || a.Token != "at-seed" {
		t.Fatalf("granted credential: got %d %q", a.status, a.raw)
	}
}

func TestPrincipalRefusesAnUngrantedCredentialWithoutSayingWhetherItExists(t *testing.T) {
	p := newPrincipalRig(t, "", twoPrincipals)
	for _, name := range []string{"copilot-work", "no-such-credential"} {
		a := p.request("rou2", http.MethodGet, "/cred/"+name)
		if a.status != http.StatusForbidden || a.Error != "not_granted" {
			t.Fatalf("%s: got %d %q, want 403 not_granted", name, a.status, a.raw)
		}
	}
	if !strings.Contains(p.logs.String(), "REFUSED copilot-work for principal rou2") {
		t.Fatalf("no refusal logged: %q", p.logs.String())
	}
}

func TestPrincipalRefusesAPeerNotInItsUsers(t *testing.T) {
	p := newPrincipalRig(t, "", twoPrincipals)
	a := p.request("keel", http.MethodGet, "/cred/"+instName)
	if a.status != http.StatusForbidden || a.Error != "forbidden" || a.Token != "" {
		t.Fatalf("got %d %q, want 403 forbidden", a.status, a.raw)
	}
}

func TestPrincipalSocketServesCredOnly(t *testing.T) {
	p := newPrincipalRig(t, "", twoPrincipals)
	for _, c := range [][2]string{{http.MethodPost, "/refresh/" + instName}, {http.MethodPost, "/cred/" + instName}, {http.MethodGet, "/status"}, {http.MethodGet, "/other"}} {
		if a := p.request("rou2", c[0], c[1]); a.status != http.StatusNotFound || a.Error != principalOnlyCred {
			t.Fatalf("%s %s on a principal socket: got %d %q", c[0], c[1], a.status, a.raw)
		}
	}
}

func TestNoAllowUserMeansAnUntaggedSocketIsRefused(t *testing.T) {
	p := newPrincipalRig(t, "", twoPrincipals)
	if a := p.request("legacy", http.MethodGet, "/cred/"+instName); a.status != http.StatusForbidden {
		t.Fatalf("untagged socket without allow_user: got %d %q", a.status, a.raw)
	}
	// Even a peer whose uid equals the server's zero-value allow uid: the
	// untagged socket is off, not merely matched against uid 0.
	p = newPrincipalRig(t, "me", twoPrincipals)
	p.srv.SetPrincipals(p.srv.principals, false)
	a := p.request("legacy", http.MethodGet, "/cred/"+instName)
	if a.status != http.StatusForbidden || a.Token != "" {
		t.Fatalf("untagged socket without allow_user: got %d %q", a.status, a.raw)
	}
}

func TestAllowUserSocketStillServesEverythingBesidePrincipals(t *testing.T) {
	p := newPrincipalRig(t, "me", twoPrincipals)
	a := p.request("legacy", http.MethodGet, "/cred/"+instName)
	if a.status != 200 || a.Token != "at-seed" {
		t.Fatalf("allow_user socket: got %d %q", a.status, a.raw)
	}
	if a := p.request("rou2", http.MethodGet, "/cred/copilot-work"); a.status != http.StatusForbidden {
		t.Fatalf("the principal socket must keep its own grants: got %d %q", a.status, a.raw)
	}
}

func TestAuditLinePerRequestNeverTheToken(t *testing.T) {
	p := newPrincipalRig(t, "me", twoPrincipals)
	p.request("rou2", http.MethodGet, "/cred/"+instName)
	p.request("keel", http.MethodGet, "/cred/"+instName)
	p.request("legacy", http.MethodGet, "/cred/"+instName)
	logs := p.logs.String()
	uid := os.Getuid()
	for _, want := range []string{
		fmt.Sprintf("cred: audit %s principal=rou2 uid=%d -> 200", instName, uid),
		fmt.Sprintf("cred: audit %s principal=keel uid=%d -> 403", instName, uid),
		fmt.Sprintf("cred: audit %s principal=owner uid=%d -> 200", instName, uid),
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("missing %q in %q", want, logs)
		}
	}
	if strings.Contains(logs, "at-seed") {
		t.Fatalf("a token reached the log: %q", logs)
	}
	p.request("rou2", http.MethodGet, "/cred/copilot-work")
	if strings.Contains(p.logs.String(), "cred: audit copilot-work") {
		t.Fatal("an instance without audit = true was audited")
	}
}

func TestPrincipalConfigValidation(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	base := fmt.Sprintf("recipient = %q\n", key.Recipient().String())
	inst := `
[instances.a]
kind = "copilot"
device_url = "https://github.example/login/device/code"
github_token_url = "https://github.example/login/oauth/access_token"
token_url = "https://api.github.example/copilot_internal/v2/token"
client_id = "Iv1.x"
`
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"neither":        {inst, "allow_user or at least one [principals] entry"},
		"no users":       {inst + "[principals.p]\ncredentials = [\"a\"]\n", "users is required"},
		"unknown cred":   {inst + "[principals.p]\nusers = [\"x\"]\ncredentials = [\"b\"]\n", `credential "b" is not an instance`},
		"relative sock":  {inst + "[principals.p]\nusers = [\"x\"]\ncredentials = [\"a\"]\nsocket = \"p.sock\"\n", "not an absolute path"},
		"bad name":       {inst + "[principals.P]\nusers = [\"x\"]\ncredentials = [\"a\"]\n", "principal name"},
		"no credentials": {inst + "[principals.p]\nusers = [\"x\"]\n", "credentials is required"},
	} {
		_, err := ParseConfig([]byte(base + tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	if _, err := ParseConfig([]byte(base + inst + "[principals.p]\nusers = [\"x\"]\ncredentials = [\"a\"]\nsocket = \"/run/band-cred/p.sock\"\n")); err != nil {
		t.Fatalf("a principal-only config must parse: %v", err)
	}
	if _, err := ParseConfig([]byte(base + inst + "[principals.p]\nusers = [\"x\"]\nrefresh = true\nsocket = \"/run/band-cred/p.sock\"\n")); err != nil {
		t.Fatalf("a refresh-only principal must parse: %v", err)
	}
}

func TestRefreshPrincipalGetsStatusNeverAToken(t *testing.T) {
	p := newPrincipalRig(t, "", `
[principals.drop]
users = ["me"]
login = true
refresh = true
`)
	a := p.request("drop", http.MethodPost, "/refresh/"+instName)
	if a.status != 200 || strings.TrimSpace(a.raw) != `{"ready":true,"refreshed":true}` {
		t.Fatalf("refresh on a refresh principal: got %d %q", a.status, a.raw)
	}
	a = p.request("drop", http.MethodPost, "/refresh/"+instName)
	if a.status != 200 || strings.TrimSpace(a.raw) != `{"ready":true,"refreshed":false}` {
		t.Fatalf("second refresh inside the floor: got %d %q", a.status, a.raw)
	}
	for _, c := range [][2]string{{http.MethodGet, "/cred/" + instName}, {http.MethodGet, "/refresh/" + instName}, {http.MethodPost, "/refresh/no-such-credential"}} {
		a := p.request("drop", c[0], c[1])
		if a.status == 200 || a.Token != "" || strings.Contains(a.raw, "at-") {
			t.Fatalf("%s %s on a refresh principal: got %d %q", c[0], c[1], a.status, a.raw)
		}
	}
	if strings.Contains(p.logs.String(), "at-") {
		t.Fatalf("a token reached the log: %q", p.logs.String())
	}
}
