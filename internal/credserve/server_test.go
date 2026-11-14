//go:build linux

package credserve

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/jack-work/hush/internal/oauth"
)

type endpoint struct {
	srv    *httptest.Server
	posts  atomic.Int64
	gets   atomic.Int64
	mu     sync.Mutex
	answer func(n int64, r *http.Request) (int, string)
	delay  time.Duration
}

func newEndpoint(t *testing.T) *endpoint {
	t.Helper()
	e := &endpoint{}
	e.answer = func(n int64, r *http.Request) (int, string) {
		return 200, fmt.Sprintf(`{"access_token":"at-%d","refresh_token":"rt-canary-rotated-%d-abcdefgh","expires_in":3600}`, n, n)
	}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int64
		if r.Method == http.MethodPost {
			n = e.posts.Add(1)
		} else {
			n = e.gets.Add(1)
		}
		time.Sleep(e.delay)
		e.mu.Lock()
		answer := e.answer
		e.mu.Unlock()
		status, body := answer(n, r)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *endpoint) setAnswer(f func(n int64, r *http.Request) (int, string)) {
	e.mu.Lock()
	e.answer = f
	e.mu.Unlock()
}

func (e *endpoint) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(e.srv.Certificate())
	return p
}

type rig struct {
	t        *testing.T
	ep       *endpoint
	key      *age.X25519Identity
	cfg      *Config
	stateDir string
	mgr      *oauth.Manager
	srv      *Server
	logs     *syncBuffer
	sock     string
	client   *http.Client
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

const instName = "anthropic-work"

func testConfig(t *testing.T, key *age.X25519Identity, tokenURL string) *Config {
	t.Helper()
	cfg, err := ParseConfig([]byte(fmt.Sprintf(`
recipient = %q
allow_user = "rou2"

[instances.%s]
kind = "anthropic"
authorize_url = "https://claude.example/oauth/authorize"
token_url = %q
redirect_uri = "https://console.example/oauth/code/callback"
client_id = "client-1"
scopes = "user:inference"

[instances.copilot-work]
kind = "copilot"
device_url = "https://github.example/login/device/code"
github_token_url = "https://github.example/login/oauth/access_token"
token_url = "https://api.github.example/copilot_internal/v2/token"
client_id = "Iv1.x"
`, key.Recipient().String(), instName, tokenURL)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newRig(t *testing.T, seed oauth.Tokens) *rig {
	t.Helper()
	ep := newEndpoint(t)
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, ep: ep, key: key, stateDir: t.TempDir(), logs: &syncBuffer{}}
	r.cfg = testConfig(t, key, ep.srv.URL+"/v1/oauth/token")

	if seed.AccessToken != "" {
		seeder := oauth.NewManager(r.stateDir, nil, key.Recipient(), log.New(io.Discard, "", 0))
		if err := seeder.Register(r.cfg.Instances[instName].OAuthConfig(instName), seed); err != nil {
			t.Fatal(err)
		}
		seeder.Stop()
	}
	r.start(uint32(os.Getuid()))
	return r
}

func (r *rig) start(allow uint32) {
	t := r.t
	r.mgr = oauth.NewManager(r.stateDir, []age.Identity{r.key}, r.key.Recipient(), log.New(r.logs, "", 0))
	r.mgr.SetHTTPClient(FencedClient(r.cfg.EgressHosts(), r.ep.roots()))
	if err := r.mgr.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.mgr.Stop)
	r.srv = NewServer(r.cfg, r.mgr, allow, log.New(r.logs, "", 0))

	dir, err := os.MkdirTemp("", "credsock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	r.sock = filepath.Join(dir, "cred.sock")
	ln, err := net.Listen("unix", r.sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := r.srv.HTTPServer()
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	r.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", r.sock)
		},
	}}
}

type answer struct {
	status int
	raw    string
	Name   string `json:"name"`
	Token  string `json:"token"`
	Expiry int64  `json:"expires_at"`
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

func (r *rig) get(name string) answer {
	r.t.Helper()
	res, err := r.client.Get("http://minter/cred/" + url.PathEscape(name))
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	a := answer{status: res.StatusCode, raw: string(body)}
	if err := json.Unmarshal(body, &a); err != nil {
		r.t.Fatalf("answer %d is not JSON: %q", res.StatusCode, body)
	}
	return a
}

func (r *rig) skew(d time.Duration) {
	r.srv.Now = func() time.Time { return time.Now().Add(d) }
}

func seedTokens(expiresIn int) oauth.Tokens {
	return oauth.Tokens{AccessToken: "at-seed", RefreshToken: "rt-canary-seed-0123456789", ExpiresIn: expiresIn}
}

func TestServesTheCachedTokenWithItsExpiry(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	a := r.get(instName)
	if a.status != 200 || a.Token != "at-seed" || a.Name != instName {
		t.Fatalf("got %d %q", a.status, a.raw)
	}
	if left := time.Until(time.Unix(a.Expiry, 0)); left < 59*time.Minute || left > 61*time.Minute {
		t.Fatalf("expires_at is %s away, want about an hour", left)
	}
	if n := r.ep.posts.Load(); n != 0 {
		t.Fatalf("a fresh token cost %d POSTs", n)
	}
}

// Row (i): the refresh token never leaves the minter, not even when the
// token endpoint echoes it back in its own error bodies.
func TestRefreshTokenCanaryNeverLeaves(t *testing.T) {
	const canary = "rt-canary-seed-0123456789"
	bodies := map[string]func(int64, *http.Request) (int, string){
		"description": func(int64, *http.Request) (int, string) {
			return 400, `{"error":"invalid_grant","error_description":"refresh token ` + canary + ` was revoked"}`
		},
		"error code": func(int64, *http.Request) (int, string) {
			return 400, `{"error":"` + canary + `"}`
		},
		"raw 5xx": func(int64, *http.Request) (int, string) {
			return 502, "upstream said refresh_token=" + canary
		},
		"rotation": func(n int64, _ *http.Request) (int, string) {
			return 200, `{"access_token":"at-1","refresh_token":"rt-canary-rotated-abcdefgh","expires_in":3600}`
		},
	}
	for label, body := range bodies {
		t.Run(label, func(t *testing.T) {
			r := newRig(t, seedTokens(3600))
			r.ep.setAnswer(body)
			r.skew(50 * time.Minute)
			var replies []string
			for i := 0; i < 3; i++ {
				replies = append(replies, r.get(instName).raw)
			}
			replies = append(replies, r.get("copilot-work").raw, r.get("nope").raw)
			if r.ep.posts.Load() == 0 {
				t.Fatal("no refresh was attempted: the canary was never exposed to the server")
			}
			for _, secret := range []string{canary, "rt-canary-rotated"} {
				for _, reply := range replies {
					if strings.Contains(reply, secret) {
						t.Fatalf("a /cred reply carried the refresh token: %s", reply)
					}
				}
				if strings.Contains(r.logs.String(), secret) {
					t.Fatalf("the log carried the refresh token:\n%s", r.logs.String())
				}
				disk, _ := os.ReadFile(filepath.Join(r.stateDir, "oauth", instName+".toml"))
				if strings.Contains(string(disk), secret) {
					t.Fatalf("the state file holds the refresh token in plaintext")
				}
			}
		})
	}
}

// Row (ii): N callers arriving during one refresh share it.
func TestConcurrentCallsDuringARefreshCostOnePost(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	r.ep.delay = 300 * time.Millisecond
	r.skew(50 * time.Minute)
	const n = 50
	var wg sync.WaitGroup
	tokens := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i] = r.get(instName).Token
		}(i)
	}
	wg.Wait()
	if p := r.ep.posts.Load(); p != 1 {
		t.Fatalf("%d concurrent calls cost %d POSTs, want 1", n, p)
	}
	for i, tok := range tokens {
		if tok != "at-1" {
			t.Fatalf("caller %d got %q, want the one refreshed token", i, tok)
		}
	}
}

// Row (ii): a caller that keeps asking (a 401 loop invalidating and
// refetching) cannot drive the token endpoint faster than the floor.
func TestRepeatedCallsCannotStormTheEndpoint(t *testing.T) {
	cases := map[string]func(int64, *http.Request) (int, string){
		"short-lived tokens": func(n int64, _ *http.Request) (int, string) {
			return 200, fmt.Sprintf(`{"access_token":"at-%d","refresh_token":"rt-%d-abcdefgh","expires_in":1}`, n, n)
		},
		"transient failure": func(int64, *http.Request) (int, string) { return 503, "busy" },
		"refused":           func(int64, *http.Request) (int, string) { return 400, `{"error":"invalid_grant"}` },
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			r := newRig(t, seedTokens(1))
			r.ep.setAnswer(body)
			for i := 0; i < 40; i++ {
				r.get(instName)
			}
			if p := r.ep.posts.Load(); p != 1 {
				t.Fatalf("40 calls inside the minimum interval cost %d POSTs, want 1", p)
			}
		})
	}
}

func TestFreshTokenIsServedWithoutAPost(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	for i := 0; i < 20; i++ {
		if a := r.get(instName); a.Token != "at-seed" {
			t.Fatalf("got %q", a.raw)
		}
	}
	if p := r.ep.posts.Load(); p != 0 {
		t.Fatalf("re-asking for a fresh token cost %d POSTs", p)
	}
}

func TestRefreshesAheadOfExpiry(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	r.skew(43 * time.Minute)
	a := r.get(instName)
	if a.status != 200 || a.Token != "at-1" {
		t.Fatalf("a token 72%% through its life was served as is: %q", a.raw)
	}
	if p := r.ep.posts.Load(); p != 1 {
		t.Fatalf("%d POSTs, want 1", p)
	}
	if left := time.Until(time.Unix(a.Expiry, 0)); left < 59*time.Minute {
		t.Fatalf("the renewed token expires in %s", left)
	}
}

func TestRefusedRefreshAnswersSignInNeeded(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	r.ep.setAnswer(func(int64, *http.Request) (int, string) {
		return 400, `{"error":"invalid_grant","error_description":"refresh token revoked"}`
	})
	r.skew(50 * time.Minute)
	a := r.get(instName)
	if a.status != 503 || a.Reason != "sign-in needed" || a.Error != "credential_stale" || a.Token != "" {
		t.Fatalf("got %d %q", a.status, a.raw)
	}
	for i := 0; i < 5; i++ {
		if a := r.get(instName); a.Reason != "sign-in needed" {
			t.Fatalf("got %q", a.raw)
		}
	}
	if p := r.ep.posts.Load(); p != 1 {
		t.Fatalf("a refused credential kept POSTing: %d", p)
	}

	login := oauth.NewManager(r.stateDir, nil, r.key.Recipient(), log.New(io.Discard, "", 0))
	if err := login.Register(r.cfg.Instances[instName].OAuthConfig(instName), oauth.Tokens{AccessToken: "at-relogin", RefreshToken: "rt-relogin-abcdefgh", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	login.Stop()
	r.skew(0)
	if a := r.get(instName); a.status != 200 || a.Token != "at-relogin" {
		t.Fatalf("a new sign-in on disk was not picked up: %q\n%s", a.raw, r.logs.String())
	}
}

func TestFirstSignInIsPickedUpWithoutARestart(t *testing.T) {
	r := newRig(t, oauth.Tokens{})
	if a := r.get(instName); a.status != 503 || a.Reason != "sign-in needed" {
		t.Fatalf("an instance never signed in answered %q", a.raw)
	}
	login := oauth.NewManager(r.stateDir, nil, r.key.Recipient(), log.New(io.Discard, "", 0))
	if err := login.Register(r.cfg.Instances[instName].OAuthConfig(instName), seedTokens(3600)); err != nil {
		t.Fatal(err)
	}
	login.Stop()
	if a := r.get(instName); a.status != 200 || a.Token != "at-seed" {
		t.Fatalf("got %q", a.raw)
	}
}

// Persist-before-use: a refreshed token whose write failed is not served.
func TestUnpersistedRefreshIsNotServed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	r := newRig(t, seedTokens(3600))
	dir := filepath.Join(r.stateDir, "oauth")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	r.skew(50 * time.Minute)
	a := r.get(instName)
	if r.ep.posts.Load() != 1 {
		t.Fatal("no refresh was attempted")
	}
	if a.Token == "at-1" {
		t.Fatal("a token the minter failed to persist was served")
	}
	if a.status != 200 || a.Token != "at-seed" {
		t.Fatalf("the old token, still valid, should be served: %q", a.raw)
	}
}

func TestPeerWithAnotherUIDIsRefused(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	r.srv.allowUID = uint32(os.Getuid()) + 1
	a := r.get(instName)
	if a.status != 403 || a.Token != "" || strings.Contains(a.raw, "at-seed") {
		t.Fatalf("got %d %q", a.status, a.raw)
	}
}

func TestUnknownCredentialIs404(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	if a := r.get("anthropic-personal"); a.status != 404 || a.Error != "unknown_credential" {
		t.Fatalf("got %d %q", a.status, a.raw)
	}
}

func TestFenceRefusesOtherHostsAndRedirects(t *testing.T) {
	ep := newEndpoint(t)
	other := newEndpoint(t)
	u, _ := url.Parse(ep.srv.URL)
	c := FencedClient([]string{u.Host}, ep.roots())

	if _, err := c.Get(ep.srv.URL); err != nil {
		t.Fatalf("the allowed host was refused: %v", err)
	}
	if _, err := c.Get(other.srv.URL); err == nil || !strings.Contains(err.Error(), ErrEgressRefused.Error()) {
		t.Fatalf("a host not configured was reached: %v", err)
	}
	before := ep.gets.Load()
	redir := httptest.NewTLSServer(http.RedirectHandler(ep.srv.URL+"/elsewhere", http.StatusFound))
	defer redir.Close()
	ru, _ := url.Parse(redir.URL)
	c = FencedClient([]string{u.Host, ru.Host}, nil)
	c.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	if _, err := c.Get(redir.URL); err == nil || !strings.Contains(err.Error(), ErrEgressRefused.Error()) {
		t.Fatalf("a redirect was followed: %v", err)
	}
	if ep.gets.Load() != before || other.gets.Load() != 0 {
		t.Fatal("a redirect reached a host")
	}
}

func TestConfigRefusesSecretsAndPlainHTTP(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	base := fmt.Sprintf("recipient = %q\nallow_user = \"rou2\"\n[instances.a]\nkind = \"anthropic\"\nauthorize_url = \"https://a.example/authorize\"\nredirect_uri = \"https://a.example/cb\"\nclient_id = \"c\"\n", key.Recipient())
	for label, extra := range map[string]string{
		"client secret": "token_url = \"https://a.example/token\"\nclient_secret = \"s\"\n",
		"refresh token": "token_url = \"https://a.example/token\"\nrefresh_token = \"s\"\n",
		"plain http":    "token_url = \"http://a.example/token\"\n",
	} {
		if _, err := ParseConfig([]byte(base + extra)); err == nil {
			t.Errorf("%s: config accepted", label)
		}
	}
	if _, err := ParseConfig([]byte(base + "token_url = \"https://a.example/token\"\n")); err != nil {
		t.Fatalf("the plain config was refused: %v", err)
	}
}
