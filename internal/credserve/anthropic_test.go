//go:build linux

package credserve

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

const maxName = "anthropic-max"

type anthropicRouting struct {
	next   http.RoundTripper
	target *url.URL
	t      *testing.T
}

func (r anthropicRouting) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != oauth.AnthropicTokenURL {
		r.t.Errorf("token request left the pinned URL: %s", req.URL)
	}
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme, u.Host = r.target.Scheme, r.target.Host
	clone.URL = &u
	return r.next.RoundTrip(clone)
}

func anthropicRig(t *testing.T, seed oauth.Tokens) (*rig, *http.Client) {
	t.Helper()
	r := newRig(t, oauth.Tokens{})
	in := (Instance{Kind: KindAnthropic}).anthropicDefaults()
	delete(r.cfg.Instances, instName)
	r.cfg.Instances[maxName] = in
	target, _ := url.Parse(r.ep.srv.URL)
	client := r.ep.srv.Client()
	client.Transport = anthropicRouting{client.Transport, target, t}
	if err := r.mgr.SetHTTPClient(client); err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "" {
		if err := r.mgr.Register(in.OAuthConfig(maxName), seed); err != nil {
			t.Fatal(err)
		}
	}
	return r, client
}

func TestAnthropicConfigPinsEveryEndpoint(t *testing.T) {
	key := newRig(t, oauth.Tokens{}).key
	prefix := fmt.Sprintf("recipient = %q\nallow_user = 'rou2'\n[instances.%s]\nkind = 'anthropic'\n", key.Recipient().String(), maxName)
	cfg, err := ParseConfig([]byte(prefix))
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Instances[maxName]
	if in.TokenURL != oauth.AnthropicTokenURL || in.AuthorizeURL != oauth.AnthropicAuthorizeURL || in.ClientID != oauth.AnthropicClientID || in.RedirectURI != oauth.AnthropicRedirectURI || in.Scopes != oauth.AnthropicScopes {
		t.Fatal("defaults are not the pinned values")
	}
	if got := in.OAuthConfig(maxName); got.Grant != oauth.GrantAnthropic || !oauth.AnthropicPinned(got) {
		t.Fatalf("oauth config %+v", got)
	}
	if hosts := cfg.EgressHosts(); len(hosts) != 1 || hosts[0] != "console.anthropic.com:443" {
		t.Fatalf("egress %v", hosts)
	}
	for _, setting := range []string{
		"token_url='https://attacker.invalid/token'",
		"authorize_url='https://attacker.invalid/auth'",
		"redirect_uri='http://localhost:5555/callback'",
		"client_id='other'",
		"scopes='user:inference'",
		"device_url='https://github.example/device'",
		"github_token_url='https://github.example/token'",
	} {
		if _, err := ParseConfig([]byte(prefix + setting)); err == nil {
			t.Fatalf("unsafe %s accepted", setting)
		}
	}
	explicit := prefix + fmt.Sprintf("token_url=%q\n", oauth.AnthropicTokenURL)
	if _, err := ParseConfig([]byte(explicit)); err != nil {
		t.Fatalf("the pinned value itself was refused: %v", err)
	}
}

func TestAnthropicServesAndRefreshesThroughThePinnedEndpoint(t *testing.T) {
	r, _ := anthropicRig(t, oauth.Tokens{AccessToken: "at-seed", RefreshToken: "rt-canary-seed-0123456789", ExpiresIn: 3600})
	if a := r.get(maxName); a.status != 200 || a.Token != "at-seed" || r.ep.posts.Load() != 0 {
		t.Fatalf("seed not served: %d %q", a.status, a.raw)
	}
	var form url.Values
	r.ep.setAnswer(func(n int64, req *http.Request) (int, string) {
		req.ParseForm()
		form = req.Form
		return 200, `{"access_token":"at-next","refresh_token":"rt-canary-rotated-abcdefgh","expires_in":28800}`
	})
	r.skew(50 * time.Minute)
	a := r.get(maxName)
	if a.status != 200 || a.Token != "at-next" || form.Get("refresh_token") != "rt-canary-seed-0123456789" || form.Get("client_id") != oauth.AnthropicClientID {
		t.Fatalf("refresh not served: %d %q %v", a.status, a.raw, form)
	}
	for _, text := range []string{a.raw, r.logs.String()} {
		if strings.Contains(text, "rt-canary") {
			t.Fatal("refresh token in a reply or the log")
		}
	}
	raw, err := os.ReadFile(filepath.Join(r.stateDir, "oauth", maxName+".toml"))
	if err != nil || strings.Contains(string(raw), "rt-canary") || strings.Contains(string(raw), "at-next") {
		t.Fatalf("state file holds a token in the clear: %v", err)
	}
}

func TestAnthropicStateWrittenForAnotherConfigIsNotServed(t *testing.T) {
	r := newRig(t, oauth.Tokens{})
	foreign := oauth.Config{Name: maxName, Grant: oauth.GrantRefreshToken, TokenURL: "https://attacker.invalid/token", ClientID: "other"}
	if err := r.mgr.Register(foreign, seedTokens(3600)); err != nil {
		t.Fatal(err)
	}
	r.cfg.Instances[maxName] = (Instance{Kind: KindAnthropic}).anthropicDefaults()
	for _, path := range []string{"/cred/", "/refresh/"} {
		req, _ := http.NewRequest(http.MethodGet, "http://minter"+path+maxName, nil)
		if path == "/refresh/" {
			req, _ = http.NewRequest(http.MethodPost, "http://minter"+path+maxName, nil)
		}
		resp, err := r.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 503 || strings.Contains(string(raw), "at-seed") || !strings.Contains(string(raw), "sign-in needed") {
			t.Fatalf("%s served a credential from a foreign config: %d %s", path, resp.StatusCode, raw)
		}
	}
	if _, doc, raw := getStatus(t, r.client); doc[maxName].State != stateStale || doc[maxName].Reason != reasonSignIn {
		t.Fatalf("/status calls a foreign config usable: %s", raw)
	}
	if r.ep.posts.Load() != 0 {
		t.Fatal("a foreign refresh token was spent")
	}
}

func TestAnthropicLocalLoginUsesAnIndependentStateAndTheExchangeServes(t *testing.T) {
	r, client := anthropicRig(t, oauth.Tokens{})
	out := &strings.Builder{}
	l := &Login{Config: r.cfg, StateDir: r.stateDir, Name: maxName, Client: client, Out: out}
	var exchange map[string]string
	r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
		raw, _ := io.ReadAll(req.Body)
		json.Unmarshal(raw, &exchange)
		return 200, `{"access_token":"at-login","refresh_token":"rt-login-abcdefgh","expires_in":28800}`
	})
	var authorize *url.URL
	l.ReadCode = func(string) (string, error) {
		raw := regexpURL(out.String())
		authorize, _ = url.Parse(raw)
		return "the-code#" + authorize.Query().Get("state"), nil
	}
	if err := l.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	q := authorize.Query()
	digest := sha256.Sum256([]byte(exchange["code_verifier"]))
	if !strings.HasPrefix(authorize.String(), oauth.AnthropicAuthorizeURL+"?") || q.Get("client_id") != oauth.AnthropicClientID || q.Get("redirect_uri") != oauth.AnthropicRedirectURI || q.Get("scope") != oauth.AnthropicScopes || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		t.Fatalf("authorize URL %s", authorize)
	}
	if base64.RawURLEncoding.EncodeToString(digest[:]) != q.Get("code_challenge") || exchange["code_verifier"] == q.Get("state") || exchange["code"] != "the-code" || exchange["state"] != q.Get("state") {
		t.Fatalf("PKCE exchange mismatch: %v", exchange)
	}
	if a := r.get(maxName); a.status != 200 || a.Token != "at-login" {
		t.Fatalf("login not served: %q", a.raw)
	}
}

func TestAnthropicLocalLoginRefusesAForeignStateWithoutSpendingTheCode(t *testing.T) {
	r, client := anthropicRig(t, oauth.Tokens{})
	l := &Login{Config: r.cfg, StateDir: r.stateDir, Name: maxName, Client: client, Out: &strings.Builder{}}
	l.ReadCode = func(string) (string, error) { return "the-code#not-this-one", nil }
	if err := l.Run(context.Background()); err == nil {
		t.Fatal("a foreign state was accepted")
	}
	if r.ep.posts.Load() != 0 {
		t.Fatal("the code was exchanged anyway")
	}
}

func regexpURL(s string) string {
	for _, field := range strings.Fields(s) {
		if strings.HasPrefix(field, "https://") {
			return field
		}
	}
	return ""
}
