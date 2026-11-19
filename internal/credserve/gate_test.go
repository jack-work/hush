//go:build linux

package credserve

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

// t0 for the gate: a fixed instant, so every boundary below is literal.
var gateT0 = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// fakeClock moves only when the gate waits: after(d) advances now by d and
// fires at once, so relay polling is deterministic and instant.
type fakeClock struct {
	mu  sync.Mutex
	cur time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.cur }
func (c *fakeClock) after(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.cur = c.cur.Add(d)
	ch := make(chan time.Time, 1)
	ch <- c.cur
	c.mu.Unlock()
	return ch
}

// idp is a fake OpenID provider, code relay and credential token endpoint on
// the rig's one TLS endpoint, shaped as Kanidm answers (discovery, a form
// token exchange returning access_token + id_token, userinfo with groups).
// Each case changes one thing from a good sign-in.
type idp struct {
	relay     []int          // statuses answered before the code (e.g. 503, 404)
	pending   bool           // the relay never has a code
	slowDown  bool           // the relay always answers 429
	relayBody string         // the 200 body (default {"code":"gate-code"})
	token     string         // the token endpoint's answer (default: a good one)
	tokenCode int            // the token endpoint's status (default 200)
	claims    map[string]any // overrides on a good id_token
	rawIDTok  string         // an id_token used verbatim
	userinfo  int            // userinfo status (default 200)
	groups    []string
	noUI      bool // discovery names no userinfo endpoint

	relayCalls int
	gotState   string
	credPost   bool // the credential's own token exchange ran
}

// gateRig returns the login, its output, the clock, and what the fake saw
// (read under the lock the handler holds: it runs on the server's goroutines).
func gateRig(t *testing.T, p *idp) (*Login, *syncBuffer, func() idp) {
	t.Helper()
	var mu sync.Mutex
	r, l, _ := loginRig(t)
	out := &syncBuffer{}
	clock := &fakeClock{cur: gateT0}
	l.Out, l.pollEvery = out, time.Second
	base := r.ep.srv.URL
	r.cfg.LoginGate = &LoginGate{Issuer: base + "/idp", ClientID: "hush-cli", Group: "hush-admin",
		RedirectURI: "https://relay.example/callback", Relay: base + "/relay", Wait: "10s"}
	if err := r.cfg.LoginGate.validate(); err != nil {
		t.Fatal(err)
	}
	r.cfg.LoginGate.clock = gateClock{now: clock.now, after: clock.after}
	gateURL := func(i int) url.Values { // the i-th URL login printed (0 = the gate's)
		all := regexp.MustCompile(`https://\S+`).FindAllString(out.String(), -1)
		u, _ := url.Parse(all[i])
		return u.Query()
	}
	r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		switch req.URL.Path {
		case "/idp/.well-known/openid-configuration":
			ui := `,"userinfo_endpoint":"%[1]s/userinfo"`
			if p.noUI {
				ui = ""
			}
			return 200, fmt.Sprintf(`{"issuer":%[1]q,"authorization_endpoint":"%[1]s/authorize","token_endpoint":"%[1]s/token"`+ui+`}`, base+"/idp")
		case "/relay":
			p.relayCalls++
			p.gotState = req.URL.Query().Get("state")
			if p.pending {
				return 404, `{}`
			}
			if p.slowDown {
				return 429, `{}`
			}
			if len(p.relay) > 0 {
				s := p.relay[0]
				p.relay = p.relay[1:]
				return s, `{}`
			}
			if p.relayBody != "" {
				return 200, p.relayBody
			}
			return 200, `{"code":"gate-code"}`
		case "/idp/token":
			req.ParseForm()
			if req.Form.Get("code") != "gate-code" || req.Form.Get("code_verifier") == "" || req.Form.Get("grant_type") != "authorization_code" {
				return 400, `{"error":"invalid_grant"}`
			}
			if p.tokenCode != 0 {
				return p.tokenCode, p.token
			}
			if p.token != "" {
				return 200, p.token
			}
			jws := p.rawIDTok
			if jws == "" {
				claims := map[string]any{"iss": base + "/idp", "aud": []string{"hush-cli"}, "nonce": gateURL(0).Get("nonce"),
					"exp": clock.now().Add(5 * time.Minute).Unix(), "auth_time": clock.now().Unix()}
				for k, v := range p.claims {
					claims[k] = v
				}
				body, _ := json.Marshal(claims)
				jws = "e30." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
			}
			return 200, fmt.Sprintf(`{"access_token":"gate-at","id_token":%q}`, jws)
		case "/idp/userinfo":
			if p.userinfo != 0 {
				return p.userinfo, `{"error":"invalid_token"}`
			}
			if req.Header.Get("Authorization") != "Bearer gate-at" {
				return 401, `{}`
			}
			groups, _ := json.Marshal(p.groups)
			return 200, fmt.Sprintf(`{"preferred_username":"jack","groups":%s}`, groups)
		case "/v1/oauth/token":
			p.credPost = true
			io.Copy(io.Discard, req.Body)
			return 200, `{"access_token":"at-login","refresh_token":"rt-login-abcdefgh","expires_in":28800}`
		}
		return 404, `{}`
	})
	l.ReadCode = func(string) (string, error) { return "the-code#" + gateURL(1).Get("state"), nil }
	return l, out, func() idp {
		mu.Lock()
		defer mu.Unlock()
		return idp{relayCalls: p.relayCalls, gotState: p.gotState, credPost: p.credPost}
	}
}

var member = []string{"idm_all_persons@idm.example", "hush-admin@idm.example"}

// TestLoginGate drives every outcome of the gate. A refusal must name its
// exact reason AND leave the credential's own login unrun. Mutations each
// case kills are listed in the PR (generated by the mutation run).
func TestLoginGate(t *testing.T) {
	fresh := func(ago time.Duration) map[string]any { return map[string]any{"auth_time": gateT0.Add(-ago).Unix()} }
	cases := []struct {
		name  string
		idp   idp
		want  string // the exact error; "" = the gate passes and the credential's login runs
		polls int    // relay calls, when the case pins them
	}{
		// passes
		{"a member signs in", idp{groups: member}, "", 1},
		{"the group's short name", idp{groups: []string{"hush-admin"}}, "", 1},
		{"auth_time exactly max_age + skew old (5m + 60s)", idp{groups: member, claims: fresh(5*time.Minute + 60*time.Second)}, "", 1},
		{"exp exactly skew past (60s)", idp{groups: member, claims: map[string]any{"exp": gateT0.Add(-60 * time.Second).Unix()}}, "", 1},
		{"aud as one string", idp{groups: member, claims: map[string]any{"aud": "hush-cli"}}, "", 1},
		{"relay 503 then 404 then 429, sign-in survives", idp{groups: member, relay: []int{503, 404, 429}}, "", 4},
		// refusals at the provider's answers
		{"not in the group", idp{groups: []string{"hush-admins@idm.example"}}, "login gate: jack is not in hush-admin", 1},
		{"a prefix of the group", idp{groups: []string{"hush-adminx@idm.example", "xhush-admin"}}, "login gate: jack is not in hush-admin", 1},
		{"no groups", idp{groups: []string{}}, "login gate: jack is not in hush-admin", 1},
		{"an empty group name", idp{groups: []string{""}}, "login gate: jack is not in hush-admin", 1},
		{"a look-alike unicode hyphen", idp{groups: []string{"hush\u2011admin@idm.example"}}, "login gate: jack is not in hush-admin", 1},
		{"trailing whitespace", idp{groups: []string{"hush-admin "}}, "login gate: jack is not in hush-admin", 1},
		{"userinfo refuses the token", idp{groups: member, userinfo: 401}, "login gate: userinfo 401: the provider refused the token", 1},
		{"auth_time one second past max_age + skew", idp{groups: member, claims: fresh(5*time.Minute + 61*time.Second)}, "login gate: the sign-in is not fresh (auth_time older than 5m0s)", 1},
		{"no auth_time", idp{groups: member, claims: map[string]any{"auth_time": 0}}, "login gate: the sign-in is not fresh (auth_time older than 5m0s)", 1},
		{"exp one second past skew", idp{groups: member, claims: map[string]any{"exp": gateT0.Add(-61 * time.Second).Unix()}}, "login gate: id_token expired", 1},
		{"another sign-in's nonce", idp{groups: member, claims: map[string]any{"nonce": "other"}}, "login gate: id_token nonce does not match this sign-in", 1},
		{"another issuer", idp{groups: member, claims: map[string]any{"iss": "https://evil.example"}}, `login gate: id_token issuer "https://evil.example" is not "ISSUER"`, 1},
		{"a token for another client", idp{groups: member, claims: map[string]any{"aud": []string{"troupe"}}}, `login gate: id_token is not for client "hush-cli"`, 1},
		{"no audience", idp{groups: member, claims: map[string]any{"aud": nil}}, `login gate: id_token is not for client "hush-cli"`, 1},
		{"id_token not a JWS", idp{groups: member, rawIDTok: "a.b"}, "login gate: id_token is not a JWS", 1},
		{"id_token payload not base64url", idp{groups: member, rawIDTok: "e30.!!!.sig"}, "login gate: id_token payload is not base64url", 1},
		{"id_token payload not JSON", idp{groups: member, rawIDTok: "e30." + base64.RawURLEncoding.EncodeToString([]byte("a]b[c")) + ".sig"}, "login gate: id_token payload is not JSON", 1},
		{"token endpoint refuses", idp{tokenCode: 400, token: `{"error":"invalid_grant","error_description":"used"}`}, "login gate: token exchange 400: invalid_grant: used", 1},
		{"token answer without id_token", idp{token: `{"access_token":"gate-at"}`}, "login gate: token exchange: no access_token or id_token in the answer", 1},
		{"provider names no userinfo", idp{noUI: true}, "login gate: the provider names no authorization or userinfo endpoint", 0},
		// refusals at the relay
		{"sign-in refused at the provider", idp{relayBody: `{"error":"access_denied","error_description":"no"}`}, "login gate: sign-in refused: access_denied: no", 1},
		{"relay answer not JSON", idp{relayBody: `a]b[c`}, "login gate: relay: the answer is not JSON", 1},
		{"relay answer without a code", idp{relayBody: `{"code":""}`}, "login gate: relay: no code in the answer", 1},
		{"relay refuses the request", idp{relay: []int{400}}, "login gate: relay 400: body of 2 bytes", 1},
		{"relay says slow down forever: 5s apart in 10s is exactly 2 polls", idp{slowDown: true}, "login gate: no sign-in arrived in time", 2},
		{"nobody signs in: wait 10s at 1s polls is exactly 10 polls", idp{pending: true}, "login gate: no sign-in arrived in time", 10},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.idp
			l, out, seen := gateRig(t, &p)
			err := l.Run(context.Background())
			got := seen()
			if c.want == "" {
				if err != nil {
					t.Fatalf("%s: refused: %v\n%s", c.name, err, out)
				}
				if !got.credPost {
					t.Fatalf("%s: the gate passed but the credential's login did not run", c.name)
				}
				if want := gateURLState(out.String()); got.gotState != want {
					t.Fatalf("%s: the relay was asked for state %q, the sign-in's is %q", c.name, got.gotState, want)
				}
			} else {
				want := strings.ReplaceAll(c.want, "ISSUER", l.Config.LoginGate.Issuer) // the rig's own issuer URL
				if err == nil || err.Error() != want {
					t.Fatalf("%s: got %v, want %q", c.name, err, want)
				}
				if got.credPost {
					t.Fatalf("%s: the gate refused but the credential's login ran", c.name)
				}
			}
			if got.relayCalls != c.polls {
				t.Fatalf("%s: relay asked %d times, want %d", c.name, got.relayCalls, c.polls)
			}
		})
	}
}

func gateURLState(out string) string {
	u, _ := url.Parse(regexp.MustCompile(`https://\S+`).FindString(out))
	return u.Query().Get("state")
}

// TestLoginGateRelayBackoffDoublesFromOneSecond: a failing relay is retried
// at 2s, 4s, 8s... (RED if the backoff stops doubling or starts elsewhere);
// with wait 7s that is polls at 0, 2s and 6s, then the deadline.
func TestLoginGateRelayBackoffDoublesFromOneSecond(t *testing.T) {
	p := idp{relay: []int{503, 503, 503, 503, 503}}
	l, _, seen := gateRig(t, &p)
	l.Config.LoginGate.wait = 7 * time.Second
	l.pollEvery = 0 // the default, one second
	err := l.Run(context.Background())
	if err == nil || err.Error() != "login gate: no sign-in arrived in time" {
		t.Fatalf("got %v", err)
	}
	if got := seen().relayCalls; got != 3 {
		t.Fatalf("relay asked %d times, want 3", got)
	}
}

// TestLoginGateAuthorizeURLForcesAFreshPasskeySignIn pins every authorize
// parameter (RED if prompt=login or max_age=0 goes: a reused session).
func TestLoginGateAuthorizeURLForcesAFreshPasskeySignIn(t *testing.T) {
	p := idp{groups: []string{"hush-admin"}}
	l, out, _ := gateRig(t, &p)
	if err := l.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(regexp.MustCompile(`https://\S+`).FindString(out.String()))
	q := u.Query()
	for k, want := range map[string]string{"prompt": "login", "max_age": "0", "code_challenge_method": "S256",
		"client_id": "hush-cli", "response_type": "code", "scope": "openid profile groups",
		"redirect_uri": "https://relay.example/callback"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("code_challenge")) != 43 || len(q.Get("nonce")) != 43 || len(q.Get("state")) != 43 || q.Get("state") == q.Get("nonce") {
		t.Errorf("challenge/nonce/state not 32 random bytes each, or reused: %v", q)
	}
}

func TestLoginGateConfig(t *testing.T) {
	good := LoginGate{Issuer: "https://idm.example/o/hush-cli", ClientID: "hush-cli", Group: "hush-admin",
		RedirectURI: "https://auth.example/cb", Relay: "https://auth.example/code"}
	cases := []struct {
		name string
		edit func(*LoginGate)
		want string
	}{
		{"good", func(*LoginGate) {}, ""},
		{"plain http issuer", func(g *LoginGate) { g.Issuer = "http://idm.example" }, `cred config: login_gate: issuer must be an https URL, not "http://idm.example"`},
		{"no relay", func(g *LoginGate) { g.Relay = "" }, `cred config: login_gate: relay must be an https URL, not ""`},
		{"relative redirect", func(g *LoginGate) { g.RedirectURI = "/cb" }, `cred config: login_gate: redirect_uri must be an https URL, not "/cb"`},
		{"no group", func(g *LoginGate) { g.Group = "" }, "cred config: login_gate: client_id and group are required"},
		{"no client", func(g *LoginGate) { g.ClientID = "" }, "cred config: login_gate: client_id and group are required"},
		{"bad max_age", func(g *LoginGate) { g.MaxAge = "soon" }, `cred config: login_gate: max_age: time: invalid duration "soon"`},
		{"zero wait", func(g *LoginGate) { g.Wait = "0s" }, "cred config: login_gate: wait: must be positive"},
		{"negative wait", func(g *LoginGate) { g.Wait = "-1s" }, "cred config: login_gate: wait: must be positive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := good
			c.edit(&g)
			err := g.validate()
			if c.want == "" && err != nil || c.want != "" && (err == nil || err.Error() != c.want) {
				t.Fatalf("%s: got %v, want %q", c.name, err, c.want)
			}
		})
	}
}

// TestLoginGateDefaultsAreFiveMinutes pins the defaults literally (RED if
// either changes).
func TestLoginGateDefaultsAreFiveMinutes(t *testing.T) {
	g := LoginGate{Issuer: "https://i.example", ClientID: "c", Group: "g", RedirectURI: "https://r.example", Relay: "https://r.example/code"}
	if err := g.validate(); err != nil {
		t.Fatal(err)
	}
	if g.maxAge != 5*time.Minute || g.wait != 5*time.Minute || gateSkew != 60*time.Second {
		t.Fatalf("max_age %s, wait %s, skew %s; want 5m0s, 5m0s, 1m0s", g.maxAge, g.wait, gateSkew)
	}
}

// TestLoginGateHostsJoinTheEgressFence: the fenced client may reach the
// gate's issuer and relay (RED if they are left out: login could not sign in).
func TestLoginGateHostsJoinTheEgressFence(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	cfg := testConfig(t, key, "https://console.example/v1/oauth/token")
	cfg.LoginGate = &LoginGate{Issuer: "https://idm.example:8445/oauth2/openid/hush-cli", Relay: "https://auth.example/figaro/code"}
	got := cfg.EgressHosts()
	want := []string{"api.github.example:443", "auth.example:443", "console.example:443", "github.example:443", "idm.example:8445"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("egress %v, want %v", got, want)
	}
}

// TestLoginGateIsValidatedWithTheConfig: a bad [login_gate] fails the whole
// config at parse time (RED if ParseConfig stops validating it).
func TestLoginGateIsValidatedWithTheConfig(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	_, err := ParseConfig([]byte(fmt.Sprintf(`
recipient = %q
allow_user = "rou"

[instances.a]
kind = "refresh_token"
authorize_url = "https://claude.example/oauth/authorize"
token_url = "https://console.example/v1/oauth/token"
redirect_uri = "https://console.example/oauth/code/callback"
client_id = "c"

[login_gate]
issuer = "http://idm.example"
client_id = "hush-cli"
group = "hush-admin"
redirect_uri = "https://auth.example/cb"
relay = "https://auth.example/code"
`, key.Recipient().String())))
	if want := `cred config: login_gate: issuer must be an https URL, not "http://idm.example"`; err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}
