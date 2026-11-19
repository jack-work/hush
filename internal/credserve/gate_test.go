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
)

// idp is a fake OpenID provider, code relay and credential token endpoint on
// the rig's one TLS endpoint. Each case changes one thing from a good sign-in.
type idp struct {
	relay    []int          // statuses before the code (e.g. 503, 404); then 200
	relayErr string         // the relay answers {"error": relayErr}
	pending  bool           // the relay never has a code
	claims   map[string]any // overrides on a good id_token
	userinfo int            // userinfo status (default 200)
	groups   []string
	gotState string
	credPost bool // the credential's own token exchange ran
}

// gateRig returns the login, its output, and what the fake saw (read under the
// lock the handler holds, since it runs on the server's goroutines).
func gateRig(t *testing.T, p *idp) (*Login, *syncBuffer, func() (string, bool)) {
	t.Helper()
	var mu sync.Mutex
	r, l, _ := loginRig(t)
	out := &syncBuffer{}
	l.Out, l.pollEvery = out, time.Millisecond
	base := r.ep.srv.URL
	r.cfg.LoginGate = &LoginGate{Issuer: base + "/idp", ClientID: "hush-cli", Group: "hush-admin",
		RedirectURI: "https://relay.example/callback", Relay: base + "/relay", Wait: "2s"}
	if err := r.cfg.LoginGate.validate(); err != nil {
		t.Fatal(err)
	}
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
			return 200, fmt.Sprintf(`{"issuer":%[1]q,"authorization_endpoint":"%[1]s/authorize","token_endpoint":"%[1]s/token","userinfo_endpoint":"%[1]s/userinfo"}`, base+"/idp")
		case "/relay":
			p.gotState = req.URL.Query().Get("state")
			if p.pending {
				return 404, `{}`
			}
			if len(p.relay) > 0 {
				s := p.relay[0]
				p.relay = p.relay[1:]
				return s, `{}`
			}
			if p.relayErr != "" {
				return 200, fmt.Sprintf(`{"error":%q,"error_description":"no"}`, p.relayErr)
			}
			return 200, `{"code":"gate-code"}`
		case "/idp/token":
			req.ParseForm()
			if req.Form.Get("code") != "gate-code" || req.Form.Get("code_verifier") == "" {
				return 400, `{"error":"invalid_grant"}`
			}
			claims := map[string]any{"iss": base + "/idp", "aud": []string{"hush-cli"}, "nonce": gateURL(0).Get("nonce"),
				"exp": time.Now().Add(5 * time.Minute).Unix(), "auth_time": time.Now().Unix()}
			for k, v := range p.claims {
				claims[k] = v
			}
			body, _ := json.Marshal(claims)
			jws := "e30." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
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
	return l, out, func() (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		return p.gotState, p.credPost
	}
}

func TestLoginGate(t *testing.T) {
	member := []string{"idm_all_persons@idm.band.internal", "hush-admin@idm.band.internal"}
	cases := []struct {
		name string
		idp  idp
		want string // "" = the gate passes and the credential's login runs
	}{
		{"member signs in", idp{groups: member}, ""},
		{"short group name", idp{groups: []string{"hush-admin"}}, ""},
		{"relay restarts, sign-in survives", idp{groups: member, relay: []int{503, 404, 429}}, ""},
		{"not in the group", idp{groups: []string{"hush-admins@idm.band.internal"}}, "jack is not in hush-admin"},
		{"token refused by userinfo", idp{groups: member, userinfo: 401}, "userinfo 401"},
		{"stale sign-in", idp{groups: member, claims: map[string]any{"auth_time": time.Now().Add(-time.Hour).Unix()}}, "not fresh"},
		{"no auth_time", idp{groups: member, claims: map[string]any{"auth_time": 0}}, "not fresh"},
		{"another sign-in's nonce", idp{groups: member, claims: map[string]any{"nonce": "other"}}, "nonce"},
		{"token for another client", idp{groups: member, claims: map[string]any{"aud": "troupe"}}, "not for client"},
		{"another issuer", idp{groups: member, claims: map[string]any{"iss": "https://evil.example"}}, "issuer"},
		{"expired id_token", idp{groups: member, claims: map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}}, "expired"},
		{"sign-in refused at the provider", idp{relayErr: "access_denied"}, "sign-in refused: access_denied"},
		{"relay refuses the request", idp{relay: []int{400}}, "relay 400"},
		{"nobody signs in", idp{pending: true}, "no sign-in arrived"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.idp
			l, out, seen := gateRig(t, &p)
			if c.name == "nobody signs in" {
				l.Config.LoginGate.wait = 50 * time.Millisecond
			}
			err := l.Run(context.Background())
			gotState, credPost := seen()
			if c.want == "" {
				if err != nil {
					t.Fatalf("refused: %v\n%s", err, out)
				}
				if !credPost {
					t.Fatal("the gate passed but the credential's login did not run")
				}
				if gate := regexp.MustCompile(`https://\S+`).FindString(out.String()); !strings.Contains(gate, "state="+url.QueryEscape(gotState)) {
					t.Fatalf("the relay was asked for state %q, not the sign-in's", gotState)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
			if credPost {
				t.Fatal("the gate refused but the credential's login ran")
			}
		})
	}
}

func TestLoginGateAuthorizeURLForcesAFreshPasskeySignIn(t *testing.T) {
	p := idp{groups: []string{"hush-admin"}}
	l, out, _ := gateRig(t, &p)
	if err := l.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(regexp.MustCompile(`https://\S+`).FindString(out.String()))
	q := u.Query()
	for k, want := range map[string]string{"prompt": "login", "max_age": "0", "code_challenge_method": "S256",
		"client_id": "hush-cli", "response_type": "code"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == q.Get("nonce") {
		t.Errorf("challenge/nonce/state missing or reused: %v", q)
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
		{"plain http issuer", func(g *LoginGate) { g.Issuer = "http://idm.example" }, "issuer must be an https URL"},
		{"no relay", func(g *LoginGate) { g.Relay = "" }, "relay must be an https URL"},
		{"no group", func(g *LoginGate) { g.Group = "" }, "client_id and group are required"},
		{"bad max_age", func(g *LoginGate) { g.MaxAge = "soon" }, "max_age"},
		{"negative wait", func(g *LoginGate) { g.Wait = "-1s" }, "wait: must be positive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := good
			c.edit(&g)
			err := g.validate()
			if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}
