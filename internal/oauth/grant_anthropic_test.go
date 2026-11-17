package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func anthropicConfig() Config {
	return Config{Name: "anthropic-max", Grant: GrantAnthropic, TokenURL: AnthropicTokenURL, AuthorizeURL: AnthropicAuthorizeURL, ClientID: AnthropicClientID, RedirectURI: AnthropicRedirectURI, Scopes: AnthropicScopes}
}

func anthropicSeed() Tokens {
	return Tokens{AccessToken: "access-seed", RefreshToken: "refresh-seed", ExpiresIn: 28800}
}

type anthropicRouting struct {
	target *url.URL
	next   http.RoundTripper
	t      *testing.T
}

func (r anthropicRouting) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != AnthropicTokenURL {
		r.t.Errorf("token request left the pinned URL: %s", req.URL)
	}
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme, u.Host = r.target.Scheme, r.target.Host
	clone.URL = &u
	return r.next.RoundTrip(clone)
}

func anthropicEndpoint(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	client := server.Client()
	client.Transport = anthropicRouting{target, client.Transport, t}
	return client
}

func TestAnthropicGrantRefusesAnythingButThePinnedSignIn(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"token url":     func(c *Config) { c.TokenURL = "https://attacker.invalid/token" },
		"authorize url": func(c *Config) { c.AuthorizeURL = "https://attacker.invalid/authorize" },
		"client":        func(c *Config) { c.ClientID = "other" },
		"redirect":      func(c *Config) { c.RedirectURI = "http://localhost:1455/callback" },
		"scopes":        func(c *Config) { c.Scopes = "user:inference" },
		"key scope":     func(c *Config) { c.Scopes = "org:create_api_key user:profile user:inference" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := anthropicConfig()
			change(&cfg)
			if (anthropicGrant{}).Validate(cfg, anthropicSeed()) == nil {
				t.Fatal("unpinned registration accepted")
			}
			doer := &unreachableDoer{}
			if _, err := (anthropicGrant{}).Mint(context.Background(), doer, cfg, "refresh-seed"); err == nil || doer.calls != 0 {
				t.Fatalf("unpinned mint reached the network: calls %d err %v", doer.calls, err)
			}
		})
	}
	for name, tok := range map[string]Tokens{
		"no access":     {RefreshToken: "r", ExpiresIn: 60},
		"no refresh":    {AccessToken: "a", ExpiresIn: 60},
		"no lifetime":   {AccessToken: "a", RefreshToken: "r"},
		"header split":  {AccessToken: "a\r\nX: y", RefreshToken: "r", ExpiresIn: 60},
		"huge lifetime": {AccessToken: "a", RefreshToken: "r", ExpiresIn: 1 << 30},
	} {
		if (anthropicGrant{}).Validate(anthropicConfig(), tok) == nil {
			t.Fatalf("%s: unsafe token pair accepted", name)
		}
	}
	if (anthropicGrant{}).Validate(anthropicConfig(), anthropicSeed()) != nil {
		t.Fatal("pinned registration refused")
	}
}

type unreachableDoer struct{ calls int }

func (d *unreachableDoer) Do(*http.Request) (*http.Response, error) {
	d.calls++
	return nil, fmt.Errorf("network reached")
}

func TestAnthropicRefreshRotatesOneChainOncePerBurst(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	cfg := anthropicConfig()
	if err := m.Register(cfg, anthropicSeed()); err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	client := anthropicEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		n := posts.Add(1)
		r.ParseForm()
		want := "refresh-seed"
		if n > 1 {
			want = fmt.Sprintf("refresh-%d", n-1)
		}
		if r.Form.Get("refresh_token") != want || r.Form.Get("client_id") != AnthropicClientID || r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("wrong refresh request %v", r.Form)
		}
		if n == 1 {
			close(entered)
			<-release
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("access-%d", n), "refresh_token": fmt.Sprintf("refresh-%d", n), "expires_in": 28800})
	})
	m.SetHTTPClient(client)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := m.Refresh(cfg.Name); err != nil {
				t.Error(err)
			}
		})
	}
	<-entered
	close(release)
	wg.Wait()
	if posts.Load() != 1 {
		t.Fatalf("refresh raced %d times", posts.Load())
	}
	m.Stop()
	next := newTestManager(t, dir, key)
	next.SetHTTPClient(client)
	if err := next.Adopt(cfg.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Refresh(cfg.Name); err != nil {
		t.Fatal(err)
	}
	lease, err := next.Lease(cfg.Name)
	if err != nil || posts.Load() != 2 || lease.AccessToken != "access-2" {
		t.Fatalf("the restarted owner did not continue the chain: posts %d err %v", posts.Load(), err)
	}
}

func TestAnthropicRefreshKeepsTheOldRefreshTokenWhenNoneRotates(t *testing.T) {
	tok, err := (anthropicGrant{}).Mint(context.Background(), fakeDoer{status: 200, body: `{"access_token":"access-new","expires_in":3600}`}, anthropicConfig(), "refresh-seed")
	if err != nil || tok.RefreshToken != "refresh-seed" || tok.AccessToken != "access-new" {
		t.Fatalf("got %+v %v", tok, err)
	}
}

func TestAnthropicTokenFailuresAreClassifiedAndNeverEchoSecrets(t *testing.T) {
	for _, tc := range []struct {
		status    int
		body      string
		permanent bool
	}{
		{400, `{"error":"invalid_grant","error_description":"TOKEN_CANARY refresh-seed"}`, true},
		{401, `<html>TOKEN_CANARY</html>`, true},
		{429, `{"error":"rate_limit_error","error_description":"TOKEN_CANARY"}`, false},
		{503, `TOKEN_CANARY`, false},
		{200, `{"access_token":"","refresh_token":"TOKEN_CANARY"}`, true},
		{200, `TOKEN_CANARY`, false},
		{200, `{"access_token":"TOKEN_CANARY","expires_in":0}`, false},
	} {
		_, err := (anthropicGrant{}).Mint(context.Background(), fakeDoer{status: tc.status, body: tc.body}, anthropicConfig(), "refresh-seed")
		if err == nil || strings.Contains(err.Error(), "TOKEN_CANARY") || strings.Contains(err.Error(), "refresh-seed") {
			t.Fatalf("%d: unsafe or missing error %v", tc.status, err)
		}
		if got := strings.Contains(err.Error(), ErrRefreshPermanent.Error()); got != tc.permanent {
			t.Fatalf("%d %q: permanent=%v want %v", tc.status, tc.body, got, tc.permanent)
		}
	}
}

func TestAnthropicTokenRedirectDoesNotSpendRefreshAgain(t *testing.T) {
	var followed atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer foreign.Close()
	client := anthropicEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", foreign.URL+"/TOKEN_CANARY")
		w.WriteHeader(307)
	})
	_, err := (anthropicGrant{}).Mint(context.Background(), client, anthropicConfig(), "REFRESH_CANARY")
	if err == nil || followed.Load() != 0 || strings.Contains(err.Error(), "TOKEN_CANARY") || strings.Contains(err.Error(), "REFRESH_CANARY") {
		t.Fatalf("redirect not contained: followed %d err %v", followed.Load(), err)
	}
}

func TestAnthropicRefusedRefreshLatchesTheCredCommandAndLeaksNothing(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	var logs strings.Builder
	m.logger.SetOutput(&logs)
	cfg := anthropicConfig()
	if err := m.Register(cfg, anthropicSeed()); err != nil {
		t.Fatal(err)
	}
	m.SetHTTPClient(anthropicEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"refresh-seed access-seed"}`)
	}))
	_, err := m.Refresh(cfg.Name)
	if err == nil || !strings.Contains(err.Error(), "hush cred login anthropic-max") {
		t.Fatalf("relogin command not named: %v", err)
	}
	lease, _ := m.Lease(cfg.Name)
	if !lease.SignInNeeded {
		t.Fatal("refused refresh did not latch sign-in")
	}
	for _, secret := range []string{"refresh-seed", "access-seed"} {
		if strings.Contains(logs.String(), secret) || strings.Contains(err.Error(), secret) {
			t.Fatalf("%s leaked into log or error", secret)
		}
	}
	raw, _ := os.ReadFile(m.filePath(cfg.Name))
	if strings.Contains(string(raw), "refresh-seed") {
		t.Fatal("token on disk in the clear")
	}
}
