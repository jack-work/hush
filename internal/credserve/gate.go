//go:build linux

package credserve

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

// LoginGate, when set, makes `hush cred login` sign an administrator in at an
// OpenID provider before any credential's own login runs: authorization code
// with PKCE (S256), the code picked up from a relay by state, and membership of
// Group read from the provider's userinfo. Nothing it fetches is stored.
type LoginGate struct {
	Issuer      string `toml:"issuer"`
	ClientID    string `toml:"client_id"`
	Group       string `toml:"group"`
	RedirectURI string `toml:"redirect_uri"`
	// Relay answers GET <relay>?state=<state> with {"code"} once the sign-in
	// lands on RedirectURI, 404 while it is pending, or {"error", ...}.
	Relay string `toml:"relay"`
	// MaxAge bounds how old the provider's credential check (auth_time) may
	// be; Wait bounds how long login waits for the sign-in. Default 5m each.
	MaxAge string `toml:"max_age"`
	Wait   string `toml:"wait"`

	maxAge, wait time.Duration
}

const gateSkew = 60 * time.Second

func (g *LoginGate) validate() error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("cred config: login_gate: "+format, a...)
	}
	for key, raw := range map[string]string{"issuer": g.Issuer, "redirect_uri": g.RedirectURI, "relay": g.Relay} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fail("%s must be an https URL, not %q", key, raw)
		}
	}
	if g.ClientID == "" || g.Group == "" {
		return fail("client_id and group are required")
	}
	var err error
	if g.maxAge, err = durationOr(g.MaxAge, 5*time.Minute); err != nil {
		return fail("max_age: %v", err)
	}
	if g.wait, err = durationOr(g.Wait, 5*time.Minute); err != nil {
		return fail("wait: %v", err)
	}
	return nil
}

func durationOr(raw string, def time.Duration) (time.Duration, error) {
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err == nil && d <= 0 {
		err = errors.New("must be positive")
	}
	return d, err
}

func (g *LoginGate) egressURLs() []string { return []string{g.Issuer, g.Relay} }

// gate signs the administrator in and returns their username, or refuses.
func (l *Login) gate(ctx context.Context) (string, error) {
	g := l.Config.LoginGate
	d, err := oauth.Discover(ctx, l.Client, g.Issuer)
	if err != nil {
		return "", fmt.Errorf("login gate: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.UserinfoEndpoint == "" {
		return "", errors.New("login gate: the provider names no authorization or userinfo endpoint")
	}
	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		return "", err
	}
	state, err := loginNonce()
	if err != nil {
		return "", err
	}
	nonce, err := loginNonce()
	if err != nil {
		return "", err
	}
	// prompt=login + max_age=0: a FRESH passkey check, not a reused session.
	authorize := d.AuthorizationEndpoint + "?" + url.Values{
		"response_type": {"code"}, "client_id": {g.ClientID}, "redirect_uri": {g.RedirectURI},
		"scope": {"openid profile groups"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {pkce.Challenge}, "code_challenge_method": {"S256"},
		"prompt": {"login"}, "max_age": {"0"},
	}.Encode()
	fmt.Fprintf(l.Out, "Sign in as a member of %s within %s:\n\n  %s\n\n", g.Group, g.wait, authorize)

	code, err := l.relayCode(ctx, g, state)
	if err != nil {
		return "", fmt.Errorf("login gate: %w", err)
	}
	access, idToken, err := gateExchange(ctx, l.Client, d.TokenEndpoint, g, code, pkce.Verifier)
	if err != nil {
		return "", fmt.Errorf("login gate: %w", err)
	}
	if err := g.checkIDToken(idToken, nonce, time.Now()); err != nil {
		return "", fmt.Errorf("login gate: %w", err)
	}
	user, err := gateMember(ctx, l.Client, d.UserinfoEndpoint, access, g.Group)
	if err != nil {
		return "", fmt.Errorf("login gate: %w", err)
	}
	return user, nil
}

// relayCode polls the relay until the sign-in's code arrives. 404 is pending
// and 429 slow down; a 5xx or a transport error is the relay failing, retried
// with backoff so the pending sign-in survives a relay restart.
func (l *Login) relayCode(ctx context.Context, g *LoginGate, state string) (string, error) {
	every := l.pollEvery
	if every == 0 {
		every = time.Second
	}
	backoff := every
	deadline := time.Now().Add(g.wait)
	for time.Now().Before(deadline) {
		body, status, err := gateGet(ctx, l.Client, g.Relay+"?"+url.Values{"state": {state}}.Encode(), "")
		wait := every
		switch {
		case err != nil || status >= 500:
			backoff = min(backoff*2, 30*time.Second)
			wait = backoff
		case status == http.StatusNotFound:
		case status == http.StatusTooManyRequests:
			wait = 5 * every
		case status != http.StatusOK:
			return "", fmt.Errorf("relay %d: %s", status, oauth.EndpointDetail(body))
		default:
			var got struct {
				Code  string `json:"code"`
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			switch {
			case json.Unmarshal(body, &got) != nil:
				return "", errors.New("relay: the answer is not JSON")
			case got.Error != "":
				return "", fmt.Errorf("sign-in refused: %s: %s", got.Error, got.Desc)
			case got.Code == "":
				return "", errors.New("relay: no code in the answer")
			}
			return got.Code, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(min(wait, time.Until(deadline))):
		}
	}
	return "", errors.New("no sign-in arrived in time")
}

func gateExchange(ctx context.Context, c *http.Client, tokenURL string, g *LoginGate, code, verifier string) (access, idToken string, err error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {g.RedirectURI},
		"client_id": {g.ClientID}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token exchange %d: %s", resp.StatusCode, oauth.EndpointDetail(raw, code, verifier))
	}
	var t struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if json.Unmarshal(raw, &t) != nil || t.AccessToken == "" || t.IDToken == "" {
		return "", "", errors.New("token exchange: no access_token or id_token in the answer")
	}
	return t.AccessToken, t.IDToken, nil
}

// checkIDToken checks the claims of an ID token taken straight from the token
// endpoint over verified TLS, which OpenID Connect Core 3.1.3.7 allows in place
// of its signature. The signature is not checked; the claims are.
func (g *LoginGate) checkIDToken(token, nonce string, now time.Time) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("id_token is not a JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("id_token payload is not base64url")
	}
	var c struct {
		Iss      string          `json:"iss"`
		Aud      json.RawMessage `json:"aud"`
		Nonce    string          `json:"nonce"`
		Exp      int64           `json:"exp"`
		AuthTime int64           `json:"auth_time"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return errors.New("id_token payload is not JSON")
	}
	var aud []string
	if json.Unmarshal(c.Aud, &aud) != nil {
		var one string
		_ = json.Unmarshal(c.Aud, &one)
		aud = []string{one}
	}
	switch {
	case strings.TrimRight(c.Iss, "/") != strings.TrimRight(g.Issuer, "/"):
		return fmt.Errorf("id_token issuer %q is not %q", c.Iss, g.Issuer)
	case !contains(aud, g.ClientID):
		return fmt.Errorf("id_token is not for client %q", g.ClientID)
	case c.Nonce != nonce:
		return errors.New("id_token nonce does not match this sign-in")
	case now.After(time.Unix(c.Exp, 0).Add(gateSkew)):
		return errors.New("id_token expired")
	case c.AuthTime == 0 || now.Sub(time.Unix(c.AuthTime, 0)) > g.maxAge+gateSkew:
		return fmt.Errorf("the sign-in is not fresh (auth_time older than %s)", g.maxAge)
	}
	return nil
}

// gateMember reads userinfo with the access token and requires Group, given
// as its name or as name@domain (an SPN).
func gateMember(ctx context.Context, c *http.Client, userinfo, access, group string) (string, error) {
	body, status, err := gateGet(ctx, c, userinfo, access)
	if err != nil {
		return "", fmt.Errorf("userinfo: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("userinfo %d: the provider refused the token", status)
	}
	var u struct {
		Name   string   `json:"preferred_username"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return "", errors.New("userinfo: the answer is not JSON")
	}
	for _, g := range u.Groups {
		if g == group || strings.HasPrefix(g, group+"@") {
			return u.Name, nil
		}
	}
	return "", fmt.Errorf("%s is not in %s", u.Name, group)
}

func gateGet(ctx context.Context, c *http.Client, u, bearer string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
