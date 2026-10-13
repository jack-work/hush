package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The Entra grant is a refresh_token grant with two differences that matter:
// the scope travels on every refresh (an Entra refresh token can mint for any
// resource the user consented to, so the resource must be named each time or
// the token that comes back may not be for Cognitive Services), and the
// endpoint is pinned to Microsoft's hosts, because a grant that would POST a
// stored refresh token to any URL a file names is the exfiltration primitive
// grant.go refuses to be.

const entraToken = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
const entraScope = "https://cognitiveservices.azure.com/.default offline_access"

type recordingDoer struct {
	status int
	body   string
	got    *http.Request
	form   url.Values
}

func (d *recordingDoer) Do(r *http.Request) (*http.Response, error) {
	d.got = r
	raw, _ := io.ReadAll(r.Body)
	d.form, _ = url.ParseQuery(string(raw))
	return &http.Response{
		StatusCode: d.status,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     http.Header{},
	}, nil
}

func entraConfig() Config {
	return Config{Name: "azure", Grant: GrantEntra, TokenURL: entraToken, ClientID: "04b07795-8ddb-461a-bbee-02f9e1bf7b46", Scopes: entraScope}
}

func TestEntraRefreshSendsTheScope(t *testing.T) {
	d := &recordingDoer{status: 200, body: `{"token_type":"Bearer","scope":"https://cognitiveservices.azure.com/.default","expires_in":4532,"ext_expires_in":4532,"access_token":"A2","refresh_token":"R2"}`}
	tok, err := entraGrant{}.Mint(context.Background(), d, entraConfig(), "R1")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if d.got.Method != http.MethodPost || d.got.URL.String() != entraToken {
		t.Fatalf("request = %s %s", d.got.Method, d.got.URL)
	}
	if ct := d.got.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q: Entra refuses anything but a form", ct)
	}
	want := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
		"refresh_token": "R1",
		"scope":         entraScope,
	}
	for k, v := range want {
		if d.form.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, d.form.Get(k), v)
		}
	}
	if tok.AccessToken != "A2" || tok.RefreshToken != "R2" || tok.ExpiresIn != 4532 {
		t.Fatalf("tokens = %+v: Entra rotates the refresh token and the new one must be kept", tok)
	}
}

func TestEntraRefreshKeepsTheOldTokenWhenNoneComesBack(t *testing.T) {
	d := &recordingDoer{status: 200, body: `{"access_token":"A2","expires_in":3600}`}
	tok, err := entraGrant{}.Mint(context.Background(), d, entraConfig(), "R1")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.RefreshToken != "R1" {
		t.Fatalf("refresh = %q: losing the durable secret means a forced re-login", tok.RefreshToken)
	}
}

func TestEntraRefreshClassifiesFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"revoked or expired", 400, `{"error":"invalid_grant","error_description":"AADSTS70008: The provided authorization code or refresh token has expired due to inactivity.","error_codes":[70008]}`, ErrRefreshPermanent},
		{"needs interaction", 400, `{"error":"interaction_required","error_description":"AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication.","error_codes":[50076]}`, ErrRefreshPermanent},
		{"bad client", 401, `{"error":"invalid_client","error_description":"AADSTS7000218: The request body must contain client_assertion or client_secret."}`, ErrRefreshPermanent},
		{"temporarily unavailable", 400, `{"error":"temporarily_unavailable","error_description":"AADSTS50196: The server terminated an operation because it encountered a client request loop."}`, ErrRefreshTransient},
		{"throttled", 429, `{"error":"too_many_requests"}`, ErrRefreshTransient},
		{"server error", 503, `<html>Service Unavailable</html>`, ErrRefreshTransient},
	}
	for _, c := range cases {
		d := &recordingDoer{status: c.status, body: c.body}
		_, err := entraGrant{}.Mint(context.Background(), d, entraConfig(), "R1")
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if c.want == ErrRefreshPermanent && strings.Contains(c.body, "AADSTS") && !strings.Contains(err.Error(), "AADSTS") {
			t.Errorf("%s: the AADSTS code was dropped from %q; it is the whole diagnosis", c.name, err)
		}
	}
}

func TestEntraRefusesATokenURLOffMicrosoftsHosts(t *testing.T) {
	tok := Tokens{AccessToken: "A", RefreshToken: "R"}
	ok := []string{
		entraToken,
		"https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",
		"https://login.microsoftonline.us/organizations/oauth2/v2.0/token",
		"https://login.partner.microsoftonline.cn/organizations/oauth2/v2.0/token",
	}
	for _, u := range ok {
		cfg := entraConfig()
		cfg.TokenURL = u
		if err := (entraGrant{}).Validate(cfg, tok); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	bad := []string{
		"http://login.microsoftonline.com/organizations/oauth2/v2.0/token",
		"https://login.microsoftonline.com.evil.example/oauth2/v2.0/token",
		"https://evil.example/login.microsoftonline.com/oauth2/v2.0/token",
		"",
	}
	for _, u := range bad {
		cfg := entraConfig()
		cfg.TokenURL = u
		if err := (entraGrant{}).Validate(cfg, tok); err == nil {
			t.Errorf("%q accepted: a stored refresh token would be posted there", u)
		}
		d := &recordingDoer{status: 200, body: `{"access_token":"A"}`}
		if _, err := (entraGrant{}).Mint(context.Background(), d, cfg, "R1"); !errors.Is(err, ErrRefreshPermanent) || d.got != nil {
			t.Errorf("%q: Mint sent the refresh token anyway (err %v)", u, err)
		}
	}
}

func TestEntraValidateNeedsWhatARefreshNeeds(t *testing.T) {
	full := Tokens{AccessToken: "A", RefreshToken: "R"}
	for name, mutate := range map[string]func(*Config, *Tokens){
		"client_id":     func(c *Config, _ *Tokens) { c.ClientID = "" },
		"scopes":        func(c *Config, _ *Tokens) { c.Scopes = "  " },
		"refresh_token": func(_ *Config, t *Tokens) { t.RefreshToken = "" },
		"access_token":  func(_ *Config, t *Tokens) { t.AccessToken = "" },
	} {
		cfg, tok := entraConfig(), full
		mutate(&cfg, &tok)
		if err := (entraGrant{}).Validate(cfg, tok); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
	if (entraGrant{}).MintsOnRegister() {
		t.Error("the first tokens come from the device flow; registration must not mint")
	}
}

func TestEntraRegistersAndRefreshesThroughTheManager(t *testing.T) {
	m := newGrantManager(t)
	d := &recordingDoer{status: 200, body: `{"access_token":"A2","refresh_token":"R2","expires_in":3600}`}
	m.httpClient = d
	if err := m.Register(entraConfig(), Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := GrantNames(); !strings.Contains(strings.Join(got, ","), GrantEntra) {
		t.Fatalf("grants = %v", got)
	}
	st := m.configs["azure"]
	if st == nil {
		t.Fatal("not installed")
	}
	tok, err := m.doRefresh(st)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok != "A2" || d.form.Get("scope") != entraScope {
		t.Fatalf("token %q, scope %q", tok, d.form.Get("scope"))
	}
}
