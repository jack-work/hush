package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// tailscale-shaped client secret: tskey-client-<clientID>-<secret>
const tsSecret = "tskey-client-kABC123CNTRL-0123456789ABCDEF"

// capture records what the token endpoint received.
type capture struct {
	form        url.Values
	contentType string
	rawQuery    string
}

func ccServer(t *testing.T, status int, body string) (*httptest.Server, *capture) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		cap.form, _ = url.ParseQuery(string(raw))
		cap.contentType = r.Header.Get("Content-Type")
		cap.rawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func ccMint(t *testing.T, cfg Config, durable string) (Tokens, error) {
	t.Helper()
	return clientCredentialsGrant{}.Mint(context.Background(), http.DefaultClient, cfg, durable)
}

// The happy path, shaped exactly like Tailscale's documented response.
func TestClientCredentialsMint(t *testing.T) {
	srv, cap := ccServer(t, 200,
		`{"access_token":"tskey-0123456789ABCDEF","token_type":"Bearer","expires_in":3600,"scope":"devices:read"}`)

	tok, err := ccMint(t, Config{
		TokenURL: srv.URL,
		ClientID: "kABC123CNTRL",
		Scopes:   "devices:read",
	}, tsSecret)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if tok.AccessToken != "tskey-0123456789ABCDEF" {
		t.Errorf("access token = %q", tok.AccessToken)
	}
	if tok.ExpiresIn != 3600 {
		t.Errorf("expires_in = %d, want 3600", tok.ExpiresIn)
	}
	// The durable secret is stable: it must be carried forward so the next
	// mint has something to make a token from.
	if tok.RefreshToken != tsSecret {
		t.Errorf("durable secret was not carried forward: %q", tok.RefreshToken)
	}
	if tok.Metadata[ScopeKey] != "devices:read" {
		t.Errorf("granted scope not recorded: %v", tok.Metadata)
	}

	if got := cap.form.Get("grant_type"); got != "client_credentials" {
		t.Errorf("grant_type = %q", got)
	}
	if got := cap.form.Get("client_secret"); got != tsSecret {
		t.Errorf("client_secret not sent")
	}
	if got := cap.form.Get("client_id"); got != "kABC123CNTRL" {
		t.Errorf("client_id = %q", got)
	}
	if got := cap.form.Get("scope"); got != "devices:read" {
		t.Errorf("scope = %q", got)
	}
	if !strings.HasPrefix(cap.contentType, "application/x-www-form-urlencoded") {
		t.Errorf("content-type = %q; RFC 6749 mandates form encoding", cap.contentType)
	}
}

// The secret must never reach the query string: URLs land in server logs,
// proxy logs and Referer headers, and this credential does not expire.
func TestClientCredentialsSecretNeverInURL(t *testing.T) {
	srv, cap := ccServer(t, 200, `{"access_token":"a","expires_in":3600}`)
	if _, err := ccMint(t, Config{TokenURL: srv.URL, ClientID: "k1"}, tsSecret); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cap.rawQuery, tsSecret) || strings.Contains(cap.rawQuery, "client_secret") {
		t.Errorf("credential leaked into the query string: %q", cap.rawQuery)
	}
}

// Providers that embed the client id in the secret accept the secret alone;
// omitting client_id must not send an empty one.
func TestClientCredentialsOmitsEmptyOptionalFields(t *testing.T) {
	srv, cap := ccServer(t, 200, `{"access_token":"a","expires_in":3600}`)
	if _, err := ccMint(t, Config{TokenURL: srv.URL}, tsSecret); err != nil {
		t.Fatal(err)
	}
	if _, present := cap.form["client_id"]; present {
		t.Error("client_id sent when unset")
	}
	if _, present := cap.form["scope"]; present {
		t.Error("scope sent when unset")
	}
}

// A refresh token in the response is ignored: RFC 6749 §4.4.3 says the
// server should not issue one, and the client secret is what mints next.
func TestClientCredentialsIgnoresReturnedRefreshToken(t *testing.T) {
	srv, _ := ccServer(t, 200,
		`{"access_token":"a","refresh_token":"SHOULD-BE-IGNORED","expires_in":3600}`)
	tok, err := ccMint(t, Config{TokenURL: srv.URL}, tsSecret)
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != tsSecret {
		t.Errorf("durable secret replaced by the response: %q", tok.RefreshToken)
	}
}

// Error classification decides whether the proactive loop retries forever or
// gives up forever. Getting it wrong is expensive in both directions.
func TestClientCredentialsErrorClassification(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"bad secret", 401, `{"error":"invalid_client"}`, ErrRefreshPermanent},
		{"bad scope", 400, `{"error":"invalid_scope"}`, ErrRefreshPermanent},
		{"forbidden", 403, `{"error":"insufficient_scope"}`, ErrRefreshPermanent},
		{"server down", 500, `oops`, ErrRefreshTransient},
		{"rate limited", 503, `busy`, ErrRefreshTransient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := ccServer(t, c.status, c.body)
			_, err := ccMint(t, Config{TokenURL: srv.URL}, tsSecret)
			if !errors.Is(err, c.want) {
				t.Errorf("status %d classified as %v, want %v", c.status, err, c.want)
			}
		})
	}
}

// A 200 with no token is the provider misbehaving, not the credential
// dying: retrying is right, giving up permanently is not.
func TestClientCredentialsEmptyTokenIsTransient(t *testing.T) {
	srv, _ := ccServer(t, 200, `{"expires_in":3600}`)
	_, err := ccMint(t, Config{TokenURL: srv.URL}, tsSecret)
	if !errors.Is(err, ErrRefreshTransient) {
		t.Errorf("empty access_token gave %v, want transient", err)
	}
}

func TestClientCredentialsMissingSecretIsNotFound(t *testing.T) {
	_, err := ccMint(t, Config{TokenURL: "http://unused.invalid"}, "")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("empty durable gave %v, want ErrNotFound", err)
	}
}

func TestClientCredentialsValidate(t *testing.T) {
	g := clientCredentialsGrant{}
	if err := g.Validate(Config{}, Tokens{RefreshToken: tsSecret}); err == nil {
		t.Error("missing token_url should be rejected")
	}
	if err := g.Validate(Config{TokenURL: "https://x"}, Tokens{}); err == nil {
		t.Error("missing client secret should be rejected")
	}
	// No client id, no access token, no expiry: a valid registration.
	if err := g.Validate(Config{TokenURL: "https://x"}, Tokens{RefreshToken: tsSecret}); err != nil {
		t.Errorf("minimal registration rejected: %v", err)
	}
}

func TestClientCredentialsRegisteredAndMintsOnRegister(t *testing.T) {
	if !MintsOnRegister(GrantClientCredentials) {
		t.Error("client_credentials must mint on register: the secret is the whole registration")
	}
	if MintsOnRegister(GrantRefreshToken) {
		t.Error("refresh_token does not mint on register")
	}
	if MintsOnRegister("no-such-grant") {
		t.Error("unknown grant must not claim to mint")
	}
	var found bool
	for _, n := range GrantNames() {
		if n == GrantClientCredentials {
			found = true
		}
	}
	if !found {
		t.Errorf("grant not registered; have %v", GrantNames())
	}
}
