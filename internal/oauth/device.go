package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDC discovery and the device authorization grant (RFC 8628).
//
// Device flow is the right shape for a command-line tool: no redirect URI,
// no localhost listener, no port to bind. The user is shown a short code and
// approves it on whatever device has a browser: which is what makes it work
// over SSH, on a headless box, or from a container, none of which an
// authorization-code redirect survives.
//
// Implemented against the stdlib rather than golang.org/x/oauth2. The grant
// is a discovery document, one POST, and a poll loop with two documented
// error codes; that is not worth a new dependency in a program whose entire
// job is holding secrets.

// Discovery is the subset of an OpenID provider metadata document we use.
type Discovery struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string   `json:"device_authorization_endpoint"`
	JWKSURI                     string   `json:"jwks_uri"`
	GrantTypesSupported         []string `json:"grant_types_supported"`
	ScopesSupported             []string `json:"scopes_supported"`
}

// SupportsDeviceFlow reports whether the provider advertises the device
// grant. Presence of the endpoint is the practical signal; some providers
// omit the grant from grant_types_supported while implementing it.
func (d *Discovery) SupportsDeviceFlow() bool {
	return d.DeviceAuthorizationEndpoint != ""
}

// Discover fetches <issuer>/.well-known/openid-configuration.
//
// This is what removes the endpoint URLs from the user's hands entirely:
// naming the issuer is enough, and a provider that moves its endpoints does
// not break every stored credential.
func Discover(ctx context.Context, doer httpDoer, issuer string) (*Discovery, error) {
	base := strings.TrimRight(issuer, "/")
	u := base + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover %s: HTTP %d", u, resp.StatusCode)
	}

	var d Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("discover %s: %w", u, err)
	}
	if d.TokenEndpoint == "" {
		return nil, fmt.Errorf("discover %s: no token_endpoint in metadata", u)
	}
	// The issuer in the document is authoritative and must match what we
	// asked for: a mismatch means the document was served by someone else.
	if d.Issuer != "" && strings.TrimRight(d.Issuer, "/") != base {
		return nil, fmt.Errorf("discovery issuer %q does not match %q", d.Issuer, base)
	}
	return &d, nil
}

// DeviceAuth is the provider's response to a device authorization request.
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	// Expires is the absolute deadline, fixed when the code was ISSUED.
	// Computing it from time.Now() on each call would silently extend the
	// window every time it was consulted, so a code could never expire.
	Expires time.Time `json:"-"`
}

// Expiry is when the device code stops being usable.
func (d *DeviceAuth) Expiry() time.Time {
	if !d.Expires.IsZero() {
		return d.Expires
	}
	if d.ExpiresIn <= 0 {
		return time.Now().Add(10 * time.Minute)
	}
	return time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
}

// PollInterval is the provider's requested gap between token polls.
func (d *DeviceAuth) PollInterval() time.Duration {
	if d.Interval <= 0 {
		return 5 * time.Second
	}
	return time.Duration(d.Interval) * time.Second
}

// RequestDeviceCode begins the device authorization grant.
func RequestDeviceCode(ctx context.Context, doer httpDoer, endpoint, clientID, scopes string) (*DeviceAuth, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	if scopes != "" {
		form.Set("scope", scopes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e oauthError
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Err == "" {
			return nil, fmt.Errorf("device authorization: HTTP %d", resp.StatusCode)
		}
		// An unknown client_id yields a flat 400 that reads like a malformed
		// request, so say what it usually means.
		if e.Err == "invalid_client" || e.Err == "invalid_request" {
			return nil, fmt.Errorf("device authorization refused (%s: %s), "+
				"is %q registered at this issuer, with the device_code grant enabled?",
				e.Err, e.Desc, clientID)
		}
		return nil, fmt.Errorf("device authorization: %s: %s", e.Err, e.Desc)
	}

	var da DeviceAuth
	if err := json.NewDecoder(resp.Body).Decode(&da); err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}
	if da.DeviceCode == "" || da.UserCode == "" {
		return nil, fmt.Errorf("device authorization: provider returned no device/user code")
	}
	// Pin the deadline now, while "now" is when the code was issued.
	if da.ExpiresIn > 0 {
		da.Expires = time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	} else {
		da.Expires = time.Now().Add(10 * time.Minute)
	}
	return &da, nil
}

type oauthError struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

// PollDeviceToken polls the token endpoint until the user approves, the code
// expires, or ctx is cancelled.
//
// The poll fires IMMEDIATELY and then waits, rather than sleeping first: a
// user who approves instantly should not pay a fixed interval for the
// privilege.
//
// RFC 8628 defines the two errors that are not failures: authorization_pending
// (keep waiting) and slow_down (keep waiting, but back off). Everything else
// is terminal.
func PollDeviceToken(ctx context.Context, doer httpDoer, tokenEndpoint, clientID string, da *DeviceAuth) (Tokens, error) {
	interval := da.PollInterval()
	deadline := da.Expiry()

	for {
		if time.Now().After(deadline) {
			return Tokens{}, fmt.Errorf("device code expired before it was approved")
		}

		tok, err := exchangeDeviceCode(ctx, doer, tokenEndpoint, clientID, da.DeviceCode)
		switch {
		case err == nil:
			return tok, nil
		case isPending(err):
			// keep waiting
		case isSlowDown(err):
			interval += 5 * time.Second
		default:
			return Tokens{}, err
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Tokens{}, ctx.Err()
		case <-timer.C:
		}
	}
}

type deviceGrantError struct{ code, desc string }

func (e *deviceGrantError) Error() string {
	if e.desc == "" {
		return e.code
	}
	return e.code + ": " + e.desc
}

func isPending(err error) bool  { return grantErrCode(err) == "authorization_pending" }
func isSlowDown(err error) bool { return grantErrCode(err) == "slow_down" }

func grantErrCode(err error) string {
	if e, ok := err.(*deviceGrantError); ok {
		return e.code
	}
	return ""
}

func exchangeDeviceCode(ctx context.Context, doer httpDoer, endpoint, clientID, deviceCode string) (Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", deviceCode)
	form.Set("client_id", clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := doer.Do(req)
	if err != nil {
		return Tokens{}, err
	}
	defer resp.Body.Close()

	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Tokens{}, fmt.Errorf("token endpoint: HTTP %d: %w", resp.StatusCode, err)
	}
	if body.Error != "" {
		return Tokens{}, &deviceGrantError{code: body.Error, desc: body.ErrorDesc}
	}
	if resp.StatusCode != http.StatusOK {
		return Tokens{}, fmt.Errorf("token endpoint: HTTP %d", resp.StatusCode)
	}
	if body.AccessToken == "" {
		return Tokens{}, fmt.Errorf("token endpoint returned no access_token")
	}

	return Tokens{
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		ExpiresIn:    body.ExpiresIn,
	}, nil
}
