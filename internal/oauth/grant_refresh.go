package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// GrantRefreshToken is the OAuth 2.0 refresh-token grant: the durable secret
// is a refresh token, and using it usually rotates it.
const GrantRefreshToken = "refresh_token"

func init() { registerGrant(refreshTokenGrant{}) }

type refreshTokenGrant struct{}

func (refreshTokenGrant) Name() string { return GrantRefreshToken }

func (refreshTokenGrant) MintsOnRegister() bool { return false }

func (refreshTokenGrant) Validate(cfg Config, tok Tokens) error {
	if cfg.TokenURL == "" {
		return errors.New("oauth: token_url is required")
	}
	if cfg.ClientID == "" {
		return errors.New("oauth: client_id is required")
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		return errors.New("oauth: access and refresh tokens are both required")
	}
	return nil
}

// Mint makes the token-endpoint POST. RFC 6749 §4.5 mandates
// application/x-www-form-urlencoded; some providers (Anthropic) happen to
// accept JSON too, but the canonical spec-compliant form works for everyone
// including strict implementations like Authelia's OIDC.
func (refreshTokenGrant) Mint(ctx context.Context, doer httpDoer, cfg Config, durable string) (Tokens, error) {
	if durable == "" {
		return Tokens{}, ErrNotFound
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {cfg.ClientID},
		"refresh_token": {durable},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: build request: %v", ErrRefreshTransient, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := doer.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: %v", ErrRefreshTransient, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if class := httpStatusClass(resp.StatusCode); class != nil {
		return Tokens{}, fmt.Errorf("%w: token endpoint %d: %s", class, resp.StatusCode, string(body))
	}

	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Tokens{}, fmt.Errorf("%w: parse token response: %v", ErrRefreshTransient, err)
	}
	if parsed.AccessToken == "" {
		return Tokens{}, fmt.Errorf("%w: token endpoint returned empty access_token", ErrRefreshPermanent)
	}
	// Some providers omit refresh_token on refresh (no rotation). Keep the
	// old one.
	if parsed.RefreshToken == "" {
		parsed.RefreshToken = durable
	}
	return Tokens{
		AccessToken:  parsed.AccessToken,
		RefreshToken: parsed.RefreshToken,
		ExpiresIn:    parsed.ExpiresIn,
	}, nil
}
