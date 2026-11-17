package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const GrantAnthropic = "anthropic"
const AnthropicAuthorizeURL = "https://claude.ai/oauth/authorize"
const AnthropicTokenURL = "https://console.anthropic.com/v1/oauth/token"
const AnthropicClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
const AnthropicRedirectURI = "https://console.anthropic.com/oauth/code/callback"
const AnthropicScopes = "org:create_api_key user:profile user:inference"

const maxAnthropicLifetime = 366 * 24 * 60 * 60

func AnthropicPinned(cfg Config) bool {
	return cfg.TokenURL == AnthropicTokenURL && cfg.ClientID == AnthropicClientID && cfg.AuthorizeURL == AnthropicAuthorizeURL && cfg.RedirectURI == AnthropicRedirectURI && cfg.Scopes == AnthropicScopes
}

func validAnthropicToken(s string) bool {
	if len(s) == 0 || len(s) > 16384 {
		return false
	}
	for _, c := range []byte(s) {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

type anthropicGrant struct{}

func init()                                  { registerGrant(anthropicGrant{}) }
func (anthropicGrant) Name() string          { return GrantAnthropic }
func (anthropicGrant) MintsOnRegister() bool { return false }

func (anthropicGrant) Validate(cfg Config, tok Tokens) error {
	if !AnthropicPinned(cfg) {
		return fmt.Errorf("anthropic: OAuth endpoints, client, callback and scopes must be pinned")
	}
	if !validAnthropicToken(tok.AccessToken) || !validAnthropicToken(tok.RefreshToken) || tok.ExpiresIn <= 0 || tok.ExpiresIn > maxAnthropicLifetime {
		return fmt.Errorf("anthropic: complete token pair required")
	}
	return nil
}

func (anthropicGrant) Mint(ctx context.Context, doer httpDoer, cfg Config, durable string) (Tokens, error) {
	if !AnthropicPinned(cfg) || durable == "" {
		return Tokens{}, fmt.Errorf("%w: invalid Anthropic credential configuration", ErrRefreshPermanent)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {AnthropicClientID}, "refresh_token": {durable}}
	return anthropicTokenRequest(ctx, doer, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), durable)
}

func anthropicTokenRequest(ctx context.Context, doer httpDoer, contentType string, body io.Reader, previous string) (Tokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, AnthropicTokenURL, body)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: cannot build Anthropic request", ErrRefreshTransient)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	if client, ok := doer.(*http.Client); ok {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		doer = &copy
	}
	resp, err := doer.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: Anthropic token service unreachable", ErrRefreshTransient)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return Tokens{}, fmt.Errorf("%w: invalid Anthropic token response", ErrRefreshTransient)
	}
	if resp.StatusCode != http.StatusOK {
		class := ErrRefreshPermanent
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			class = ErrRefreshTransient
		}
		return Tokens{}, fmt.Errorf("%w: Anthropic token request refused (HTTP %d)", class, resp.StatusCode)
	}
	var doc struct {
		Access    string `json:"access_token"`
		Refresh   string `json:"refresh_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return Tokens{}, fmt.Errorf("%w: invalid Anthropic token response", ErrRefreshTransient)
	}
	if doc.Access == "" {
		return Tokens{}, fmt.Errorf("%w: incomplete Anthropic token response", ErrRefreshPermanent)
	}
	if doc.Refresh == "" {
		doc.Refresh = previous
	}
	if doc.Refresh == "" {
		return Tokens{}, fmt.Errorf("%w: missing Anthropic refresh token", ErrRefreshPermanent)
	}
	if !validAnthropicToken(doc.Access) || !validAnthropicToken(doc.Refresh) || doc.ExpiresIn <= 0 || doc.ExpiresIn > maxAnthropicLifetime {
		return Tokens{}, fmt.Errorf("%w: invalid Anthropic token response", ErrRefreshTransient)
	}
	return Tokens{AccessToken: doc.Access, RefreshToken: doc.Refresh, ExpiresIn: doc.ExpiresIn}, nil
}
