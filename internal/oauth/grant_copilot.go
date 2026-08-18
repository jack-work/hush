package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GrantCopilot is GitHub Copilot's token exchange: a GitHub access token is
// presented to an internal endpoint, which answers with a session token good
// for about half an hour plus the API host to spend it at.
//
// It differs from an OAuth refresh in three ways, and only the third costs
// anything:
//
//  1. The durable secret does not rotate. The GitHub token is stable, so the
//     grant echoes it back unchanged - the same path the refresh grant
//     already takes for providers that omit refresh_token.
//  2. Expiry is absolute (expires_at), not relative. Converted here, so
//     newTokenState stays the only place lifetime arithmetic happens.
//  3. The response carries ROUTING - endpoints.api - which the caller needs
//     and which no OAuth response has. That is what Tokens.Metadata is for.
const GrantCopilot = "copilot"

// CopilotAPIBaseKey is the metadata key carrying the API host the session
// token must be spent at. Clients read it from OAuthGet.
const CopilotAPIBaseKey = "api_base"

func init() { registerGrant(copilotGrant{}) }

type copilotGrant struct{}

func (copilotGrant) Name() string { return GrantCopilot }

// MintsOnRegister: a human has only the GitHub token, so registration mints
// the first session itself - which also proves the credential works while
// someone is still watching.
func (copilotGrant) MintsOnRegister() bool { return true }

func (copilotGrant) Validate(cfg Config, tok Tokens) error {
	if cfg.TokenURL == "" {
		return errors.New("oauth: token_url is required")
	}
	if tok.RefreshToken == "" {
		return errors.New("oauth: the GitHub access token is required")
	}
	return nil
}

// copilotHeaders are what the endpoint expects from an editor plugin. They
// are not authentication; sending nothing plausible gets the request refused.
var copilotHeaders = map[string]string{
	"User-Agent":             "GitHubCopilotChat/0.35.0",
	"Editor-Version":         "vscode/1.107.0",
	"Editor-Plugin-Version":  "copilot-chat/0.35.0",
	"Copilot-Integration-Id": "vscode-chat",
	"X-GitHub-Api-Version":   "2026-06-01",
}

func (copilotGrant) Mint(ctx context.Context, doer httpDoer, cfg Config, durable string) (Tokens, error) {
	if durable == "" {
		return Tokens{}, ErrNotFound
	}

	req, err := http.NewRequestWithContext(ctx, "GET", cfg.TokenURL, nil)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: build request: %v", ErrRefreshTransient, err)
	}
	req.Header.Set("Authorization", "Bearer "+durable)
	req.Header.Set("Accept", "application/json")
	for k, v := range copilotHeaders {
		req.Header.Set(k, v)
	}

	resp, err := doer.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: %v", ErrRefreshTransient, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if class := copilotStatusClass(resp.StatusCode); class != nil {
		return Tokens{}, fmt.Errorf("%w: copilot token exchange %d: %s",
			class, resp.StatusCode, firstLine(string(body)))
	}

	var parsed struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
		Endpoints struct {
			API string `json:"api"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Tokens{}, fmt.Errorf("%w: parse exchange response: %v", ErrRefreshTransient, err)
	}
	if parsed.Token == "" {
		return Tokens{}, fmt.Errorf("%w: exchange returned an empty token", ErrRefreshTransient)
	}

	lifetime := int(time.Until(time.Unix(parsed.ExpiresAt, 0)).Seconds())
	if lifetime < 0 {
		lifetime = 0
	}

	tok := Tokens{
		AccessToken: parsed.Token,
		// The GitHub token is durable and unrotated: hand it straight back
		// so the manager persists the same secret it started with.
		RefreshToken: durable,
		ExpiresIn:    lifetime,
	}
	if api := strings.TrimRight(parsed.Endpoints.API, "/"); api != "" {
		tok.Metadata = map[string]string{CopilotAPIBaseKey: api}
	}
	return tok, nil
}

// copilotStatusClass overrides the default 4xx-is-permanent reading.
//
// This is the whole reason the classification is per-grant. GitHub answers a
// BURST on the exchange endpoint with 403 and an HTML error page - the
// "Unicorn!" page, not a JSON error - and that is a throttle, not a
// revocation. Read as permanent it stops the proactive loop forever and
// every consumer is told its credential is gone. Only 401 means the GitHub
// token itself is no longer good.
func copilotStatusClass(status int) error {
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusUnauthorized:
		return ErrRefreshPermanent
	default:
		return ErrRefreshTransient
	}
}

// firstLine keeps an error message readable when the body is a web page.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
