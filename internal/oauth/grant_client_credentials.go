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

// GrantClientCredentials is the OAuth 2.0 client-credentials grant
// (RFC 6749 §4.4): a MACHINE identity, with no user behind it and no
// delegated consent. The durable secret is the client secret, and every mint
// is a fresh exchange of it for a short-lived access token.
//
// Two properties distinguish it from refresh_token, and both matter:
//
//   - The durable secret is STABLE. A refresh token usually rotates, so
//     losing a write breaks the chain and lands the human back at a device
//     code. A client secret does not rotate, so there is no chain to lose:
//     minting is idempotent and a failed mint costs nothing but a retry.
//
//   - There is no refresh token in the response. RFC 6749 §4.4.3 says the
//     authorization server SHOULD NOT issue one, because the client can
//     always authenticate again. Tailscale, for instance, answers with an
//     access token good for one hour and nothing else.
//
// The consequence worth stating plainly: a client secret does not expire.
// Its safety comes from scope and revocability at the issuer, not from time,
// which is precisely why it should live in hush and be handed out only as
// the short-lived token this grant mints.
const GrantClientCredentials = "client_credentials"

// ScopeKey is the metadata key carrying the scope the authorization server
// actually GRANTED, which may be narrower than the one requested.
const ScopeKey = "scope"

func init() { registerGrant(clientCredentialsGrant{}) }

type clientCredentialsGrant struct{}

func (clientCredentialsGrant) Name() string { return GrantClientCredentials }

// MintsOnRegister is true: the client secret is the entire registration, so
// the agent can mint the first token itself. That also proves the credential
// works while a human is still watching, rather than at 3am in a timer.
func (clientCredentialsGrant) MintsOnRegister() bool { return true }

func (clientCredentialsGrant) Validate(cfg Config, tok Tokens) error {
	if cfg.TokenURL == "" {
		return errors.New("oauth: token_url is required")
	}
	if tok.RefreshToken == "" {
		return errors.New("oauth: client secret is required")
	}
	// ClientID is deliberately optional. Some providers embed the client id
	// in the secret itself (Tailscale's tskey-client-<id>-<secret>) and
	// accept the secret alone; others require the pair. Sending only what
	// we were given lets both work.
	return nil
}

// Mint exchanges the client secret for an access token.
//
// Credentials go in the form body, never the URL: a query string lands in
// server logs, proxy logs, and Referer headers, and this secret does not
// expire to limit the damage.
func (clientCredentialsGrant) Mint(ctx context.Context, doer httpDoer, cfg Config, durable string) (Tokens, error) {
	if durable == "" {
		return Tokens{}, ErrNotFound
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_secret": {durable},
	}
	if cfg.ClientID != "" {
		form.Set("client_id", cfg.ClientID)
	}
	if cfg.Scopes != "" {
		form.Set("scope", cfg.Scopes)
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
		return Tokens{}, fmt.Errorf("%w: token endpoint %d: %s",
			class, resp.StatusCode, firstLine(string(body)))
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Tokens{}, fmt.Errorf("%w: parse token response: %v", ErrRefreshTransient, err)
	}
	if parsed.AccessToken == "" {
		// A 200 with no token is the provider misbehaving, not the
		// credential dying: retrying is the right move.
		return Tokens{}, fmt.Errorf("%w: token endpoint returned empty access_token", ErrRefreshTransient)
	}

	// The GRANTED scope, which may be narrower than what was asked for.
	// Recorded so a caller can assert it got what it needed rather than
	// discovering the shortfall as a 403 halfway through a job.
	var meta map[string]string
	if parsed.Scope != "" {
		meta = map[string]string{ScopeKey: parsed.Scope}
	}

	return Tokens{
		AccessToken: parsed.AccessToken,
		// The client secret is carried forward unchanged. It is what the
		// next mint is made from, and unlike a refresh token it never
		// rotates: any refresh_token the provider sends is ignored.
		RefreshToken: durable,
		ExpiresIn:    parsed.ExpiresIn,
		Metadata:     meta,
	}, nil
}
