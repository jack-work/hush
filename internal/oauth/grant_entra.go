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

const GrantEntra = "entra"

var entraHosts = map[string]bool{
	"login.microsoftonline.com":        true,
	"login.microsoftonline.us":         true,
	"login.partner.microsoftonline.cn": true,
}

func init() { registerGrant(entraGrant{}) }

type entraGrant struct{}

func (entraGrant) Name() string { return GrantEntra }

func (entraGrant) MintsOnRegister() bool { return false }

func (entraGrant) Validate(cfg Config, tok Tokens) error {
	if err := entraEndpoint(cfg.TokenURL); err != nil {
		return err
	}
	if cfg.ClientID == "" {
		return errors.New("oauth: entra: client_id is required")
	}
	if strings.TrimSpace(cfg.Scopes) == "" {
		return errors.New("oauth: entra: scopes are required: they name the resource every refreshed token is for")
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		return errors.New("oauth: entra: access and refresh tokens are both required (request offline_access)")
	}
	return nil
}

func entraEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !entraHosts[u.Host] {
		return fmt.Errorf("oauth: entra: token_url %q is not a Microsoft identity platform endpoint (https://login.microsoftonline.com/...)", raw)
	}
	return nil
}

func (entraGrant) Mint(ctx context.Context, doer httpDoer, cfg Config, durable string) (Tokens, error) {
	if durable == "" {
		return Tokens{}, ErrNotFound
	}
	if err := entraEndpoint(cfg.TokenURL); err != nil {
		return Tokens{}, fmt.Errorf("%w: %v", ErrRefreshPermanent, err)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {cfg.ClientID},
		"refresh_token": {durable},
		"scope":         {cfg.Scopes},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
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

	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &parsed)
	if resp.StatusCode != http.StatusOK {
		detail := parsed.Error
		if parsed.Description != "" {
			detail += ": " + firstLine(parsed.Description)
		}
		if detail == "" {
			detail = firstLine(string(body))
		}
		return Tokens{}, fmt.Errorf("%w: entra token endpoint %d: %s", entraClass(resp.StatusCode, parsed.Error), resp.StatusCode, detail)
	}
	if parsed.AccessToken == "" {
		return Tokens{}, fmt.Errorf("%w: entra token endpoint returned no access_token", ErrRefreshPermanent)
	}
	if parsed.RefreshToken == "" {
		parsed.RefreshToken = durable
	}
	return Tokens{AccessToken: parsed.AccessToken, RefreshToken: parsed.RefreshToken, ExpiresIn: parsed.ExpiresIn}, nil
}

func entraClass(status int, code string) error {
	switch {
	case status >= 500, status == http.StatusTooManyRequests, code == "temporarily_unavailable":
		return ErrRefreshTransient
	default:
		return ErrRefreshPermanent
	}
}
