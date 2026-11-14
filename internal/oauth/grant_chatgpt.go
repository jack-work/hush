package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const GrantChatGPT = "chatgpt"
const ChatGPTTokenURL = "https://auth.openai.com/oauth/token"
const ChatGPTAuthorizeURL = "https://auth.openai.com/oauth/authorize"
const ChatGPTClientID = "app_EMoamEEZ73f0CkXaXp7hrann"
const ChatGPTRedirectURI = "http://localhost:1455/auth/callback"
const ChatGPTScopes = "openid profile email offline_access"

var accountIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func ValidAccountID(s string) bool { return accountIDPattern.MatchString(s) }

type chatGPTGrant struct{}

func init()                                { registerGrant(chatGPTGrant{}) }
func (chatGPTGrant) Name() string          { return GrantChatGPT }
func (chatGPTGrant) MintsOnRegister() bool { return false }
func (chatGPTGrant) Validate(cfg Config, tok Tokens) error {
	if cfg.TokenURL != ChatGPTTokenURL || cfg.ClientID != ChatGPTClientID || cfg.AuthorizeURL != ChatGPTAuthorizeURL || cfg.RedirectURI != ChatGPTRedirectURI {
		return fmt.Errorf("chatgpt: OAuth endpoints and client must be pinned")
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || !ValidAccountID(tok.Metadata["account_id"]) || tok.ExpiresIn <= 0 {
		return fmt.Errorf("chatgpt: complete token and account tuple required")
	}
	claims, err := chatGPTClaims(tok.AccessToken)
	if err != nil || claims.AccountID != tok.Metadata["account_id"] {
		return fmt.Errorf("chatgpt: token account metadata mismatch")
	}
	return nil
}
func (chatGPTGrant) Mint(ctx context.Context, doer httpDoer, cfg Config, durable string) (Tokens, error) {
	if cfg.TokenURL != ChatGPTTokenURL || cfg.ClientID != ChatGPTClientID || durable == "" {
		return Tokens{}, fmt.Errorf("%w: invalid ChatGPT credential configuration", ErrRefreshPermanent)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {ChatGPTClientID}, "refresh_token": {durable}}
	return chatGPTTokenRequest(ctx, doer, form, durable)
}

type chatGPTIdentity struct {
	AccountID string
	ExpiresAt int64
}

func chatGPTClaims(token string) (chatGPTIdentity, error) {
	parts := strings.Split(token, ".")
	if len(token) > 16384 || len(parts) != 3 || len(parts[1]) > 64<<10 || strings.IndexFunc(token, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.')
	}) >= 0 {
		return chatGPTIdentity{}, fmt.Errorf("chatgpt: invalid access token claims")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return chatGPTIdentity{}, fmt.Errorf("chatgpt: invalid access token claims")
	}
	var doc struct {
		Exp  int64 `json:"exp"`
		Auth struct {
			AccountID string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(raw, &doc) != nil || !ValidAccountID(doc.Auth.AccountID) || doc.Exp <= 0 {
		return chatGPTIdentity{}, fmt.Errorf("chatgpt: missing access token account or expiry")
	}
	return chatGPTIdentity{AccountID: doc.Auth.AccountID, ExpiresAt: doc.Exp}, nil
}

func chatGPTTokenRequest(ctx context.Context, doer httpDoer, form url.Values, previous string) (Tokens, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ChatGPTTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: cannot build ChatGPT request", ErrRefreshTransient)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if client, ok := doer.(*http.Client); ok {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		doer = &copy
	}
	resp, err := doer.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: ChatGPT token service unreachable", ErrRefreshTransient)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return Tokens{}, fmt.Errorf("%w: invalid ChatGPT token response", ErrRefreshTransient)
	}
	if resp.StatusCode != http.StatusOK {
		class := ErrRefreshPermanent
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			class = ErrRefreshTransient
		}
		return Tokens{}, fmt.Errorf("%w: ChatGPT token request refused (HTTP %d)", class, resp.StatusCode)
	}
	var doc struct {
		Access    string `json:"access_token"`
		Refresh   string `json:"refresh_token"`
		ID        string `json:"id_token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Access == "" {
		return Tokens{}, fmt.Errorf("%w: incomplete ChatGPT token response", ErrRefreshPermanent)
	}
	claims, err := chatGPTClaims(doc.Access)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: invalid ChatGPT access token", ErrRefreshPermanent)
	}
	if doc.ID != "" {
		identity, err := chatGPTClaims(doc.ID)
		if err != nil || identity.AccountID != claims.AccountID {
			return Tokens{}, fmt.Errorf("%w: ChatGPT identity mismatch", ErrRefreshPermanent)
		}
	}
	lifetime := int(time.Until(time.Unix(claims.ExpiresAt, 0)).Seconds())
	if doc.ExpiresIn > 0 && doc.ExpiresIn < lifetime {
		lifetime = doc.ExpiresIn
	}
	if lifetime <= 0 {
		return Tokens{}, fmt.Errorf("%w: expired ChatGPT access token", ErrRefreshPermanent)
	}
	if doc.Refresh == "" {
		doc.Refresh = previous
	}
	if doc.Refresh == "" {
		return Tokens{}, fmt.Errorf("%w: missing ChatGPT refresh token", ErrRefreshPermanent)
	}
	return Tokens{AccessToken: doc.Access, RefreshToken: doc.Refresh, ExpiresIn: lifetime, Metadata: map[string]string{"account_id": claims.AccountID}}, nil
}

func ExchangeChatGPTCode(ctx context.Context, c *http.Client, code, verifier string) (Tokens, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {ChatGPTClientID}, "code": {code}, "redirect_uri": {ChatGPTRedirectURI}, "code_verifier": {verifier}}
	return chatGPTTokenRequest(ctx, c, form, "")
}
