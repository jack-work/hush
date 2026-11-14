//go:build linux

package credserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/jack-work/hush/internal/oauth"
)

type Login struct {
	Config   *Config
	StateDir string
	Name     string
	Replace  bool
	Client   *http.Client
	ReadCode func(prompt string) (string, error)
	Out      io.Writer
}

func (l *Login) Run(ctx context.Context) error {
	in, ok := l.Config.Instances[l.Name]
	if !ok {
		return fmt.Errorf("no instance %q in the cred config", l.Name)
	}
	if err := l.checkStateDir(); err != nil {
		return err
	}
	if err := l.checkExisting(); err != nil {
		return err
	}

	var tok oauth.Tokens
	var err error
	switch in.Kind {
	case KindAnthropic:
		tok, err = l.anthropic(ctx, in)
	case KindCopilot:
		tok, err = l.copilot(ctx, in)
	}
	if err != nil {
		return err
	}

	mgr := oauth.NewManager(l.StateDir, nil, l.Config.RecipientKey(), discardLogger())
	mgr.SetHTTPClient(l.Client)
	defer mgr.Stop()
	if err := mgr.Register(in.OAuthConfig(l.Name), tok); err != nil {
		return err
	}
	fmt.Fprintf(l.Out, "signed in %s; hush cred serve picks it up on its next request for it\n", l.Name)
	return nil
}

func (l *Login) checkStateDir() error {
	fi, err := os.Stat(l.StateDir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s belongs to uid %d: run login as that user, so the server can read what it writes", l.StateDir, st.Uid)
	}
	return nil
}

func (l *Login) checkExisting() error {
	data, err := os.ReadFile(filepath.Join(l.StateDir, "oauth", l.Name+".toml"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var mark struct {
		Relogin string `toml:"relogin_required"`
	}
	_, _ = toml.Decode(string(data), &mark)
	if mark.Relogin != "" || l.Replace {
		return nil
	}
	return fmt.Errorf("%s is signed in and not marked sign-in needed; stop hush-cred and pass --replace to sign in again", l.Name)
}

func (l *Login) anthropic(ctx context.Context, in Instance) (oauth.Tokens, error) {
	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		return oauth.Tokens{}, err
	}
	q := url.Values{
		"code":                  {"true"},
		"client_id":             {in.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {in.RedirectURI},
		"scope":                 {in.Scopes},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
		"state":                 {pkce.Verifier},
	}
	fmt.Fprintf(l.Out, "Open this URL, sign in, and paste the code it shows:\n\n  %s?%s\n\n", in.AuthorizeURL, q.Encode())
	raw, err := l.ReadCode("code#state: ")
	if err != nil {
		return oauth.Tokens{}, err
	}
	code, state, found := strings.Cut(strings.TrimSpace(raw), "#")
	if !found || code == "" || state == "" {
		return oauth.Tokens{}, errors.New("expected code#state")
	}
	if state != pkce.Verifier {
		return oauth.Tokens{}, errors.New("the pasted state is not this login's")
	}
	return exchangeCode(ctx, l.Client, in, code, state, pkce.Verifier)
}

func exchangeCode(ctx context.Context, c *http.Client, in Instance, code, state, verifier string) (oauth.Tokens, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     in.ClientID,
		"code":          code,
		"state":         state,
		"redirect_uri":  in.RedirectURI,
		"code_verifier": verifier,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.TokenURL, bytes.NewReader(body))
	if err != nil {
		return oauth.Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return oauth.Tokens{}, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return oauth.Tokens{}, fmt.Errorf("token exchange %d: %s", resp.StatusCode, oauth.EndpointDetail(raw, code, verifier))
	}
	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return oauth.Tokens{}, errors.New("token exchange: the answer is not JSON")
	}
	if parsed.AccessToken == "" || parsed.RefreshToken == "" {
		return oauth.Tokens{}, errors.New("token exchange: no access or refresh token in the answer")
	}
	return oauth.Tokens{AccessToken: parsed.AccessToken, RefreshToken: parsed.RefreshToken, ExpiresIn: parsed.ExpiresIn}, nil
}

func (l *Login) copilot(ctx context.Context, in Instance) (oauth.Tokens, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	da, err := oauth.RequestDeviceCode(ctx, l.Client, in.DeviceURL, in.ClientID, in.Scopes)
	if err != nil {
		return oauth.Tokens{}, err
	}
	target := da.VerificationURIComplete
	if target == "" {
		target = da.VerificationURI
	}
	fmt.Fprintf(l.Out, "Open %s and enter %s\n", target, da.UserCode)
	gh, err := oauth.PollDeviceToken(ctx, l.Client, in.GitHubTokenURL, in.ClientID, da)
	if err != nil {
		return oauth.Tokens{}, err
	}
	return oauth.Tokens{RefreshToken: gh.AccessToken}, nil
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
