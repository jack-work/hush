//go:build linux

package credserve

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/BurntSushi/toml"

	"github.com/jack-work/hush/internal/oauth"
)

const (
	KindAnthropic    = "anthropic"
	KindRefreshToken = "refresh_token"
	KindCopilot      = "copilot"
	KindChatGPT      = "chatgpt"
)

type Instance struct {
	Kind           string `toml:"kind"`
	AuthorizeURL   string `toml:"authorize_url"`
	TokenURL       string `toml:"token_url"`
	RedirectURI    string `toml:"redirect_uri"`
	ClientID       string `toml:"client_id"`
	Scopes         string `toml:"scopes"`
	DeviceURL      string `toml:"device_url"`
	GitHubTokenURL string `toml:"github_token_url"`
	// Audit logs one line per GET /cred/<name> for this instance, served or
	// refused: the credential, the principal, the peer uid and the status.
	// Never the token.
	Audit bool `toml:"audit"`
	// Command and Timeout belong to kind "exec" only.
	Command []string `toml:"command"`
	Timeout string   `toml:"timeout"`
}

type Principal struct {
	Users       []string `toml:"users"`
	Credentials []string `toml:"credentials"`
	Socket      string   `toml:"socket"`
	Login       bool     `toml:"login"`
	Refresh     bool     `toml:"refresh"`

	RefreshCredentials []string `toml:"refresh_credentials"`
}

type Config struct {
	Recipient string              `toml:"recipient"`
	AllowUser string              `toml:"allow_user"`
	Instances map[string]Instance `toml:"instances"`
	// Principals, when set, add one socket per principal beside the
	// allow_user socket (which keeps serving every instance, as before).
	Principals map[string]Principal `toml:"principals"`
	// Systemd, when set, adds the LoadCredential socket: units granted by
	// name receive a raw token from systemd itself.
	Systemd *Systemd `toml:"systemd"`
	// ConsentGrants is the path of a consent grants file ({"grants": [{id,
	// principal, credential, expires_at, approved_by}]}), read at every use:
	// a live row grants that credential to that principal beside the
	// config's own grants. Empty: no consent grants.
	ConsentGrants string `toml:"consent_grants"`

	recipient age.Recipient
}

var instanceNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (*Config, error) {
	var c Config
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&c)
	if err != nil {
		return nil, fmt.Errorf("cred config: %w", err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, len(un))
		for i, k := range un {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("cred config: unknown keys %s", strings.Join(keys, ", "))
	}
	if c.recipient, err = age.ParseX25519Recipient(c.Recipient); err != nil {
		return nil, fmt.Errorf("cred config: recipient: %w", err)
	}
	if c.AllowUser == "" && len(c.Principals) == 0 {
		return nil, errors.New("cred config: allow_user or at least one [principals] entry is required")
	}
	if len(c.Instances) == 0 {
		return nil, errors.New("cred config: no instances")
	}
	for name, in := range c.Instances {
		switch in.Kind {
		case KindChatGPT:
			in = in.chatGPTDefaults()
			c.Instances[name] = in
		case KindAnthropic:
			in = in.anthropicDefaults()
			c.Instances[name] = in
		}
		if err := in.validate(name); err != nil {
			return nil, err
		}
	}
	if c.ConsentGrants != "" && !filepath.IsAbs(c.ConsentGrants) {
		return nil, fmt.Errorf("cred config: consent_grants must be an absolute path, not %q", c.ConsentGrants)
	}
	for name, p := range c.Principals {
		if err := p.validate(name, c.Instances, c.ConsentGrants != ""); err != nil {
			return nil, err
		}
	}
	if c.Systemd != nil {
		if err := c.Systemd.validate(c.Instances); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func (p Principal) validate(name string, instances map[string]Instance, consent bool) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("cred config: principal %s: "+format, append([]any{name}, a...)...)
	}
	if !instanceNameRE.MatchString(name) {
		return fmt.Errorf("cred config: principal name %q must match %s", name, instanceNameRE)
	}
	if name == SystemdFDName {
		return fail("the name is reserved for the systemd LoadCredential socket")
	}
	if len(p.Users) == 0 {
		return fail("users is required")
	}
	for _, u := range p.Users {
		if u == "" {
			return fail("an empty user")
		}
	}
	if len(p.Credentials) == 0 && !p.Login && !p.Refresh && !consent {
		// With a consent grants file, a principal may hold consent grants only.
		return fail("credentials is required")
	}
	for _, cred := range p.Credentials {
		if _, ok := instances[cred]; !ok {
			return fail("credential %q is not an instance", cred)
		}
	}
	for _, cred := range p.RefreshCredentials {
		if _, ok := instances[cred]; !ok {
			return fail("refresh_credentials %q is not an instance", cred)
		}
	}
	if len(p.RefreshCredentials) > 0 && !p.Refresh {
		return fail("refresh_credentials needs refresh = true")
	}
	if p.Refresh && len(p.RefreshCredentials) == 0 && len(p.Credentials) == 0 && !consent {
		return fail("refresh = true grants no instance: set refresh_credentials, credentials or consent_grants")
	}
	if p.Socket != "" && !strings.HasPrefix(p.Socket, "/") {
		return fail("socket %q is not an absolute path", p.Socket)
	}
	return nil
}

func (c *Config) RecipientKey() age.Recipient { return c.recipient }

func (in Instance) validate(name string) error {
	if !instanceNameRE.MatchString(name) {
		return fmt.Errorf("cred config: instance name %q must match %s", name, instanceNameRE)
	}
	fail := func(format string, a ...any) error {
		return fmt.Errorf("cred config: instance %s: "+format, append([]any{name}, a...)...)
	}
	if in.Kind == KindExec {
		return in.validateExec(name)
	}
	if len(in.Command) > 0 || in.Timeout != "" {
		return fail("command and timeout belong to kind %q", KindExec)
	}
	if in.Kind == KindChatGPT {
		if in.AuthorizeURL != oauth.ChatGPTAuthorizeURL || in.TokenURL != oauth.ChatGPTTokenURL || in.ClientID != oauth.ChatGPTClientID || in.RedirectURI != oauth.ChatGPTRedirectURI || in.Scopes != oauth.ChatGPTScopes || in.DeviceURL != "" || in.GitHubTokenURL != "" {
			return fail("ChatGPT endpoints, client and callback are pinned")
		}
		return nil
	}
	if in.ClientID == "" {
		return fail("client_id is required")
	}
	if in.Kind == KindAnthropic {
		if in.AuthorizeURL != oauth.AnthropicAuthorizeURL || in.TokenURL != oauth.AnthropicTokenURL || in.ClientID != oauth.AnthropicClientID || in.RedirectURI != oauth.AnthropicRedirectURI || in.Scopes != oauth.AnthropicScopes || in.DeviceURL != "" || in.GitHubTokenURL != "" {
			return fail("Anthropic endpoints, client, callback and scopes are pinned")
		}
		return nil
	}
	need := map[string]string{"token_url": in.TokenURL}
	switch in.Kind {
	case KindRefreshToken:
		need["authorize_url"] = in.AuthorizeURL
		need["redirect_uri"] = in.RedirectURI
		if in.DeviceURL != "" || in.GitHubTokenURL != "" {
			return fail("device_url and github_token_url belong to kind %q", KindCopilot)
		}
	case KindCopilot:
		need["device_url"] = in.DeviceURL
		need["github_token_url"] = in.GitHubTokenURL
		if in.AuthorizeURL != "" || in.RedirectURI != "" {
			return fail("authorize_url and redirect_uri belong to kind %q", KindRefreshToken)
		}
	default:
		return fail("kind must be %q, %q, %q, %q or %q, not %q", KindAnthropic, KindRefreshToken, KindCopilot, KindChatGPT, KindExec, in.Kind)
	}
	for key, raw := range need {
		if raw == "" {
			return fail("%s is required", key)
		}
		if err := checkHTTPS(raw); err != nil {
			return fail("%s: %v", key, err)
		}
	}
	return nil
}

func checkHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q is not a plain https URL", raw)
	}
	return nil
}

func (in Instance) OAuthConfig(name string) oauth.Config {
	c := oauth.Config{
		Name:     name,
		TokenURL: in.TokenURL,
		ClientID: in.ClientID,
		Scopes:   in.Scopes,
	}
	switch in.Kind {
	case KindRefreshToken:
		c.AuthorizeURL = in.AuthorizeURL
		c.RedirectURI = in.RedirectURI
		c.Grant = oauth.GrantRefreshToken
	case KindCopilot:
		c.Grant = oauth.GrantCopilot
	case KindChatGPT:
		c.AuthorizeURL = in.AuthorizeURL
		c.RedirectURI = in.RedirectURI
		c.Grant = oauth.GrantChatGPT
	case KindAnthropic:
		c.AuthorizeURL = in.AuthorizeURL
		c.RedirectURI = in.RedirectURI
		c.Grant = oauth.GrantAnthropic
	}
	return c
}

func (in Instance) egressURLs() []string {
	return []string{in.TokenURL, in.DeviceURL, in.GitHubTokenURL}
}

func (c *Config) EgressHosts() []string {
	seen := map[string]bool{}
	for _, in := range c.Instances {
		for _, raw := range in.egressURLs() {
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			seen[hostPort(u)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

func (in Instance) chatGPTDefaults() Instance {
	if in.AuthorizeURL == "" {
		in.AuthorizeURL = oauth.ChatGPTAuthorizeURL
	}
	if in.TokenURL == "" {
		in.TokenURL = oauth.ChatGPTTokenURL
	}
	if in.ClientID == "" {
		in.ClientID = oauth.ChatGPTClientID
	}
	if in.RedirectURI == "" {
		in.RedirectURI = oauth.ChatGPTRedirectURI
	}
	if in.Scopes == "" {
		in.Scopes = oauth.ChatGPTScopes
	}
	return in
}

func (in Instance) anthropicDefaults() Instance {
	if in.AuthorizeURL == "" {
		in.AuthorizeURL = oauth.AnthropicAuthorizeURL
	}
	if in.TokenURL == "" {
		in.TokenURL = oauth.AnthropicTokenURL
	}
	if in.ClientID == "" {
		in.ClientID = oauth.AnthropicClientID
	}
	if in.RedirectURI == "" {
		in.RedirectURI = oauth.AnthropicRedirectURI
	}
	if in.Scopes == "" {
		in.Scopes = oauth.AnthropicScopes
	}
	return in
}
