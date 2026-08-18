package oauth

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jack-work/hush/internal/secrets"
)

// tomlForm is the on-disk shape. Metadata fields are plaintext; tokens are
// AGE-encrypted strings; expires_at is unix millis (plaintext) so the agent
// can sort startup state without decrypting.
type tomlForm struct {
	AuthorizeURL string `toml:"authorize_url"`
	TokenURL     string `toml:"token_url"`
	RedirectURI  string `toml:"redirect_uri"`
	ClientID     string `toml:"client_id"`
	Scopes       string `toml:"scopes"`
	// Grant is the minting strategy. Absent means refresh_token: files
	// written by an older hush load unchanged and keep their behaviour.
	Grant        string `toml:"grant,omitempty"`
	AccessToken  string `toml:"access_token"`
	RefreshToken string `toml:"refresh_token"`
	// RefreshTokenPrev is the predecessor of RefreshToken, kept so a
	// rotation lost between the token response and this file can be
	// retried once instead of forcing a full re-login.
	RefreshTokenPrev string `toml:"refresh_token_prev,omitempty"`
	IssuedAt         int64  `toml:"issued_at,omitempty"`
	ExpiresAt        int64  `toml:"expires_at"`
	// Metadata is minted with the access token and is NOT secret (an API
	// host, say). Plaintext so it can be read without unlocking, and
	// rewritten on every mint so it can never outlive its token.
	Metadata map[string]string `toml:"metadata,omitempty"`
}

func (m *Manager) oauthDir() string {
	return filepath.Join(m.stateDir, "oauth")
}

func (m *Manager) filePath(name string) string {
	return filepath.Join(m.oauthDir(), name+".toml")
}

func stripTOMLExt(s string) string {
	if !strings.HasSuffix(s, ".toml") {
		return ""
	}
	return strings.TrimSuffix(s, ".toml")
}

func (m *Manager) loadFile(path string) (Config, plaintextTokens, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, plaintextTokens{}, err
	}
	var raw tomlForm
	if err := toml.Unmarshal(data, &raw); err != nil {
		return Config{}, plaintextTokens{}, fmt.Errorf("parse toml: %w", err)
	}

	access, err := secrets.DecryptValue(raw.AccessToken, m.identities)
	if err != nil {
		return Config{}, plaintextTokens{}, fmt.Errorf("decrypt access_token: %w", err)
	}
	refresh, err := secrets.DecryptValue(raw.RefreshToken, m.identities)
	if err != nil {
		return Config{}, plaintextTokens{}, fmt.Errorf("decrypt refresh_token: %w", err)
	}
	var prevRefresh string
	if raw.RefreshTokenPrev != "" {
		// A predecessor we cannot decrypt is not worth failing the load
		// over; it is only a fallback.
		if v, err := secrets.DecryptValue(raw.RefreshTokenPrev, m.identities); err == nil {
			prevRefresh = v
		}
	}

	name := stripTOMLExt(filepath.Base(path))
	cfg := Config{
		Name:         name,
		AuthorizeURL: raw.AuthorizeURL,
		TokenURL:     raw.TokenURL,
		RedirectURI:  raw.RedirectURI,
		ClientID:     raw.ClientID,
		Scopes:       raw.Scopes,
		Grant:        raw.Grant,
	}
	tok := plaintextTokens{
		access:      access,
		refresh:     refresh,
		metadata:    raw.Metadata,
		prevRefresh: prevRefresh,
		expiresAt:   time.UnixMilli(raw.ExpiresAt),
	}
	if raw.IssuedAt != 0 {
		tok.issuedAt = time.UnixMilli(raw.IssuedAt)
	}
	return cfg, tok, nil
}

// saveFile writes an OAuth config and its (plaintext) tokens to disk
// atomically (temp file + rename).
func (m *Manager) saveFile(cfg Config, tok plaintextTokens) error {
	encAccess, err := secrets.EncryptValue(tok.access, m.recipient)
	if err != nil {
		return fmt.Errorf("encrypt access_token: %w", err)
	}
	encRefresh, err := secrets.EncryptValue(tok.refresh, m.recipient)
	if err != nil {
		return fmt.Errorf("encrypt refresh_token: %w", err)
	}
	var encPrevRefresh string
	if tok.prevRefresh != "" {
		encPrevRefresh, err = secrets.EncryptValue(tok.prevRefresh, m.recipient)
		if err != nil {
			return fmt.Errorf("encrypt refresh_token_prev: %w", err)
		}
	}

	form := tomlForm{
		AuthorizeURL:     cfg.AuthorizeURL,
		TokenURL:         cfg.TokenURL,
		RedirectURI:      cfg.RedirectURI,
		ClientID:         cfg.ClientID,
		Scopes:           cfg.Scopes,
		Grant:            cfg.Grant,
		Metadata:         tok.metadata,
		AccessToken:      encAccess,
		RefreshToken:     encRefresh,
		RefreshTokenPrev: encPrevRefresh,
		ExpiresAt:        tok.expiresAt.UnixMilli(),
	}
	if !tok.issuedAt.IsZero() {
		form.IssuedAt = tok.issuedAt.UnixMilli()
	}

	var buf bytes.Buffer
	buf.WriteString("# Managed by hush. Do not edit.\n")
	if err := toml.NewEncoder(&buf).Encode(form); err != nil {
		return fmt.Errorf("encode toml: %w", err)
	}

	dir := m.oauthDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create oauth dir: %w", err)
	}

	finalPath := m.filePath(cfg.Name)
	tmpPath := finalPath + ".tmp"
	if err := os.WriteFile(tmpPath, buf.Bytes(), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
