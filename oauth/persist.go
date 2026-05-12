package oauth

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/jack-work/hush/secrets"
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
	AccessToken  string `toml:"access_token"`
	RefreshToken string `toml:"refresh_token"`
	ExpiresAt    int64  `toml:"expires_at"`
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

	name := stripTOMLExt(filepath.Base(path))
	cfg := Config{
		Name:         name,
		AuthorizeURL: raw.AuthorizeURL,
		TokenURL:     raw.TokenURL,
		RedirectURI:  raw.RedirectURI,
		ClientID:     raw.ClientID,
		Scopes:       raw.Scopes,
	}
	tok := plaintextTokens{
		access:    access,
		refresh:   refresh,
		expiresAt: time.UnixMilli(raw.ExpiresAt),
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

	form := tomlForm{
		AuthorizeURL: cfg.AuthorizeURL,
		TokenURL:     cfg.TokenURL,
		RedirectURI:  cfg.RedirectURI,
		ClientID:     cfg.ClientID,
		Scopes:       cfg.Scopes,
		AccessToken:  encAccess,
		RefreshToken: encRefresh,
		ExpiresAt:    tok.expiresAt.UnixMilli(),
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
