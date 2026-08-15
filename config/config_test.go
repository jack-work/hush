package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// write drops a hush.toml into dir and returns dir.
func write(t *testing.T, dir, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "hush.toml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := loadFromDirs(dir, dir, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.TTL != 30*time.Minute {
		t.Errorf("ttl = %s, want 30m", cfg.TTL)
	}
	if want := filepath.Join(dir, "identity.age"); cfg.IdentityFile != want {
		t.Errorf("identity = %s, want %s", cfg.IdentityFile, want)
	}
	if cfg.Unlock.Method != "auto" {
		t.Errorf("unlock method = %q, want auto", cfg.Unlock.Method)
	}
	if cfg.Unlock.Keyring.Service != "hush" || cfg.Unlock.Keyring.Account != "default" {
		t.Errorf("keyring = %+v, want hush/default", cfg.Unlock.Keyring)
	}
}

// TestLoadFileOverlaysDefaults also pins the shape of the file: absent
// keys keep their defaults rather than zeroing.
func TestLoadFileOverlaysDefaults(t *testing.T) {
	dir := write(t, t.TempDir(), `
ttl = "168h"

[unlock]
method = "exec"
exec = ["pass", "show", "hush/passphrase"]
`)
	cfg, err := loadFromDirs(dir, dir, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.TTL != 168*time.Hour {
		t.Errorf("ttl = %s, want 168h", cfg.TTL)
	}
	if cfg.Unlock.Method != "exec" {
		t.Errorf("method = %q", cfg.Unlock.Method)
	}
	if len(cfg.Unlock.Exec) != 3 || cfg.Unlock.Exec[0] != "pass" {
		t.Errorf("exec = %v", cfg.Unlock.Exec)
	}
	// Untouched by the file, so still the default.
	if cfg.Unlock.Keyring.Service != "hush" {
		t.Errorf("keyring service = %q, want the default to survive", cfg.Unlock.Keyring.Service)
	}
	if want := filepath.Join(dir, "identity.age"); cfg.IdentityFile != want {
		t.Errorf("identity = %s, want the default to survive", cfg.IdentityFile)
	}
}

func TestEnvBeatsFile(t *testing.T) {
	dir := write(t, t.TempDir(), "ttl = \"1h\"\nidentity = \"/from/file\"\n")
	t.Setenv("HUSH_TTL", "5m")
	t.Setenv("HUSH_IDENTITY", "/from/env")
	t.Setenv("HUSH_KEYRING_SERVICE", "figaro-dev")

	cfg, err := loadFromDirs(dir, dir, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.TTL != 5*time.Minute {
		t.Errorf("ttl = %s, want the env to win", cfg.TTL)
	}
	if cfg.IdentityFile != "/from/env" {
		t.Errorf("identity = %s, want the env to win", cfg.IdentityFile)
	}
	if cfg.Unlock.Keyring.Service != "figaro-dev" {
		t.Errorf("keyring service = %q, want the env to win", cfg.Unlock.Keyring.Service)
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadFromDirs(dir, dir, dir); err != nil {
		t.Fatalf("a missing hush.toml must be fine: %v", err)
	}
}

func TestBadInputIsAnError(t *testing.T) {
	t.Run("unparseable ttl", func(t *testing.T) {
		dir := write(t, t.TempDir(), `ttl = "half past four"`)
		if _, err := loadFromDirs(dir, dir, dir); err == nil {
			t.Fatal("want an error")
		}
	})
	t.Run("malformed toml", func(t *testing.T) {
		dir := write(t, t.TempDir(), "ttl = \nunclosed [")
		if _, err := loadFromDirs(dir, dir, dir); err == nil {
			t.Fatal("want an error")
		}
	})
}

// TestLoadsAreIndependent is the bug the viper removal fixed: package-level
// state meant a second Load with different dirs inherited the first one's
// search path and defaults. Two loads must see only their own directory.
func TestLoadsAreIndependent(t *testing.T) {
	first := write(t, t.TempDir(), "ttl = \"1h\"\n")
	second := t.TempDir() // no hush.toml at all

	if _, err := loadFromDirs(first, first, first); err != nil {
		t.Fatalf("first load: %v", err)
	}
	cfg, err := loadFromDirs(second, second, second)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if cfg.TTL != 30*time.Minute {
		t.Errorf("ttl = %s — the first load's config leaked into the second", cfg.TTL)
	}
	if want := filepath.Join(second, "identity.age"); cfg.IdentityFile != want {
		t.Errorf("identity = %s, want %s — the first load's default leaked", cfg.IdentityFile, want)
	}
}
