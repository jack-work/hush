package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	TTL          time.Duration
	IdentityFile string
	ConfigDir    string
	CommandsDir  string
	StateDir     string
	RuntimeDir   string
	Unlock       UnlockConfig
}

// UnlockConfig controls how the agent acquires the passphrase that
// decrypts the on-disk age identity at startup. The chosen method is a
// property of the host (and its surrounding desktop environment), not
// of any particular consumer or secret — hush owns the bootstrap so
// every consumer (figaro, gws, brave, ...) gets the same UX for free.
//
// Default is "passphrase" (TTY prompt), preserving today's behavior.
type UnlockConfig struct {
	// Method names the resolver:
	//
	//   "passphrase" (default) — prompt on the terminal.
	//   "keyring"              — look up in the OS keyring
	//                            (Secret Service / Keychain / Credential
	//                            Manager) under Service/Account.
	//   "exec"                 — run an external command and read the
	//                            passphrase from its stdout.
	Method string

	// Keyring is consulted when Method == "keyring".
	Keyring KeyringConfig

	// Exec is the argv consulted when Method == "exec". The command's
	// stdout is read; a single trailing newline is stripped.
	Exec []string
}

// KeyringConfig identifies the OS-keyring entry holding the hush
// passphrase. Both fields default to "hush" / "default" so a fresh
// `[unlock]` table with just `method = "keyring"` works out of the box.
//
// HUSH_KEYRING_SERVICE overrides Service (used by dev shells to
// namespace per-shell keyring entries, mirroring how HUSH_CONFIG_DIR
// scopes the on-disk config).
type KeyringConfig struct {
	Service string
	Account string
}

// Directory resolution honors, in priority order:
//
//  1. HUSH_CONFIG_DIR / HUSH_STATE_DIR / HUSH_RUNTIME_DIR — explicit
//     hush-scoped overrides used as-is (no "/hush" suffix appended).
//     These exist so dev shells and embedded callers can pin every
//     singleton without colliding with the user's session-level
//     XDG_RUNTIME_DIR, which is normally always set.
//  2. XDG_CONFIG_HOME / XDG_STATE_HOME / XDG_RUNTIME_DIR — standard
//     XDG dirs; "/hush" is appended.
//  3. Hard-coded defaults under $HOME (or os.TempDir for runtime).
func configDir() (string, error) {
	if d := os.Getenv("HUSH_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "hush"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(home, ".config", "hush"), nil
}

func stateDir() (string, error) {
	if d := os.Getenv("HUSH_STATE_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "hush"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve state dir: %w", err)
	}
	return filepath.Join(home, ".local", "state", "hush"), nil
}

func runtimeDir() (string, error) {
	if d := os.Getenv("HUSH_RUNTIME_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hush"), nil
	}
	d := filepath.Join(os.TempDir(), "hush")
	if err := os.MkdirAll(d, 0700); err != nil {
		return "", fmt.Errorf("create runtime dir: %w", err)
	}
	return d, nil
}

// Dirs holds explicit directory overrides. Any non-empty field takes
// precedence over the XDG / env-based defaults. Used by the managed
// package to point at an app-specific config root.
type Dirs struct {
	ConfigDir  string
	StateDir   string
	RuntimeDir string
}

// LoadWithDirs loads configuration using the supplied directory overrides.
// Empty fields in dirs fall back to the normal XDG resolution.
func LoadWithDirs(dirs Dirs) (*Config, error) {
	cfgDir := dirs.ConfigDir
	sDir := dirs.StateDir
	rDir := dirs.RuntimeDir

	var err error
	if cfgDir == "" {
		if cfgDir, err = configDir(); err != nil {
			return nil, err
		}
	}
	if sDir == "" {
		if sDir, err = stateDir(); err != nil {
			return nil, err
		}
	}
	if rDir == "" {
		if rDir, err = runtimeDir(); err != nil {
			return nil, err
		}
	}

	return loadFromDirs(cfgDir, sDir, rDir)
}

// Load reads config with priority: flags (caller sets via viper) > env > file > defaults.
func Load() (*Config, error) {
	cfgDir, err := configDir()
	if err != nil {
		return nil, err
	}
	sDir, err := stateDir()
	if err != nil {
		return nil, err
	}
	rDir, err := runtimeDir()
	if err != nil {
		return nil, err
	}

	return loadFromDirs(cfgDir, sDir, rDir)
}

func loadFromDirs(cfgDir, sDir, rDir string) (*Config, error) {
	viper.SetDefault("ttl", "30m")
	viper.SetDefault("identity", filepath.Join(cfgDir, "identity.age"))
	viper.SetDefault("unlock.method", "auto")
	viper.SetDefault("unlock.keyring.service", "hush")
	viper.SetDefault("unlock.keyring.account", "default")

	viper.SetConfigName("hush")
	viper.SetConfigType("toml")
	viper.AddConfigPath(cfgDir)

	viper.SetEnvPrefix("HUSH")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	ttl, err := time.ParseDuration(viper.GetString("ttl"))
	if err != nil {
		return nil, fmt.Errorf("parse ttl: %w", err)
	}

	// HUSH_KEYRING_SERVICE overrides unlock.keyring.service so dev
	// shells can namespace keyring entries the same way they scope
	// HUSH_CONFIG_DIR. Done explicitly because viper's env binding
	// for dotted keys is finicky.
	keyringService := viper.GetString("unlock.keyring.service")
	if v := os.Getenv("HUSH_KEYRING_SERVICE"); v != "" {
		keyringService = v
	}

	return &Config{
		TTL:          ttl,
		IdentityFile: viper.GetString("identity"),
		ConfigDir:    cfgDir,
		CommandsDir:  filepath.Join(cfgDir, "commands"),
		StateDir:     sDir,
		RuntimeDir:   rDir,
		Unlock: UnlockConfig{
			Method: viper.GetString("unlock.method"),
			Keyring: KeyringConfig{
				Service: keyringService,
				Account: viper.GetString("unlock.keyring.account"),
			},
			Exec: viper.GetStringSlice("unlock.exec"),
		},
	}, nil
}
