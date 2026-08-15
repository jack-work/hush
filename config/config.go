package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
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
	return defaultConfigDir()
}

func stateDir() (string, error) {
	if d := os.Getenv("HUSH_STATE_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "hush"), nil
	}
	return defaultStateDir()
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

// Load reads config with priority: env > file > defaults.
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

// fileConfig is hush.toml on disk. Every field is optional; what is
// absent keeps its default.
type fileConfig struct {
	TTL      string `toml:"ttl"`
	Identity string `toml:"identity"`
	Unlock   struct {
		Method  string   `toml:"method"`
		Exec    []string `toml:"exec"`
		Keyring struct {
			Service string `toml:"service"`
			Account string `toml:"account"`
		} `toml:"keyring"`
	} `toml:"unlock"`
}

// loadFromDirs resolves configuration in one pass: defaults, overlaid by
// <cfgDir>/hush.toml if it exists, overlaid by the environment.
//
// This used to be viper. Viper's cost was not its API — twelve calls —
// but its company: a second TOML parser next to the one we already use,
// a YAML parser in a program that has never seen YAML, a virtual
// filesystem, a file watcher for a file we never watch. Half a megabyte
// of linked symbols and nine modules to read five keys.
//
// It was also global state, which is a poor fit for a package whose
// callers deliberately load several configurations in one process:
// viper.AddConfigPath appends, so an embedded consumer resolving its own
// dirs after hush's would search both and could read the wrong hush.toml,
// and defaults set for the first load leaked into the second.
func loadFromDirs(cfgDir, sDir, rDir string) (*Config, error) {
	var f fileConfig
	f.TTL = "30m"
	f.Identity = filepath.Join(cfgDir, "identity.age")
	f.Unlock.Method = "auto"
	f.Unlock.Keyring.Service = "hush"
	f.Unlock.Keyring.Account = "default"

	data, err := os.ReadFile(filepath.Join(cfgDir, "hush.toml"))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err == nil {
		if err := toml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	// Environment wins over the file. Only these three are honoured, which
	// is what viper's AutomaticEnv actually managed: dotted keys never
	// bound without a key replacer, so HUSH_UNLOCK_METHOD never worked.
	overrideFromEnv("HUSH_TTL", &f.TTL)
	overrideFromEnv("HUSH_IDENTITY", &f.Identity)
	overrideFromEnv("HUSH_KEYRING_SERVICE", &f.Unlock.Keyring.Service)

	ttl, err := time.ParseDuration(f.TTL)
	if err != nil {
		return nil, fmt.Errorf("parse ttl: %w", err)
	}

	return &Config{
		TTL:          ttl,
		IdentityFile: f.Identity,
		ConfigDir:    cfgDir,
		CommandsDir:  filepath.Join(cfgDir, "commands"),
		StateDir:     sDir,
		RuntimeDir:   rDir,
		Unlock: UnlockConfig{
			Method:  f.Unlock.Method,
			Keyring: KeyringConfig(f.Unlock.Keyring),
			Exec:    f.Unlock.Exec,
		},
	}, nil
}

func overrideFromEnv(key string, dst *string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

// AppDirs returns platform-correct config and state directories for a
// consuming application's embedded hush instance. Uses the same OS
// conventions as hush itself (XDG on Unix, APPDATA/LOCALAPPDATA on
// Windows) but scoped under the given app name instead of "hush".
func AppDirs(appName string) (Dirs, error) {
	cfgBase, err := defaultConfigDir()
	if err != nil {
		return Dirs{}, err
	}
	stateBase, err := defaultStateDir()
	if err != nil {
		return Dirs{}, err
	}
	// Replace the trailing "hush" segment with "<appName>/hush".
	cfgBase = filepath.Join(filepath.Dir(cfgBase), appName, "hush")
	stateBase = filepath.Join(filepath.Dir(stateBase), appName, "hush")
	return Dirs{
		ConfigDir:  cfgBase,
		StateDir:   stateBase,
		RuntimeDir: filepath.Join(os.TempDir(), appName+"-hush"),
	}, nil
}
