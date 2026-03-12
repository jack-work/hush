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
}

func configDir() (string, error) {
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
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hush"), nil
	}
	d := filepath.Join(os.TempDir(), "hush")
	if err := os.MkdirAll(d, 0700); err != nil {
		return "", fmt.Errorf("create runtime dir: %w", err)
	}
	return d, nil
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

	viper.SetDefault("ttl", "30m")
	viper.SetDefault("identity", filepath.Join(cfgDir, "identity.age"))

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

	return &Config{
		TTL:          ttl,
		IdentityFile: viper.GetString("identity"),
		ConfigDir:    cfgDir,
		CommandsDir:  filepath.Join(cfgDir, "commands"),
		StateDir:     sDir,
		RuntimeDir:   rDir,
	}, nil
}
