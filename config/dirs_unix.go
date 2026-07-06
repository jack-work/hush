//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultConfigDir is the XDG-style config location when neither
// HUSH_CONFIG_DIR nor XDG_CONFIG_HOME is set.
func defaultConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(home, ".config", "hush"), nil
}

// defaultStateDir is the XDG-style state location when neither
// HUSH_STATE_DIR nor XDG_STATE_HOME is set.
func defaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve state dir: %w", err)
	}
	return filepath.Join(home, ".local", "state", "hush"), nil
}
