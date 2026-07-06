//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultConfigDir resolves to %APPDATA%\hush (typically
// C:\Users\<user>\AppData\Roaming\hush), the conventional Windows config
// location and where earlier hush builds already wrote the identity.
func defaultConfigDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(d, "hush"), nil
}

// defaultStateDir resolves to %LOCALAPPDATA%\hush (encrypted OAuth blobs
// and the log live here). LOCALAPPDATA is per-user and not roamed.
func defaultStateDir() (string, error) {
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "hush"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve state dir: %w", err)
	}
	return filepath.Join(home, "AppData", "Local", "hush"), nil
}
