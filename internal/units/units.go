// Package units holds the systemd user units that make the hush agent
// start on demand, and renders them for a given installation.
//
// The units are files, not string literals in Go, so that the NixOS
// module and the `hush install-units` path describe the same thing and
// a reader can diff them.
package units

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed hush-agent.socket
var socketTemplate string

//go:embed hush-agent.service
var serviceTemplate string

// Unit is one rendered unit file, ready to be written.
type Unit struct {
	Name    string
	Content string
}

// Render fills the two units in for a concrete installation.
//
// exe is the absolute path of the hush binary the service should run.
// runtimeDir is where the agent expects its socket; when it is the
// default ($XDG_RUNTIME_DIR/hush) the unit uses systemd's %t specifier
// instead of a hard-coded uid path, so the same file works for any user.
func Render(exe, runtimeDir string) []Unit {
	return []Unit{
		{Name: "hush-agent.socket", Content: strings.ReplaceAll(
			socketTemplate, "{{SOCKET}}", socketSpec(runtimeDir))},
		{Name: "hush-agent.service", Content: strings.ReplaceAll(
			serviceTemplate, "{{EXEC}}", exe)},
	}
}

func socketSpec(runtimeDir string) string {
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" && runtimeDir == filepath.Join(xdg, "hush") {
		return "%t/hush/agent.sock"
	}
	return filepath.Join(runtimeDir, "agent.sock")
}

// Dir is where user units live: $XDG_CONFIG_HOME/systemd/user, or the
// default ~/.config/systemd/user.
func Dir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "systemd", "user"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}
