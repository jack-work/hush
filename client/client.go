// Package client provides a library interface for external programs to decrypt
// hush-managed secrets via the running hush agent. No keys in memory, no
// passphrase prompts — just a quiet word to the agent over the socket.
//
// Usage:
//
//	values, err := client.DecryptConfig("twitch")
//	if err != nil { ... }
//	secret := values["client_secret"]
package client

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/jack-work/hush/agent"
)

// DecryptConfig reads the secrets.toml for the named hush command and decrypts
// all values via the running hush agent. Returns a flat map of key → plaintext.
//
// The agent must be running (hush up -d). If it's not, returns a clear error.
func DecryptConfig(name string) (map[string]string, error) {
	commandsDir, err := CommandsDir()
	if err != nil {
		return nil, err
	}

	secretsPath := filepath.Join(commandsDir, name, "secrets.toml")
	return DecryptFile(secretsPath)
}

// DecryptFile reads a secrets.toml at the given path and decrypts all values
// via the running hush agent.
func DecryptFile(secretsPath string) (map[string]string, error) {
	data, err := os.ReadFile(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("psst — can't find the goods at %s: %w", secretsPath, err)
	}

	var rawValues map[string]string
	if err := toml.Unmarshal(data, &rawValues); err != nil {
		return nil, fmt.Errorf("that toml ain't right: %w", err)
	}

	sockPath, err := AgentSocket()
	if err != nil {
		return nil, err
	}

	resp, err := RPC(sockPath, agent.Request{Op: "decrypt", Values: rawValues})
	if err != nil {
		return nil, fmt.Errorf("hush agent ain't running. wake me up first:\n\n  hush up -d")
	}
	if !resp.OK {
		return nil, fmt.Errorf("agent says: %s", resp.Error)
	}

	return resp.Values, nil
}

// RPC sends a request to the agent over the unix socket and returns the response.
func RPC(sockPath string, req agent.Request) (*agent.Response, error) {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp agent.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Ping checks whether the agent at sockPath is alive and responding.
func Ping(sockPath string) error {
	resp, err := RPC(sockPath, agent.Request{Op: "status"})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("agent error: %s", resp.Error)
	}
	return nil
}

// CommandsDir returns the default hush commands directory, respecting
// XDG_CONFIG_HOME.
func CommandsDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "hush", "commands"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("can't find home: %w", err)
	}
	return filepath.Join(home, ".config", "hush", "commands"), nil
}

// AgentSocket returns the default agent socket path, respecting
// XDG_RUNTIME_DIR.
func AgentSocket() (string, error) {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hush", "agent.sock"), nil
	}
	return filepath.Join(os.TempDir(), "hush", "agent.sock"), nil
}
