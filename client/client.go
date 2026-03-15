// Package client provides a library interface for external programs to encrypt
// and decrypt hush-managed secrets. Decryption goes through the running hush
// agent (no keys in your process). Encryption uses the public key directly —
// no agent required.
//
// Usage:
//
//	// Decrypt
//	values, err := client.DecryptConfig("twitch")
//	if err != nil { ... }
//	secret := values["client_secret"]
//
//	// Encrypt to default location
//	err = client.EncryptConfig("twitch", map[string]string{
//	    "client_secret": "sk-live-...",
//	    "client_id":     "public-thing",
//	}, []string{"client_secret"})
//
//	// Encrypt to arbitrary path
//	err = client.EncryptFile("/tmp/my-secrets.toml", map[string]string{
//	    "token": "secret-value",
//	}, nil) // nil = encrypt all values
package client

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"

	"github.com/jack-work/hush/agent"
	"github.com/jack-work/hush/secrets"
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
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "commands"), nil
}

// EncryptConfig writes encrypted secrets to the default location for a named
// hush command (~/.config/hush/commands/<name>/secrets.toml). Creates the
// directory if it doesn't exist.
//
// keysToEncrypt specifies which keys to encrypt. If nil or empty, all values
// are encrypted.
func EncryptConfig(name string, values map[string]string, keysToEncrypt []string) error {
	commandsDir, err := CommandsDir()
	if err != nil {
		return err
	}

	dir := filepath.Join(commandsDir, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create command dir: %w", err)
	}

	secretsPath := filepath.Join(dir, "secrets.toml")
	return EncryptToFile(secretsPath, values, keysToEncrypt)
}

// EncryptToFile encrypts the given values and writes them to a TOML file at
// the specified path. Creates parent directories if needed.
//
// keysToEncrypt specifies which keys to encrypt. If nil or empty, all values
// are encrypted.
func EncryptToFile(path string, values map[string]string, keysToEncrypt []string) error {
	recipient, err := loadRecipient()
	if err != nil {
		return err
	}

	if len(keysToEncrypt) == 0 {
		keysToEncrypt = make([]string, 0, len(values))
		for k := range values {
			keysToEncrypt = append(keysToEncrypt, k)
		}
	}

	data, err := secrets.EncryptFile(values, recipient, keysToEncrypt)
	if err != nil {
		return err
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
	}

	return os.WriteFile(path, data, 0600)
}

// EncryptValue encrypts a single plaintext string and returns the AGE-ENC[...]
// wrapped ciphertext. No file I/O on the secret — just string in, string out.
func EncryptValue(plaintext string) (string, error) {
	recipient, err := loadRecipient()
	if err != nil {
		return "", err
	}
	return secrets.EncryptValue(plaintext, recipient)
}

// loadRecipient reads the hush public key from the default identity location.
func loadRecipient() (age.Recipient, error) {
	pubPath, err := publicKeyPath()
	if err != nil {
		return nil, err
	}

	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("can't read public key at %s: %w (run 'hush init' first)", pubPath, err)
	}

	return age.ParseX25519Recipient(strings.TrimSpace(string(pubData)))
}

// publicKeyPath returns the path to the hush public key file.
func publicKeyPath() (string, error) {
	if p := os.Getenv("HUSH_IDENTITY"); p != "" {
		return p + ".pub", nil
	}
	configDir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "identity.age.pub"), nil
}

// configDir returns the hush config directory, respecting XDG_CONFIG_HOME.
func configDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "hush"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("can't find home: %w", err)
	}
	return filepath.Join(home, ".config", "hush"), nil
}

// AgentSocket returns the default agent socket path, respecting
// XDG_RUNTIME_DIR.
func AgentSocket() (string, error) {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hush", "agent.sock"), nil
	}
	return filepath.Join(os.TempDir(), "hush", "agent.sock"), nil
}
