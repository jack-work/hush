// Package client provides a library interface for external programs to encrypt
// and decrypt secrets via the running hush agent. The client never touches
// key material or config files — it's a pure socket client.
//
// Usage:
//
//	c, err := client.New()  // connects to default socket
//	if err != nil { ... }
//
//	// Decrypt
//	plain, err := c.Decrypt(map[string]string{"token": "AGE-ENC[...]"})
//
//	// Encrypt
//	enc, err := c.Encrypt(map[string]string{"token": "super-secret"})
package client

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jack-work/hush/agent"
)

// Client talks to a running hush agent over a unix socket.
type Client struct {
	sockPath string
}

// New creates a client connected to the default agent socket.
func New() (*Client, error) {
	sockPath, err := DefaultSocket()
	if err != nil {
		return nil, err
	}
	return &Client{sockPath: sockPath}, nil
}

// NewWithSocket creates a client connected to a specific socket path.
func NewWithSocket(sockPath string) *Client {
	return &Client{sockPath: sockPath}
}

// Decrypt sends encrypted values to the agent and returns plaintext values.
// Values not wrapped in AGE-ENC[...] are passed through as-is.
func (c *Client) Decrypt(values map[string]string) (map[string]string, error) {
	resp, err := c.rpc(agent.Request{Op: "decrypt", Values: values})
	if err != nil {
		return nil, fmt.Errorf("hush agent ain't running. wake me up first:\n\n  hush up -d")
	}
	if !resp.OK {
		return nil, fmt.Errorf("agent says: %s", resp.Error)
	}
	return resp.Values, nil
}

// Encrypt sends plaintext values to the agent and returns AGE-ENC[...] wrapped
// values. Values already wrapped in AGE-ENC[...] are passed through as-is.
func (c *Client) Encrypt(values map[string]string) (map[string]string, error) {
	resp, err := c.rpc(agent.Request{Op: "encrypt", Values: values})
	if err != nil {
		return nil, fmt.Errorf("hush agent ain't running. wake me up first:\n\n  hush up -d")
	}
	if !resp.OK {
		return nil, fmt.Errorf("agent says: %s", resp.Error)
	}
	return resp.Values, nil
}

// Status checks whether the agent is alive and returns the remaining TTL.
func (c *Client) Status() (string, error) {
	resp, err := c.rpc(agent.Request{Op: "status"})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("agent error: %s", resp.Error)
	}
	return resp.TTLRemaining, nil
}

// Ping checks whether the agent is alive and responding.
func (c *Client) Ping() error {
	_, err := c.Status()
	return err
}

func (c *Client) rpc(req agent.Request) (*agent.Response, error) {
	conn, err := net.DialTimeout("unix", c.sockPath, 2*time.Second)
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

// DefaultSocket returns the default agent socket path, respecting
// XDG_RUNTIME_DIR.
func DefaultSocket() (string, error) {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hush", "agent.sock"), nil
	}
	return filepath.Join(os.TempDir(), "hush", "agent.sock"), nil
}
