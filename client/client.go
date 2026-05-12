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
	"errors"
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

// Error is returned by client calls that the agent rejected. Use errors.Is
// to compare against the ErrOAuth* sentinels.
type Error struct {
	Message string
	Code    string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (code %s)", e.Message, e.Code)
	}
	return e.Message
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return t.Code != "" && e.Code == t.Code
}

// Sentinels for errors.Is. Match by error code (Message ignored).
var (
	ErrOAuthNotFound         = &Error{Code: agent.ErrCodeOAuthNotFound}
	ErrOAuthRefreshPermanent = &Error{Code: agent.ErrCodeOAuthRefreshPermanent}
	ErrOAuthRefreshTransient = &Error{Code: agent.ErrCodeOAuthRefreshTransient}
	ErrOAuthBadRequest       = &Error{Code: agent.ErrCodeOAuthBadRequest}
)

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

// Version returns the version of the running agent.
func (c *Client) Version() (string, error) {
	resp, err := c.rpc(agent.Request{Op: "version"})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("agent error: %s", resp.Error)
	}
	return resp.Version, nil
}

// Ping checks whether the agent is alive and responding.
func (c *Client) Ping() error {
	_, err := c.Status()
	return err
}

// OAuthRegisterRequest is the input to OAuthRegister.
type OAuthRegisterRequest struct {
	Name         string
	AuthorizeURL string
	TokenURL     string
	RedirectURI  string
	ClientID     string
	Scopes       string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// OAuthRegister installs (or replaces) an OAuth credential. The agent
// persists the encrypted tokens, kicks off proactive refresh, and exposes
// the access token via OAuthGet.
func (c *Client) OAuthRegister(req OAuthRegisterRequest) error {
	resp, err := c.rpc(agent.Request{
		Op: "oauth_register",
		OAuth: &agent.OAuthRequest{
			Name:         req.Name,
			AuthorizeURL: req.AuthorizeURL,
			TokenURL:     req.TokenURL,
			RedirectURI:  req.RedirectURI,
			ClientID:     req.ClientID,
			Scopes:       req.Scopes,
			AccessToken:  req.AccessToken,
			RefreshToken: req.RefreshToken,
			ExpiresIn:    req.ExpiresIn,
		},
	})
	if err != nil {
		return err
	}
	return checkResp(resp)
}

// OAuthGet returns the current cached access token for the given name. It
// never blocks on refresh; if the cached token has expired, the caller is
// expected to detect the 401 from the provider and call OAuthRefresh.
func (c *Client) OAuthGet(name string) (string, error) {
	resp, err := c.rpc(agent.Request{Op: "oauth_get", OAuth: &agent.OAuthRequest{Name: name}})
	if err != nil {
		return "", err
	}
	if err := checkResp(resp); err != nil {
		return "", err
	}
	return resp.Token, nil
}

// OAuthRefresh forces a refresh for the given name (coalescing with any
// in-flight refresh for the same config) and returns the new access token.
// Use this when the provider rejects the cached access token.
func (c *Client) OAuthRefresh(name string) (string, error) {
	resp, err := c.rpc(agent.Request{Op: "oauth_refresh", OAuth: &agent.OAuthRequest{Name: name}})
	if err != nil {
		return "", err
	}
	if err := checkResp(resp); err != nil {
		return "", err
	}
	return resp.Token, nil
}

// OAuthDelete removes the on-disk and in-memory state for a credential.
func (c *Client) OAuthDelete(name string) error {
	resp, err := c.rpc(agent.Request{Op: "oauth_delete", OAuth: &agent.OAuthRequest{Name: name}})
	if err != nil {
		return err
	}
	return checkResp(resp)
}

// OAuthList returns the names of all registered OAuth credentials.
func (c *Client) OAuthList() ([]string, error) {
	resp, err := c.rpc(agent.Request{Op: "oauth_list"})
	if err != nil {
		return nil, err
	}
	if err := checkResp(resp); err != nil {
		return nil, err
	}
	return resp.Names, nil
}

func checkResp(resp *agent.Response) error {
	if resp.OK {
		return nil
	}
	if resp.ErrorCode != "" {
		return &Error{Message: resp.Error, Code: resp.ErrorCode}
	}
	return errors.New(resp.Error)
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
