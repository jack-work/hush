package workload

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/spiffeid"
	"github.com/jack-work/hush/svid"
)

const SocketEnv = "HUSH_WORKLOAD_SOCKET"

func SocketPath() string {
	if p := os.Getenv(SocketEnv); p != "" {
		return p
	}
	if _, err := os.Stat("/run/hush/workload.sock"); err == nil {
		return "/run/hush/workload.sock"
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hush", "workload.sock")
	}
	return "/run/hush/workload.sock"
}

type Client struct {
	TrustDomain string
	http        *http.Client

	mu   sync.Mutex
	seen uint64
}

type Error struct {
	Status int
	Code   string
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("hush workload: %d %s: %s", e.Status, e.Code, e.Reason)
}

func NewClient(td, socket string) *Client {
	d := net.Dialer{Timeout: 5 * time.Second}
	return &Client{TrustDomain: td, http: &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", socket)
		}},
	}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) ([]byte, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://hush"+path, body)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e apiError
		_ = json.Unmarshal(raw, &e)
		return nil, &Error{Status: resp.StatusCode, Code: e.Error, Reason: e.Reason}
	}
	if out != nil {
		return raw, json.Unmarshal(raw, out)
	}
	return raw, nil
}

func (c *Client) Bundle(ctx context.Context) (*bundle.Bundle, error) {
	raw, err := c.do(ctx, http.MethodGet, "/v1/bundle", nil, nil)
	if err != nil {
		return nil, err
	}
	b, err := bundle.Parse(c.TrustDomain, raw)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if b.Sequence < c.seen {
		return nil, fmt.Errorf("hush workload: bundle sequence %d is older than %d", b.Sequence, c.seen)
	}
	c.seen = b.Sequence
	return b, nil
}

type X509SVID struct {
	ID         spiffeid.ID
	Chain      []*x509.Certificate
	Key        crypto.Signer
	RenewAfter time.Time
}

func (c *Client) X509(ctx context.Context, key crypto.Signer, b *bundle.Bundle) (*X509SVID, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	var resp X509Response
	if _, err := c.do(ctx, http.MethodPost, "/v1/x509-svid", X509Request{CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}, &resp); err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	rest := []byte(resp.Chain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, errors.New("hush workload: no certificate in the answer")
	}
	if pub, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("hush workload: the certificate is not for our key")
	}
	id, err := svid.VerifyX509(chain, b, time.Now())
	if err != nil {
		return nil, err
	}
	if id.String() != resp.SPIFFEID {
		return nil, fmt.Errorf("hush workload: answer names %s, certificate %s", resp.SPIFFEID, id)
	}
	return &X509SVID{ID: id, Chain: chain, Key: key, RenewAfter: resp.RenewAfter}, nil
}

func (c *Client) JWT(ctx context.Context, audience ...string) (JWTResponse, error) {
	var resp JWTResponse
	_, err := c.do(ctx, http.MethodPost, "/v1/jwt-svid", JWTRequest{Audience: audience}, &resp)
	return resp, err
}
