//go:build linux

package credserve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

var ErrEgressRefused = errors.New("egress refused")

func FencedClient(hosts []string, roots *x509.CertPool) *http.Client {
	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		allowed[strings.ToLower(h)] = true
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if !allowed[strings.ToLower(addr)] {
					return nil, fmt.Errorf("%w: %s is not a configured token endpoint", ErrEgressRefused, addr)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        4,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w: redirect to %s", ErrEgressRefused, req.URL.Host)
		},
	}
}
