//go:build linux

package credserve

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

const (
	DefaultMinRefreshInterval = 30 * time.Second
	serveFloor                = 30 * time.Second
	reasonSignIn              = "sign-in needed"
)

type Server struct {
	cfg      *Config
	mgr      *oauth.Manager
	allowUID uint32
	logger   *log.Logger

	Now                func() time.Time
	MinRefreshInterval time.Duration

	mu    sync.Mutex
	cells map[string]*cell
}

type cell struct {
	flight   chan struct{}
	lastDone time.Time
}

func NewServer(cfg *Config, mgr *oauth.Manager, allowUID uint32, logger *log.Logger) *Server {
	return &Server{
		cfg:                cfg,
		mgr:                mgr,
		allowUID:           allowUID,
		logger:             logger,
		Now:                time.Now,
		MinRefreshInterval: DefaultMinRefreshInterval,
		cells:              map[string]*cell{},
	}
}

type peerKey struct{}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uid, err := peerUID(c)
			if err != nil {
				return ctx
			}
			return context.WithValue(ctx, peerKey{}, uid)
		},
	}
}

func (s *Server) Serve(ln net.Listener) error {
	return s.HTTPServer().Serve(ln)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uid, ok := r.Context().Value(peerKey{}).(uint32)
	if !ok || uid != s.allowUID {
		if ok {
			s.logger.Printf("cred: refused peer uid %d", uid)
		} else {
			s.logger.Printf("cred: refused a peer without credentials")
		}
		writeError(w, http.StatusForbidden, "forbidden", "peer not allowed")
		return
	}
	name, found := strings.CutPrefix(r.URL.Path, "/cred/")
	if !found || name == "" || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, "not_found", "GET /cred/<name>")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if _, ok := s.cfg.Instances[name]; !ok {
		writeError(w, http.StatusNotFound, "unknown_credential", "no such credential")
		return
	}
	s.answer(w, name)
}

func (s *Server) answer(w http.ResponseWriter, name string) {
	lease, err := s.mgr.Lease(name)
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		if err := s.mgr.Adopt(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.logger.Printf("cred: %s: %v", name, err)
		}
	case err != nil:
		s.logger.Printf("cred: %s: lease: %v", name, err)
	case lease.SignInNeeded:
		_, _ = s.mgr.Refresh(name)
	case s.due(lease):
		s.paced(name, func() error { _, err := s.mgr.Refresh(name); return err })
	}

	lease, err = s.mgr.Lease(name)
	if err != nil || lease.SignInNeeded {
		writeStale(w, name)
		return
	}
	if lease.ExpiresAt.Sub(s.Now()) < serveFloor {
		writeError(w, http.StatusServiceUnavailable, "refresh_failing", "token expired and the refresh has not succeeded")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Name      string `json:"name"`
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}{name, lease.AccessToken, lease.ExpiresAt.Unix()})
}

func (s *Server) due(l oauth.Lease) bool {
	now := s.Now()
	return !now.Before(l.RefreshAt) || l.ExpiresAt.Sub(now) < serveFloor
}

func (s *Server) paced(name string, attempt func() error) {
	s.mu.Lock()
	c := s.cells[name]
	if c == nil {
		c = &cell{}
		s.cells[name] = c
	}
	if f := c.flight; f != nil {
		s.mu.Unlock()
		<-f
		return
	}
	if since := s.Now().Sub(c.lastDone); !c.lastDone.IsZero() && since >= 0 && since < s.MinRefreshInterval {
		s.mu.Unlock()
		return
	}
	f := make(chan struct{})
	c.flight = f
	s.mu.Unlock()

	if err := attempt(); err != nil {
		s.logger.Printf("cred: %s: %v", name, err)
	}

	s.mu.Lock()
	c.flight = nil
	c.lastDone = s.Now()
	close(f)
	s.mu.Unlock()
}

func writeStale(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":  "credential_stale",
		"stale":  "credential_stale:" + name,
		"reason": reasonSignIn,
	})
}

func writeError(w http.ResponseWriter, status int, code, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "reason": reason})
}
