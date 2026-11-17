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
	"strconv"
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

	mu          sync.Mutex
	cells       map[string]*cell
	principals  map[string]PrincipalAuth
	noLegacy    bool
	pending     map[string]*remoteLogin
	connMu      sync.Mutex
	connections sync.WaitGroup
	conns       map[net.Conn]bool
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
		conns:              map[net.Conn]bool{},
	}
}

type peerKey struct{}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ConnState:         s.connectionState,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(*principalConn); ok {
				ctx = context.WithValue(ctx, principalKey{}, pc.principal)
			}
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
	principal, _ := r.Context().Value(principalKey{}).(string)
	if name, ok := strings.CutPrefix(r.URL.Path, "/cred/"); ok {
		if in, ok := s.cfg.Instances[name]; ok && in.Audit {
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			w = rec
			defer func() {
				who := principal
				if who == "" {
					who = "owner"
				}
				uid := "-"
				if u, ok := r.Context().Value(peerKey{}).(uint32); ok {
					uid = strconv.FormatUint(uint64(u), 10)
				}
				s.logger.Printf("cred: audit %s principal=%s uid=%s -> %d", name, who, uid, rec.status)
			}()
		}
	}
	if principal != "" {
		s.servePrincipal(w, r, principal)
		return
	}
	uid, ok := r.Context().Value(peerKey{}).(uint32)
	if !ok || uid != s.allowUID || s.noLegacy {
		if ok {
			s.logger.Printf("cred: refused peer uid %d", uid)
		} else {
			s.logger.Printf("cred: refused a peer without credentials")
		}
		writeError(w, http.StatusForbidden, "forbidden", "peer not allowed")
		return
	}
	if s.loginRoute(w, r) {
		return
	}
	refresh := strings.HasPrefix(r.URL.Path, "/refresh/")
	prefix := "/cred/"
	if refresh {
		prefix = "/refresh/"
	}
	name, found := strings.CutPrefix(r.URL.Path, prefix)
	if !found || name == "" || strings.Contains(name, "/") {
		writeError(w, http.StatusNotFound, "not_found", "GET /cred/<name>")
		return
	}
	if (!refresh && r.Method != http.MethodGet) || (refresh && r.Method != http.MethodPost) {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if _, ok := s.cfg.Instances[name]; !ok {
		writeError(w, http.StatusNotFound, "unknown_credential", "no such credential")
		return
	}
	if refresh {
		if r.URL.RawQuery != "" || !controlBody(r, &struct{}{}, true) {
			writeError(w, 400, "invalid_request", "invalid request")
			return
		}
		finish, performed, err := s.beginRemoteRefresh(name)
		if err != nil {
			writeOperationError(w, name, err)
			return
		}
		defer finish()
		current, err := s.mgr.Lease(name)
		if errors.Is(err, oauth.ErrNotFound) {
			if adoptErr := s.mgr.Adopt(name); adoptErr != nil {
				writeCredentialFailure(w, name, adoptErr)
				return
			}
			current, err = s.mgr.Lease(name)
		}
		if err != nil || (s.cfg.Instances[name].Kind == KindChatGPT && (!oauth.ValidAccountID(current.AccountID) || current.Config != s.cfg.Instances[name].OAuthConfig(name))) {
			writeCredentialFailure(w, name, err)
			return
		}
		var refreshErr error
		if performed {
			_, refreshErr = s.mgr.TryRefresh(name)
		}
		if refreshErr != nil {
			writeOperationError(w, name, refreshErr)
			return
		}
		l, err := s.mgr.Lease(name)
		if err != nil || l.SignInNeeded || l.ExpiresAt.Sub(s.Now()) < serveFloor {
			writeCredentialFailure(w, name, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]any{"ready": true, "refreshed": performed})
		return
	}
	s.answer(w, name)
}

func (s *Server) answer(w http.ResponseWriter, name string) {
	lease, err := s.mgr.Lease(name)
	if errors.Is(err, oauth.ErrStopped) || errors.Is(err, oauth.ErrDrainUncertain) {
		writeCredentialFailure(w, name, err)
		return
	}
	if err == nil && s.cfg.Instances[name].Kind == KindChatGPT && (!oauth.ValidAccountID(lease.AccountID) || lease.Config != s.cfg.Instances[name].OAuthConfig(name)) {
		writeStale(w, name)
		return
	}
	switch {
	case errors.Is(err, oauth.ErrNotFound):
		if err := s.mgr.Adopt(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.logger.Printf("cred: %s: credential operation failed", name)
		}
	case err != nil:
		s.logger.Printf("cred: %s: lease unavailable", name)
	case lease.SignInNeeded:
		_, _ = s.mgr.Refresh(name)
	case s.due(lease):
		s.paced(name, func() error { _, err := s.mgr.Refresh(name); return err })
	}

	lease, err = s.mgr.Lease(name)
	if err != nil || lease.SignInNeeded {
		writeCredentialFailure(w, name, err)
		return
	}
	if lease.ExpiresAt.Sub(s.Now()) < serveFloor {
		writeError(w, http.StatusServiceUnavailable, "refresh_failing", "token expired and the refresh has not succeeded")
		return
	}
	if s.cfg.Instances[name].Kind == KindChatGPT && (!oauth.ValidAccountID(lease.AccountID) || lease.Config != s.cfg.Instances[name].OAuthConfig(name)) {
		writeStale(w, name)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Name      string `json:"name"`
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
		AccountID string `json:"account_id,omitempty"`
	}{name, lease.AccessToken, lease.ExpiresAt.Unix(), lease.AccountID})
}

func (s *Server) due(l oauth.Lease) bool {
	now := s.Now()
	return !now.Before(l.RefreshAt) || l.ExpiresAt.Sub(now) < serveFloor
}

func (s *Server) paced(name string, attempt func() error) bool {
	s.mu.Lock()
	c := s.cells[name]
	if c == nil {
		c = &cell{}
		s.cells[name] = c
	}
	if f := c.flight; f != nil {
		s.mu.Unlock()
		<-f
		return false
	}
	if since := s.Now().Sub(c.lastDone); !c.lastDone.IsZero() && since >= 0 && since < s.MinRefreshInterval {
		s.mu.Unlock()
		return false
	}
	f := make(chan struct{})
	c.flight = f
	s.mu.Unlock()

	if err := attempt(); err != nil {
		s.logger.Printf("cred: %s: credential operation failed", name)
	}

	s.mu.Lock()
	c.flight = nil
	c.lastDone = s.Now()
	close(f)
	s.mu.Unlock()
	return true
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

func writeCredentialFailure(w http.ResponseWriter, name string, err error) {
	switch {
	case errors.Is(err, oauth.ErrStopped):
		writeError(w, http.StatusServiceUnavailable, "manager_stopped", "service stopping")
	case errors.Is(err, oauth.ErrDrainUncertain):
		writeError(w, http.StatusServiceUnavailable, "credential_uncertain", "credential state unresolved")
	default:
		writeStale(w, name)
	}
}
