//go:build linux

package credserve

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

// A remote copilot sign-in runs GitHub's device flow here, on the minter:
// login-start returns the verification URI and user code, and login-complete
// polls GitHub for at most completePollWait per call. The GitHub token is
// born here and never leaves; callers carry only the URI, the code and an
// opaque handle.
const maxDeviceLife = 900 * time.Second

// completePollWait bounds one login-complete call (a var for tests).
var completePollWait = 30 * time.Second

func (s *Server) loginClient() *http.Client {
	if s.LoginClient != nil {
		return s.LoginClient
	}
	return FencedClient(s.cfg.EgressHosts(), nil)
}

func (s *Server) startDeviceLogin(w http.ResponseWriter, r *http.Request, name string, in Instance) {
	s.mu.Lock()
	if s.pending[name] != nil {
		s.mu.Unlock()
		writeError(w, 409, "operation_busy", "credential operation busy")
		return
	}
	c := s.cells[name]
	if c == nil {
		c = &cell{}
		s.cells[name] = c
	}
	if c.flight != nil {
		s.mu.Unlock()
		writeError(w, 409, "operation_busy", "credential operation busy")
		return
	}
	if !c.lastDone.IsZero() && s.Now().Sub(c.lastDone) < s.MinRefreshInterval {
		s.mu.Unlock()
		writeError(w, 429, "rate_limited", "credential operation paced")
		return
	}
	if err := s.mgr.BeginLogin(name); err != nil {
		s.mu.Unlock()
		writeOperationError(w, name, err)
		return
	}
	handle, err := loginNonce()
	if err != nil {
		s.mgr.CancelLogin(name)
		s.mu.Unlock()
		writeError(w, 503, "login_failed", "login failed")
		return
	}
	// Reserve the slot before the network call, so a second start is refused.
	pending := &remoteLogin{handle: handle, completing: true}
	if s.pending == nil {
		s.pending = map[string]*remoteLogin{}
	}
	s.pending[name] = pending
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	da, err := oauth.RequestDeviceCode(ctx, s.loginClient(), in.DeviceURL, in.ClientID, in.Scopes)
	if err != nil || da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		s.mu.Lock()
		delete(s.pending, name)
		s.mgr.CancelLogin(name)
		s.mu.Unlock()
		s.logger.Printf("cred: %s: device code request failed", name)
		writeError(w, 502, "login_failed", "device code request failed")
		return
	}
	expires := da.Expiry()
	if limit := s.Now().Add(maxDeviceLife); expires.After(limit) {
		expires = limit
	}
	da.Expires = expires

	s.mu.Lock()
	pending.device = da
	pending.expires = expires
	pending.completing = false
	pending.timer = time.AfterFunc(time.Until(expires), func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pending[name] == pending && !pending.completing {
			delete(s.pending, name)
			s.mgr.CancelLogin(name)
		}
	})
	s.mu.Unlock()

	s.logger.Printf("cred: %s: remote device sign-in started", name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":           "started",
		"handle":           handle,
		"verification_uri": da.VerificationURI,
		"user_code":        da.UserCode,
		"expires_in":       int(time.Until(expires).Seconds()),
	})
}

func (s *Server) completeDeviceLogin(w http.ResponseWriter, r *http.Request, name string, in Instance, handle string) {
	s.mu.Lock()
	pending := s.pending[name]
	if pending == nil || pending.device == nil || subtle.ConstantTimeCompare([]byte(handle), []byte(pending.handle)) != 1 {
		s.mu.Unlock()
		writeError(w, 400, "invalid_handle", "no sign-in with that handle")
		return
	}
	if pending.completing {
		s.mu.Unlock()
		writeError(w, 409, "operation_busy", "credential operation busy")
		return
	}
	if !s.Now().Before(pending.expires) {
		s.endDeviceLoginLocked(name, pending)
		s.mgr.CancelLogin(name)
		s.mu.Unlock()
		writeError(w, 400, "login_expired", "the device code expired")
		return
	}
	pending.completing = true
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), completePollWait+15*time.Second)
	defer cancel()
	gh, err := oauth.PollDeviceTokenFor(ctx, s.loginClient(), in.GitHubTokenURL, in.ClientID, pending.device, completePollWait)
	if errors.Is(err, oauth.ErrDevicePending) {
		s.mu.Lock()
		pending.completing = false
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
		return
	}

	s.mu.Lock()
	s.endDeviceLoginLocked(name, pending)
	s.mu.Unlock()
	if err != nil {
		s.mgr.CancelLogin(name)
	}
	switch {
	case errors.Is(err, oauth.ErrDeviceExpired):
		writeError(w, 400, "login_expired", "the device code expired")
		return
	case errors.Is(err, oauth.ErrDeviceDenied):
		s.logger.Printf("cred: %s: remote device sign-in denied", name)
		writeError(w, 400, "invalid_login", "the sign-in was denied")
		return
	case err != nil:
		s.logger.Printf("cred: %s: remote device sign-in failed", name)
		writeError(w, 400, "invalid_login", "the sign-in failed")
		return
	}
	// Register persists the GitHub token and mints the first Copilot token,
	// as a terminal login does; the reservation keeps refreshes out meanwhile.
	err = s.mgr.Register(in.OAuthConfig(name), oauth.Tokens{RefreshToken: gh.AccessToken})
	s.mgr.CancelLogin(name)
	if err != nil {
		s.logger.Printf("cred: %s: remote device sign-in could not be stored", name)
		writeOperationError(w, name, err)
		return
	}
	s.logger.Printf("cred: %s: remote device sign-in complete", name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "signed-in"})
}

// endDeviceLoginLocked drops a pending device sign-in; the caller holds s.mu
// and releases the manager's login reservation (after storing the token, on
// success).
func (s *Server) endDeviceLoginLocked(name string, pending *remoteLogin) {
	if pending.timer != nil {
		pending.timer.Stop()
	}
	if s.pending[name] == pending {
		delete(s.pending, name)
	}
	if c := s.cells[name]; c != nil {
		c.lastDone = s.Now()
	}
}
