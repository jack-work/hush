package credserve

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

type remoteLogin struct {
	handle, verifier string
	expires          time.Time
	completing       bool
	timer            *time.Timer
}

func controlBody(r *http.Request, target any, empty bool) bool {
	raw, err := io.ReadAll(io.LimitReader(r.Body, (10<<10)+1))
	if err != nil || len(raw) > 10<<10 {
		return false
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return empty
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && decoder.Decode(new(any)) == io.EOF
}

func loginNonce() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (s *Server) loginRoute(w http.ResponseWriter, r *http.Request) bool {
	action := ""
	if strings.HasPrefix(r.URL.Path, "/login-start/") {
		action = "start"
	}
	if strings.HasPrefix(r.URL.Path, "/login-complete/") {
		action = "complete"
	}
	if action == "" {
		return false
	}
	prefix := "/login-" + action + "/"
	name := strings.TrimPrefix(r.URL.Path, prefix)
	in, ok := s.cfg.Instances[name]
	if !ok || name == "" || strings.Contains(name, "/") || in.Kind != KindChatGPT {
		writeError(w, 404, "unknown_credential", "no such credential")
		return true
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "method_not_allowed", "POST required")
		return true
	}
	if r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_request", "query refused")
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	if action == "start" {
		if !controlBody(r, &struct{}{}, true) {
			writeError(w, 400, "invalid_request", "invalid request")
			return true
		}
		s.startLogin(w, name, in)
	} else {
		var body struct {
			Handle string `json:"handle"`
			Code   string `json:"code"`
		}
		if !controlBody(r, &body, false) || len(body.Handle) > 128 || len(body.Code) == 0 || len(body.Code) > 8192 {
			writeError(w, 400, "invalid_request", "invalid request")
			return true
		}
		s.completeLogin(w, r, name, in, body.Handle, body.Code)
	}
	return true
}

func (s *Server) startLogin(w http.ResponseWriter, name string, in Instance) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[name] != nil {
		writeError(w, 409, "operation_busy", "credential operation busy")
		return
	}
	c := s.cells[name]
	if c == nil {
		c = &cell{}
		s.cells[name] = c
	}
	if c.flight != nil {
		writeError(w, 409, "operation_busy", "credential operation busy")
		return
	}
	if !c.lastDone.IsZero() && s.Now().Sub(c.lastDone) < s.MinRefreshInterval {
		writeError(w, 429, "rate_limited", "credential operation paced")
		return
	}
	if err := s.mgr.BeginLogin(name); err != nil {
		writeOperationError(w, name, err)
		return
	}
	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		s.mgr.CancelLogin(name)
		writeError(w, 503, "login_failed", "login failed")
		return
	}
	handle, err := loginNonce()
	if err != nil {
		s.mgr.CancelLogin(name)
		writeError(w, 503, "login_failed", "login failed")
		return
	}
	state, err := loginNonce()
	if err != nil {
		s.mgr.CancelLogin(name)
		writeError(w, 503, "login_failed", "login failed")
		return
	}
	pending := &remoteLogin{handle: handle, verifier: pkce.Verifier, expires: s.Now().Add(5 * time.Minute)}
	if s.pending == nil {
		s.pending = map[string]*remoteLogin{}
	}
	s.pending[name] = pending
	pending.timer = time.AfterFunc(5*time.Minute, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.pending[name] == pending && !pending.completing {
			delete(s.pending, name)
			s.mgr.CancelLogin(name)
		}
	})
	q := url.Values{"client_id": {oauth.ChatGPTClientID}, "redirect_uri": {oauth.ChatGPTRedirectURI}, "response_type": {"code"}, "scope": {oauth.ChatGPTScopes}, "code_challenge": {pkce.Challenge}, "code_challenge_method": {"S256"}, "state": {state}, "id_token_add_organizations": {"true"}, "codex_cli_simplified_flow": {"true"}, "originator": {"codex_cli_rs"}, "prompt": {"login"}}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "started", "authorize_url": oauth.ChatGPTAuthorizeURL + "?" + q.Encode(), "handle": handle})
}

func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, name string, in Instance, handle, code string) {
	s.mu.Lock()
	pending := s.pending[name]
	if pending == nil || pending.completing || !s.Now().Before(pending.expires) || subtle.ConstantTimeCompare([]byte(handle), []byte(pending.handle)) != 1 {
		s.mu.Unlock()
		writeError(w, 400, "invalid_session", "login session invalid")
		return
	}
	pending.completing = true
	pending.timer.Stop()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, name)
		s.cells[name].lastDone = s.Now()
		s.mgr.CancelLogin(name)
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := s.mgr.CompleteChatGPTLogin(ctx, in.OAuthConfig(name), code, pending.verifier); err != nil {
		writeOperationError(w, name, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "signed-in"})
}

func writeOperationError(w http.ResponseWriter, name string, err error) {
	if errors.Is(err, oauth.ErrOperationBusy) {
		writeError(w, 409, "operation_busy", "credential operation busy")
		return
	}
	writeCredentialFailure(w, name, err)
}

func (s *Server) beginRemoteRefresh(name string) (func(), bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[name] != nil {
		return nil, false, oauth.ErrOperationBusy
	}
	c := s.cells[name]
	if c == nil {
		c = &cell{}
		s.cells[name] = c
	}
	if c.flight != nil {
		return nil, false, oauth.ErrOperationBusy
	}
	if !c.lastDone.IsZero() && s.Now().Sub(c.lastDone) < s.MinRefreshInterval {
		return func() {}, false, nil
	}
	c.flight = make(chan struct{})
	return func() { s.mu.Lock(); c.lastDone = s.Now(); close(c.flight); c.flight = nil; s.mu.Unlock() }, true, nil
}
