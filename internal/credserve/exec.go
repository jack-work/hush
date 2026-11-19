//go:build linux

package credserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// KindExec is a credential some other tool already holds (a CLI's token
// cache, an OS keyring): hush runs Command, which prints
// {"token": "...", "expires_at": <unix seconds>} on stdout, and serves the
// result until it is about to expire. hush keeps no state for it and never
// sees a refresh token; signing in is the tool's own business. Exit status 3
// means "sign-in needed"; any other failure is transient.
const KindExec = "exec"

const (
	defaultExecTimeout = 30 * time.Second
	maxExecTimeout     = 5 * time.Minute
	maxExecOutput      = 64 << 10
	execExitSignIn     = 3
)

var (
	errExecSignIn    = errors.New("sign-in needed")
	errExecTransient = errors.New("credential command failed")
)

type execToken struct {
	token   string
	expires time.Time
}

type execFlight struct {
	done chan struct{}
	tok  execToken
	err  error
}

type execState struct {
	tokens   map[string]execToken
	flights  map[string]*execFlight
	failedAt map[string]time.Time
	lastErr  map[string]error
}

func (in Instance) validateExec(name string) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("cred config: instance %s: "+format, append([]any{name}, a...)...)
	}
	if len(in.Command) == 0 || in.Command[0] == "" {
		return fail("command is required")
	}
	if !strings.HasPrefix(in.Command[0], "/") {
		return fail("command[0] %q is not an absolute path", in.Command[0])
	}
	if in.AuthorizeURL != "" || in.TokenURL != "" || in.RedirectURI != "" || in.ClientID != "" || in.Scopes != "" || in.DeviceURL != "" || in.GitHubTokenURL != "" {
		return fail("kind %q takes command and timeout only", KindExec)
	}
	if _, err := in.execTimeout(); err != nil {
		return fail("%v", err)
	}
	return nil
}

func (in Instance) execTimeout() (time.Duration, error) {
	if in.Timeout == "" {
		return defaultExecTimeout, nil
	}
	d, err := time.ParseDuration(in.Timeout)
	if err != nil || d <= 0 || d > maxExecTimeout {
		return 0, fmt.Errorf("timeout %q must be a duration in (0, %s]", in.Timeout, maxExecTimeout)
	}
	return d, nil
}

// execGet returns a cached token while it has at least serveFloor left,
// else runs the command once however many callers ask at the same time.
// After a failure the command is not run again for MinRefreshInterval.
func (s *Server) execGet(name string, force bool) (execToken, error) {
	s.mu.Lock()
	if s.exec.tokens == nil {
		s.exec = execState{tokens: map[string]execToken{}, flights: map[string]*execFlight{}, failedAt: map[string]time.Time{}, lastErr: map[string]error{}}
	}
	if t, ok := s.exec.tokens[name]; ok && !force && t.expires.Sub(s.Now()) >= serveFloor {
		s.mu.Unlock()
		return t, nil
	}
	if f := s.exec.flights[name]; f != nil {
		s.mu.Unlock()
		<-f.done
		return f.tok, f.err
	}
	if at, ok := s.exec.failedAt[name]; ok && s.Now().Sub(at) < s.MinRefreshInterval {
		err := s.exec.lastErr[name]
		s.mu.Unlock()
		return execToken{}, err
	}
	f := &execFlight{done: make(chan struct{})}
	s.exec.flights[name] = f
	s.mu.Unlock()

	f.tok, f.err = s.runExec(name)

	s.mu.Lock()
	delete(s.exec.flights, name)
	if f.err == nil {
		s.exec.tokens[name] = f.tok
		delete(s.exec.failedAt, name)
		delete(s.exec.lastErr, name)
	} else {
		delete(s.exec.tokens, name)
		s.exec.failedAt[name] = s.Now()
		s.exec.lastErr[name] = f.err
	}
	close(f.done)
	s.mu.Unlock()
	return f.tok, f.err
}

func (s *Server) runExec(name string) (execToken, error) {
	in := s.cfg.Instances[name]
	timeout, _ := in.execTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.Command[0], in.Command[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: maxExecOutput}
	cmd.Stderr = io.Discard // a tool's diagnostics may carry secrets: never logged
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr) && exitErr.ExitCode() == execExitSignIn:
		s.logger.Printf("cred: %s: command reports sign-in needed", name)
		return execToken{}, errExecSignIn
	case ctx.Err() != nil:
		s.logger.Printf("cred: %s: command timed out after %s", name, timeout)
		return execToken{}, errExecTransient
	case errors.As(err, &exitErr):
		s.logger.Printf("cred: %s: command failed: exit %d", name, exitErr.ExitCode())
		return execToken{}, errExecTransient
	case err != nil:
		s.logger.Printf("cred: %s: command did not run", name)
		return execToken{}, errExecTransient
	}
	var doc struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if json.Unmarshal(out.Bytes(), &doc) != nil || doc.Token == "" || doc.ExpiresAt <= 0 {
		s.logger.Printf("cred: %s: command printed no {token, expires_at}", name)
		return execToken{}, errExecTransient
	}
	exp := time.Unix(doc.ExpiresAt, 0)
	if exp.Sub(s.Now()) < serveFloor {
		s.logger.Printf("cred: %s: command printed a token that expires within %s", name, serveFloor)
		return execToken{}, errExecTransient
	}
	return execToken{token: doc.Token, expires: exp}, nil
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("command output too large")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

func (s *Server) answerExec(w http.ResponseWriter, name string) {
	t, err := s.execGet(name, false)
	if err != nil {
		s.writeExecFailure(w, name, err)
		return
	}
	s.clearStale(name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Name      string `json:"name"`
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}{name, t.token, t.expires.Unix()})
}

func (s *Server) refreshExec(w http.ResponseWriter, name string, performed bool) {
	if _, err := s.execGet(name, performed); err != nil {
		s.writeExecFailure(w, name, err)
		return
	}
	s.clearStale(name)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "refreshed": performed})
}

func (s *Server) writeExecFailure(w http.ResponseWriter, name string, err error) {
	if errors.Is(err, errExecSignIn) {
		s.writeStale(w, name)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "transient", "name": name, "reason": errExecTransient.Error()})
}
