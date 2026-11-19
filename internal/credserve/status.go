//go:build linux

package credserve

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

// Status states. "stale" carries "since" (when this server first saw it),
// the shape exporters already key on.
const (
	stateOK       = "ok"
	stateUnminted = "unminted"
	stateStale    = "stale"
	stateFailing  = "failing"
)

type credStatus struct {
	Kind      string `json:"kind"`
	State     string `json:"state"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Since     int64  `json:"since,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// status reports every instance's state without minting, refreshing or
// running anything, and never a token.
func (s *Server) status() map[string]credStatus {
	names := make([]string, 0, len(s.cfg.Instances))
	for n := range s.cfg.Instances {
		names = append(names, n)
	}
	sort.Strings(names)
	now := s.Now()
	out := make(map[string]credStatus, len(names))
	for _, name := range names {
		in := s.cfg.Instances[name]
		st := credStatus{Kind: in.Kind}
		if in.Kind == KindExec {
			st = s.execStatus(name, st, now)
		} else {
			lease, err := s.mgr.Lease(name)
			switch {
			case errors.Is(err, oauth.ErrNotFound):
				st.State = stateUnminted
			case err != nil:
				st.State, st.Reason = stateFailing, "credential state unavailable"
			case lease.SignInNeeded || s.pinnedStale(name, lease):
				st.State, st.Reason = stateStale, reasonSignIn
			case lease.ExpiresAt.Sub(now) < serveFloor:
				st.State, st.Reason, st.ExpiresAt = stateFailing, "token expired and the refresh has not succeeded", lease.ExpiresAt.Unix()
			default:
				st.State, st.ExpiresAt = stateOK, lease.ExpiresAt.Unix()
			}
		}
		if st.State == stateStale {
			st.Since = s.staleSince(name, now).Unix()
		} else {
			s.clearStale(name)
		}
		out[name] = st
	}
	return out
}

func (s *Server) execStatus(name string, st credStatus, now time.Time) credStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.exec.tokens[name]; ok && t.expires.Sub(now) >= serveFloor {
		st.State, st.ExpiresAt = stateOK, t.expires.Unix()
		return st
	}
	switch err := s.exec.lastErr[name]; {
	case errors.Is(err, errExecSignIn):
		st.State, st.Reason = stateStale, reasonSignIn
	case err != nil:
		st.State, st.Reason = stateFailing, errExecTransient.Error()
	default:
		st.State = stateUnminted
	}
	return st
}

// SetStaleFile keeps each stale episode's start on disk at path, so a restart
// reports the same "since" and an alert keyed on it sees one episode, not two.
// Unset (tests, ad hoc runs): episodes live in memory only.
func (s *Server) SetStaleFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staleFile, s.staleLoaded, s.staleAt = path, false, nil
}

// staleSince returns when the stale episode of name began, starting one at now
// if none is open. Callers: /status and every credential_stale answer.
func (s *Server) staleSince(name string, now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadStaleLocked()
	if t, ok := s.staleAt[name]; ok {
		return t
	}
	s.staleAt[name] = now
	s.saveStaleLocked()
	return now
}

func (s *Server) clearStale(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadStaleLocked()
	if _, ok := s.staleAt[name]; !ok {
		return
	}
	delete(s.staleAt, name)
	s.saveStaleLocked()
}

func (s *Server) loadStaleLocked() {
	if s.staleAt == nil {
		s.staleAt = map[string]time.Time{}
	}
	if s.staleLoaded || s.staleFile == "" {
		return
	}
	s.staleLoaded = true
	data, err := os.ReadFile(s.staleFile)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger.Printf("cred: stale episodes unreadable, starting fresh: %v", err)
		}
		return
	}
	var disk map[string]int64
	if err := json.Unmarshal(data, &disk); err != nil {
		s.logger.Printf("cred: stale episodes unreadable, starting fresh: %v", err)
		return
	}
	for n, t := range disk {
		if _, known := s.cfg.Instances[n]; known && t > 0 {
			s.staleAt[n] = time.Unix(t, 0)
		}
	}
}

// saveStaleLocked writes the open episodes (names and start times only, never
// a token) with a rename, so a crash leaves the old file or the new one.
func (s *Server) saveStaleLocked() {
	if s.staleFile == "" {
		return
	}
	disk := make(map[string]int64, len(s.staleAt))
	for n, t := range s.staleAt {
		disk[n] = t.Unix()
	}
	data, _ := json.Marshal(disk)
	tmp := s.staleFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		s.logger.Printf("cred: stale episodes not saved: %v", err)
		return
	}
	if err := os.Rename(tmp, s.staleFile); err != nil {
		s.logger.Printf("cred: stale episodes not saved: %v", err)
	}
}

func (s *Server) serveStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(s.status())
}
