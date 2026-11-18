//go:build linux

package credserve

import (
	"encoding/json"
	"errors"
	"net/http"
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
			case lease.SignInNeeded || (in.Kind == KindChatGPT && !oauth.ValidAccountID(lease.AccountID)):
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

func (s *Server) staleSince(name string, now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.staleAt == nil {
		s.staleAt = map[string]time.Time{}
	}
	if t, ok := s.staleAt[name]; ok {
		return t
	}
	s.staleAt[name] = now
	return now
}

func (s *Server) clearStale(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.staleAt, name)
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
