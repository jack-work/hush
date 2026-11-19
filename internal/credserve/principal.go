//go:build linux

package credserve

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// PrincipalAuth is a principal resolved for serving: its uids and grants.
type PrincipalAuth struct {
	Name        string
	UIDs        map[uint32]bool
	Credentials map[string]bool
	Login       bool
	Refresh     bool
}

// ResolvePrincipals turns the config's principals into uid sets, using
// lookup to resolve each user name (or number).
func ResolvePrincipals(c *Config, lookup func(string) (uint32, error)) (map[string]PrincipalAuth, error) {
	out := make(map[string]PrincipalAuth, len(c.Principals))
	for name, p := range c.Principals {
		pa := PrincipalAuth{Name: name, UIDs: map[uint32]bool{}, Credentials: map[string]bool{}, Login: p.Login, Refresh: p.Refresh}
		for _, u := range p.Users {
			uid, err := lookup(u)
			if err != nil {
				return nil, fmt.Errorf("principal %s: user %s: %w", name, u, err)
			}
			pa.UIDs[uid] = true
		}
		for _, cred := range p.Credentials {
			pa.Credentials[cred] = true
		}
		out[name] = pa
	}
	return out, nil
}

type principalKey struct{}

const principalOnlyCred = "a principal socket serves /cred/<name> only"

// PrincipalListener tags every connection ln accepts with principal, so
// requests on it are judged against that principal's grants.
func PrincipalListener(ln net.Listener, principal string) net.Listener {
	return principalListener{Listener: ln, principal: principal}
}

type principalListener struct {
	net.Listener
	principal string
}

func (l principalListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &principalConn{Conn: c, principal: l.principal}, nil
}

type principalConn struct {
	net.Conn
	principal string
}

// SetPrincipals installs the resolved principals. legacy says whether the
// allow_user socket exists; without it, an untagged connection is refused.
func (s *Server) SetPrincipals(ps map[string]PrincipalAuth, legacy bool) {
	s.principals = ps
	s.noLegacy = !legacy
}

func (s *Server) servePrincipal(w http.ResponseWriter, r *http.Request, name string) {
	p, known := s.principals[name]
	uid, hasUID := r.Context().Value(peerKey{}).(uint32)
	if !known || !hasUID || !p.UIDs[uid] {
		if hasUID {
			s.logger.Printf("cred: refused peer uid %d on principal %s", uid, name)
		} else {
			s.logger.Printf("cred: refused a peer without credentials on principal %s", name)
		}
		writeError(w, http.StatusForbidden, "forbidden", "peer not allowed")
		return
	}
	if p.Login && s.loginRoute(w, r) {
		return
	}
	if p.Refresh && s.refreshRoute(w, r) {
		return
	}
	cred, found := strings.CutPrefix(r.URL.Path, "/cred/")
	if !found || cred == "" || strings.Contains(cred, "/") || r.Method != http.MethodGet {
		// The broker this replaces answers exactly this on a principal socket; callers may match on it.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": principalOnlyCred})
		return
	}
	grant, err := s.authorizeCred(p, cred)
	if err != nil {
		// Checked before existence, so a principal learns nothing about
		// credentials it was not granted.
		s.logger.Printf("cred: REFUSED %s for principal %s uid %d: not granted", cred, name, uid)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "not_granted",
			"name":   cred,
			"reason": fmt.Sprintf("credential %q is not granted to principal %q", cred, name),
		})
		return
	}
	if grant != nil {
		// A consent grant use is always audited, with the grant id and its approver. Never the token.
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		w = rec
		defer func() {
			s.logger.Printf("cred: consent-grant use %q principal=%s credential=%s uid=%d approved_by=%q expires_at=%d -> %d",
				grant.ID, name, cred, uid, grant.ApprovedBy, int64(grant.ExpiresAt), rec.status)
		}()
		if _, ok := s.cfg.Instances[cred]; !ok {
			writeError(w, http.StatusNotFound, "unknown_credential", "no such credential")
			return
		}
	}
	s.answer(w, cred)
}

// statusRecorder remembers the status a handler wrote, for the audit line.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// InheritedListeners returns the sockets systemd passed, keyed by their
// FileDescriptorName (LISTEN_FDNAMES). It returns nil when the process was
// not socket-activated.
func InheritedListeners() (map[string]net.Listener, error) {
	pidStr, fdsStr := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	if pidStr == "" || fdsStr == "" {
		return nil, nil
	}
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid != os.Getpid() {
		return nil, nil
	}
	n, err := strconv.Atoi(fdsStr)
	if err != nil {
		return nil, fmt.Errorf("socket activation: LISTEN_FDS=%q is not a number", fdsStr)
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	out := make(map[string]net.Listener, n)
	for i := 0; i < n; i++ {
		fd := 3 + i
		syscall.CloseOnExec(fd)
		name := "unknown"
		if i < len(names) && names[i] != "" {
			name = names[i]
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("socket activation: two descriptors named %q", name)
		}
		f := os.NewFile(uintptr(fd), name)
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("socket activation: descriptor %q: %w", name, err)
		}
		out[name] = ln
	}
	return out, nil
}
