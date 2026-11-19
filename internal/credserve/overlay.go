//go:build linux

package credserve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jack-work/hush/policy"
)

// The runtime overlay: hush is the ONE store of temporary grants and
// suspensions (package policy says how a gateway combines them with standing
// access). Writes come only from the owner socket; a principal with
// overlay = true reads the live overlay. Every create, revoke, lift and expiry
// is one audit line; an entry never names a secret.

const (
	overlayMaxTTL          = 30 * 24 * time.Hour
	overlayMaxGrantsPerSub = 16
	overlayReasonMax       = 200
	overlayReadPath        = "/v1/overlay"
	grantsPath             = "/v1/grants"
	suspensionsPath        = "/v1/suspensions"
)

var (
	overlayGrantRE   = regexp.MustCompile(`^grant-[a-z0-9][a-z0-9-]{0,62}$`)
	overlaySubjectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
)

// overlayKind is one of the two entry kinds: its routes, its audit verbs and
// whether an entry must expire.
type overlayKind struct {
	path, created, removed string
	expires                bool // expires_at is required
	wildcard               bool // grant may be policy.Wildcard
}

var (
	grantKind      = overlayKind{path: grantsPath, created: "granted", removed: "revoked", expires: true}
	suspensionKind = overlayKind{path: suspensionsPath, created: "suspended", removed: "lifted", wildcard: true}
)

type overlayStore struct {
	Sequence    uint64                  `json:"sequence"`
	Grants      map[string]policy.Entry `json:"grants"`
	Suspensions map[string]policy.Entry `json:"suspensions"`
}

func newOverlayStore() overlayStore {
	return overlayStore{Grants: map[string]policy.Entry{}, Suspensions: map[string]policy.Entry{}}
}

func (o *overlayStore) entries(k overlayKind) map[string]policy.Entry {
	if k == grantKind {
		return o.Grants
	}
	return o.Suspensions
}

// SetOverlayFile names where the overlay persists and loads it; entries that
// expired while hush was down are expired now, each with its audit line.
func (s *Server) SetOverlayFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overlayFile = path
	s.overlay = newOverlayStore()
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			s.logger.Printf("cred: overlay unreadable, starting empty: %v", err)
		}
		return
	}
	disk := newOverlayStore()
	if err := json.Unmarshal(data, &disk); err != nil {
		s.logger.Printf("cred: overlay unreadable, starting empty: %v", err)
		return
	}
	if disk.Grants == nil {
		disk.Grants = map[string]policy.Entry{}
	}
	if disk.Suspensions == nil {
		disk.Suspensions = map[string]policy.Entry{}
	}
	s.overlay = disk
	s.sweepOverlayLocked(s.Now())
}

// RunOverlaySweep expires entries every interval until ctx ends, so an expiry
// is audited even when nobody reads.
func (s *Server) RunOverlaySweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			s.sweepOverlayLocked(s.Now())
			s.mu.Unlock()
		}
	}
}

func (s *Server) sweepOverlayLocked(now time.Time) {
	changed := false
	for _, k := range []overlayKind{grantKind, suspensionKind} {
		for id, e := range s.overlay.entries(k) {
			if !e.Live(now) {
				delete(s.overlay.entries(k), id)
				s.logger.Printf("cred: overlay %s expired %s subject=%s grant=%s", id, k.created, e.Subject, e.Grant)
				changed = true
			}
		}
	}
	if changed {
		s.changedOverlayLocked()
	}
}

// changedOverlayLocked moves the sequence on and persists.
func (s *Server) changedOverlayLocked() {
	s.overlay.Sequence++
	if s.overlayFile == "" {
		return
	}
	if err := writeJSONAtomic(s.overlayFile, s.overlay); err != nil {
		s.logger.Printf("cred: overlay not saved: %v", err)
	}
}

// overlayRoute serves the overlay routes to who; owner says whether it may
// write. false when the path is not an overlay route.
func (s *Server) overlayRoute(w http.ResponseWriter, r *http.Request, owner bool, who string) bool {
	if r.URL.Path == overlayReadPath {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
			return true
		}
		s.readOverlay(w)
		return true
	}
	for _, k := range []overlayKind{grantKind, suspensionKind} {
		id, isItem := strings.CutPrefix(r.URL.Path, k.path+"/")
		if r.URL.Path != k.path && !isItem {
			continue
		}
		switch {
		case !owner:
			s.logger.Printf("cred: REFUSED overlay %s %s by %s: owner socket only", r.Method, k.path, who)
			writeError(w, http.StatusForbidden, "forbidden", "the overlay is written on the owner socket only")
		case !isItem && r.Method == http.MethodPost:
			s.createOverlay(w, r, k, who)
		case isItem && r.Method == http.MethodDelete:
			s.removeOverlay(w, k, id, who)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST "+k.path+", DELETE "+k.path+"/<id>")
		}
		return true
	}
	return false
}

// readOverlay answers what still applies: live grants and live suspensions.
func (s *Server) readOverlay(w http.ResponseWriter) {
	s.mu.Lock()
	s.sweepOverlayLocked(s.Now())
	out := policy.Overlay{Sequence: s.overlay.Sequence, Grants: sortedEntries(s.overlay.Grants), Suspensions: sortedEntries(s.overlay.Suspensions)}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

func sortedEntries(m map[string]policy.Entry) []policy.Entry {
	out := make([]policy.Entry, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type overlayRequest struct {
	Subject   string    `json:"subject"`
	Grant     string    `json:"grant"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

func (s *Server) createOverlay(w http.ResponseWriter, r *http.Request, k overlayKind, who string) {
	var req overlayRequest
	if r.URL.RawQuery != "" || !controlBody(r, &req, false) {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request")
		return
	}
	now := s.Now()
	if reason := req.check(k, now); reason != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", reason)
		return
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "no randomness")
		return
	}
	e := policy.Entry{ID: hex.EncodeToString(raw[:]), Subject: req.Subject, Grant: req.Grant, ExpiresAt: req.ExpiresAt, Reason: req.Reason, ApprovedBy: who}
	s.mu.Lock()
	s.sweepOverlayLocked(now)
	full := k == grantKind && s.liveGrantsLocked(req.Subject) >= overlayMaxGrantsPerSub
	if !full {
		s.overlay.entries(k)[e.ID] = e
		s.changedOverlayLocked()
	}
	s.mu.Unlock()
	if full {
		writeError(w, http.StatusConflict, "overlay_full", fmt.Sprintf("%s holds %d temporary grants; revoke one first", req.Subject, overlayMaxGrantsPerSub))
		return
	}
	until := "lifted"
	if !e.ExpiresAt.IsZero() {
		until = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	s.logger.Printf("cred: overlay %s %s subject=%s grant=%s until=%s by=%s reason=%q", e.ID, k.created, e.Subject, e.Grant, until, who, e.Reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(e)
}

func (s *Server) liveGrantsLocked(subject string) int {
	n := 0
	for _, g := range s.overlay.Grants {
		if g.Subject == subject {
			n++
		}
	}
	return n
}

func (s *Server) removeOverlay(w http.ResponseWriter, k overlayKind, id, who string) {
	s.mu.Lock()
	e, ok := s.overlay.entries(k)[id]
	if ok {
		delete(s.overlay.entries(k), id)
		s.changedOverlayLocked()
	}
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such entry")
		return
	}
	s.logger.Printf("cred: overlay %s %s subject=%s grant=%s by=%s", id, k.removed, e.Subject, e.Grant, who)
	w.WriteHeader(http.StatusNoContent)
}

// check refuses a request for kind k at now with a reason, or returns "".
func (q overlayRequest) check(k overlayKind, now time.Time) string {
	switch {
	case !overlaySubjectRE.MatchString(q.Subject):
		return "subject must be a principal name matching " + overlaySubjectRE.String()
	case !overlayGrantRE.MatchString(q.Grant) && !(k.wildcard && q.Grant == policy.Wildcard):
		return "grant must match " + overlayGrantRE.String()
	case k.expires && q.ExpiresAt.IsZero():
		return "expires_at is required"
	case !q.ExpiresAt.IsZero() && !q.ExpiresAt.After(now):
		return "expires_at is not in the future"
	case q.ExpiresAt.Sub(now) > overlayMaxTTL:
		return "expires_at is more than 30 days away"
	case q.Reason == "" || len(q.Reason) > overlayReasonMax || strings.IndexFunc(q.Reason, func(c rune) bool { return c < ' ' || c == 0x7f }) >= 0:
		return "reason must be one printable line of 1 to 200 bytes"
	}
	return ""
}

// authzFields carries the gateway's request id and verified SPIFFE ID into a
// /cred audit line, so a fetch traces back to the request that caused it.
// Values outside a plain character set are logged as "invalid", never raw.
func authzFields(r *http.Request) string {
	out := ""
	for _, f := range []struct{ key, header string }{
		{"request", "X-Authz-Request-Id"},
		{"spiffe", "X-Authz-Spiffe-Id"},
	} {
		v := r.Header.Get(f.header)
		if v == "" {
			continue
		}
		if len(v) > 256 || strings.IndexFunc(v, func(c rune) bool { return !authzChar(c) }) >= 0 {
			v = "invalid"
		}
		out += " " + f.key + "=" + v
	}
	return out
}

func authzChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:/-", c)
}
