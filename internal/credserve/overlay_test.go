//go:build linux

package credserve

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jack-work/hush/policy"
)

// front reads the overlay, rou2 reads credentials only, the allow_user socket
// ("legacy") reads it too; only the overlay admin socket ("admin") writes.
const overlayPrincipals = `
[overlay_admin]
socket = "/run/hush-test/overlay-admin.sock"
users = ["me"]

[principals.front]
users = ["me"]
overlay = true

[principals.rou2]
users = ["me"]
credentials = ["anthropic-work"]
`

// testClock is a clock tests move while the server reads it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// t0 is now (to the second), so the seeded token stays fresh while the clock moves.
var t0 = time.Now().UTC().Truncate(time.Second)

// newOverlayRig serves overlayPrincipals on a test clock at t0, the overlay
// persisted in the rig's state dir; admin is the overlay admin socket's one uid
// (default: this process's).
func newOverlayRig(t *testing.T, admin ...uint32) (*prig, *testClock, string) {
	t.Helper()
	clock := &testClock{t: t0}
	var file string
	if len(admin) == 0 {
		admin = []uint32{uint32(os.Getuid())}
	}
	p := newPrincipalRig(t, "me", overlayPrincipals, func(r *rig) {
		r.srv.Now = clock.now
		file = filepath.Join(r.stateDir, "overlay.json")
		r.srv.SetOverlayFile(file)
		r.srv.SetOverlayAdmins(map[uint32]bool{admin[0]: true})
	})
	return p, clock, file
}

func entryBody(subject, grant string, expires time.Time, reason string) string {
	b := map[string]any{"subject": subject, "grant": grant, "reason": reason}
	if !expires.IsZero() {
		b["expires_at"] = expires
	}
	out, _ := json.Marshal(b)
	return string(out)
}

var oneHour = entryBody("keel", "grant-ghe", t0.Add(time.Hour), "review PR")

func readOverlay(t *testing.T, p *prig) policy.Overlay {
	t.Helper()
	a := p.request("front", http.MethodGet, overlayReadPath)
	var o policy.Overlay
	if a.status != 200 || json.Unmarshal([]byte(a.raw), &o) != nil {
		t.Fatalf("read overlay: %d %q", a.status, a.raw)
	}
	return o
}

func create(t *testing.T, p *prig, path, body string) policy.Entry {
	t.Helper()
	a := p.call("admin", http.MethodPost, path, body, nil)
	var e policy.Entry
	if a.status != 201 || json.Unmarshal([]byte(a.raw), &e) != nil {
		t.Fatalf("create on %s: %d %q", path, a.status, a.raw)
	}
	return e
}

// logLine returns the one log line that contains marker (failing on none or
// several), so a test compares the whole line, not a fragment.
func logLine(t *testing.T, logs, marker string) string {
	t.Helper()
	var hits []string
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, marker) {
			hits = append(hits, l)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("%d log lines contain %q, want 1:\n%s", len(hits), marker, logs)
	}
	return hits[0]
}

// Who may do what, socket by socket. RED if the admin socket stops writing, if
// the allow_user socket or a principal may write (the self-grant hole), or if a
// principal without overlay = true may read.
func TestOverlayAccessBySocket(t *testing.T) {
	for _, c := range []struct {
		socket, method, path, body string
		status                     int
		code                       string // the error code of a refusal
		stored                     int
	}{
		{"admin", http.MethodPost, grantsPath, oneHour, 201, "", 1},
		{"admin", http.MethodPost, suspensionsPath, oneHour, 201, "", 1},
		{"admin", http.MethodGet, overlayReadPath, "", 200, "", 0},
		{"admin", http.MethodGet, "/cred/" + instName, "", 404, "not_found", 0},
		{"admin", http.MethodPut, grantsPath, oneHour, 405, "method_not_allowed", 0},
		{"admin", http.MethodPost, overlayReadPath, oneHour, 405, "method_not_allowed", 0},
		{"admin", http.MethodDelete, grantsPath + "/0123456789abcdef", "", 404, "not_found", 0},
		{"legacy", http.MethodGet, overlayReadPath, "", 200, "", 0},
		{"legacy", http.MethodPost, grantsPath, oneHour, 403, "forbidden", 0},
		{"legacy", http.MethodPost, suspensionsPath, oneHour, 403, "forbidden", 0},
		{"front", http.MethodGet, overlayReadPath, "", 200, "", 0},
		{"front", http.MethodPost, grantsPath, oneHour, 403, "forbidden", 0},
		{"front", http.MethodPost, suspensionsPath, oneHour, 403, "forbidden", 0},
		{"front", http.MethodDelete, suspensionsPath + "/0123456789abcdef", "", 403, "forbidden", 0},
		{"rou2", http.MethodGet, overlayReadPath, "", 403, "forbidden", 0},
		{"rou2", http.MethodPost, grantsPath, oneHour, 403, "forbidden", 0},
	} {
		name := fmt.Sprintf("%s %s %s", c.socket, c.method, c.path)
		t.Run(name, func(t *testing.T) {
			p, _, _ := newOverlayRig(t)
			if a := p.call(c.socket, c.method, c.path, c.body, nil); a.status != c.status || a.Error != c.code {
				t.Fatalf("%s: got %d %q, want %d %q", name, a.status, a.raw, c.status, c.code)
			}
			if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != c.stored {
				t.Fatalf("%s: stored %+v, want %d entries", name, o, c.stored)
			}
		})
	}
}

// The admin socket serves only its listed uids. RED if the uid check goes.
func TestOverlayAdminSocketRefusesOtherUIDs(t *testing.T) {
	p, _, _ := newOverlayRig(t, otherUID)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, grantsPath, oneHour},
		{http.MethodPost, suspensionsPath, oneHour},
		{http.MethodGet, overlayReadPath, ""},
	} {
		if a := p.call("admin", c.method, c.path, c.body, nil); a.status != 403 || a.Error != "forbidden" || a.Reason != "peer not allowed" {
			t.Fatalf("%s %s from a non-admin uid: %d %q", c.method, c.path, a.status, a.raw)
		}
	}
	if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != 0 {
		t.Fatalf("stored: %+v", o)
	}
	if want := fmt.Sprintf("cred: refused peer uid %d on the overlay admin socket\n", os.Getuid()); strings.Count(p.logs.String(), want) != 3 {
		t.Fatalf("refusal lines: %q", p.logs.String())
	}
}

// Every refusal of a write, by its exact reason, at each boundary and one past
// it; the legal edge of each boundary is accepted. Literal numbers on purpose:
// RED if the 30-day bound, the 200-byte reason cap or a name pattern moves.
func TestOverlayValidatesEntries(t *testing.T) {
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	const month = 720 * time.Hour // 30 days, written out
	long := func(n int) string { return strings.Repeat("a", n) }
	const (
		badSubject = "subject must be a principal name matching ^[a-z0-9][a-z0-9_.-]{0,63}$"
		badGrant   = "grant must match ^grant-[a-z0-9][a-z0-9-]{0,62}$"
		badReason  = "reason must be one printable line of 1 to 200 bytes"
	)
	for _, c := range []struct {
		name, path, body, reason string // reason "" = accepted
	}{
		{"subject empty", grantsPath, entryBody("", "grant-x", at(time.Hour), "r"), badSubject},
		{"subject whitespace", grantsPath, entryBody(" keel", "grant-x", at(time.Hour), "r"), badSubject},
		{"subject unicode", grantsPath, entryBody("kéel", "grant-x", at(time.Hour), "r"), badSubject},
		{"subject a SPIFFE ID", grantsPath, entryBody("spiffe://cheroot/node/n1", "grant-x", at(time.Hour), "r"), badSubject},
		{"subject 64 bytes", grantsPath, entryBody(long(64), "grant-x", at(time.Hour), "r"), ""},
		{"subject 65 bytes", grantsPath, entryBody(long(65), "grant-x", at(time.Hour), "r"), badSubject},
		{"grant without prefix", grantsPath, entryBody("keel", "ghe", at(time.Hour), "r"), badGrant},
		{"grant nested", grantsPath, entryBody("keel", "grant-a]b[c", at(time.Hour), "r"), badGrant},
		{"grant 69 bytes", grantsPath, entryBody("keel", "grant-"+long(63), at(time.Hour), "r"), ""},
		{"grant 70 bytes", grantsPath, entryBody("keel", "grant-"+long(64), at(time.Hour), "r"), badGrant},
		{"wildcard on a grant", grantsPath, entryBody("keel", "*", at(time.Hour), "r"), badGrant},
		{"wildcard on a suspension", suspensionsPath, entryBody("keel", "*", at(time.Hour), "r"), ""},
		{"grant without expiry", grantsPath, entryBody("keel", "grant-x", time.Time{}, "r"), "expires_at is required"},
		{"suspension without expiry", suspensionsPath, entryBody("keel", "grant-x", time.Time{}, "r"), ""},
		{"expiry now", grantsPath, entryBody("keel", "grant-x", at(0), "r"), "expires_at is not in the future"},
		{"expiry 1 ms ahead", grantsPath, entryBody("keel", "grant-x", at(time.Millisecond), "r"), ""},
		{"grant 30 days", grantsPath, entryBody("keel", "grant-x", at(month), "r"), ""},
		{"grant 30 days + 1 ms", grantsPath, entryBody("keel", "grant-x", at(month+time.Millisecond), "r"), "expires_at is more than 30 days away"},
		{"suspension 30 days + 1 ms", suspensionsPath, entryBody("keel", "*", at(month+time.Millisecond), "r"), "expires_at is more than 30 days away"},
		{"suspension in the past", suspensionsPath, entryBody("keel", "*", at(-time.Second), "r"), "expires_at is not in the future"},
		{"reason empty", grantsPath, entryBody("keel", "grant-x", at(time.Hour), ""), badReason},
		{"reason two lines", grantsPath, entryBody("keel", "grant-x", at(time.Hour), "a\nb"), badReason},
		{"reason 200 bytes of unicode", grantsPath, entryBody("keel", "grant-x", at(time.Hour), strings.Repeat("é", 100)), ""},
		{"reason 201 bytes", grantsPath, entryBody("keel", "grant-x", at(time.Hour), long(201)), badReason},
		{"unknown field", grantsPath, `{"subject":"keel","grant":"grant-x","expires_at":"` + at(time.Hour).Format(time.RFC3339) + `","reason":"r","effect":"allow"}`, "invalid request"},
		{"not JSON", suspensionsPath, `suspend everyone`, "invalid request"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, _ := newOverlayRig(t)
			a := p.call("admin", http.MethodPost, c.path, c.body, nil)
			stored := len(readOverlay(t, p).Grants) + len(readOverlay(t, p).Suspensions)
			switch {
			case c.reason == "" && (a.status != 201 || stored != 1):
				t.Fatalf("%s: want accepted, got %d %q (%d stored)", c.name, a.status, a.raw, stored)
			case c.reason != "" && (a.status != 400 || a.Error != "invalid_request" || a.Reason != c.reason || stored != 0):
				t.Fatalf("%s: want 400 %q, got %d %q (%d stored)", c.name, c.reason, a.status, a.raw, stored)
			}
		})
	}
}

// At most 16 live temporary grants per subject (literal); another subject is
// not affected. RED if the cap goes or counts across subjects.
func TestOverlayCapsGrantsAt16PerSubject(t *testing.T) {
	p, _, _ := newOverlayRig(t)
	for i := 0; i < 16; i++ {
		create(t, p, grantsPath, entryBody("keel", fmt.Sprintf("grant-s%d", i), t0.Add(time.Hour), "r"))
	}
	if a := p.call("admin", http.MethodPost, grantsPath, oneHour, nil); a.status != 409 || a.Error != "overlay_full" ||
		a.Reason != "keel holds 16 temporary grants; revoke one first" {
		t.Fatalf("the 17th grant: %d %q", a.status, a.raw)
	}
	create(t, p, grantsPath, entryBody("rou2", "grant-ghe", t0.Add(time.Hour), "r"))
	if n := len(readOverlay(t, p).Grants); n != 17 {
		t.Fatalf("%d grants stored, want 17", n)
	}
}

// Only what still applies is served; every change moves the sequence; each
// expiry is one exact audit line and leaves the disk. RED if the sweep stops
// deleting, or a read serves an expired entry.
func TestOverlayServesLiveEntriesOnly(t *testing.T) {
	p, clock, file := newOverlayRig(t)
	g := create(t, p, grantsPath, oneHour)
	create(t, p, suspensionsPath, entryBody("keel", "*", time.Time{}, "incident 7"))
	s := create(t, p, suspensionsPath, entryBody("rou2", "grant-ado", t0.Add(30*time.Minute), "r"))
	var seq uint64
	for _, c := range []struct {
		name                string
		at                  time.Duration
		grants, suspensions int
	}{
		{"all live", 0, 1, 2},
		{"the suspension's last ms", 30*time.Minute - time.Millisecond, 1, 2},
		{"the suspension expired", 30 * time.Minute, 1, 1},
		{"the grant expired", time.Hour, 0, 1},
	} {
		clock.set(t0.Add(c.at))
		o := readOverlay(t, p)
		if len(o.Grants) != c.grants || len(o.Suspensions) != c.suspensions || o.Sequence < seq {
			t.Fatalf("%s: %+v (previous sequence %d)", c.name, o, seq)
		}
		seq = o.Sequence
	}
	if seq != 5 { // 3 creates + 2 expiries
		t.Fatalf("sequence %d, want 5", seq)
	}
	for _, want := range []string{
		"cred: overlay " + s.ID + " expired suspended subject=rou2 grant=grant-ado",
		"cred: overlay " + g.ID + " expired granted subject=keel grant=grant-ghe",
	} {
		if got := logLine(t, p.logs.String(), strings.Fields(want)[2]+" expired"); got != want {
			t.Fatalf("expiry line %q, want %q", got, want)
		}
	}
	disk, err := os.ReadFile(file)
	var stored overlayStore
	if err != nil || json.Unmarshal(disk, &stored) != nil || len(stored.Grants) != 0 || len(stored.Suspensions) != 1 || stored.Sequence != 5 {
		t.Fatalf("disk after expiry: %s (%v)", disk, err)
	}
}

// Revoke and lift, each on its own path, with exact audit lines. RED if a
// DELETE stops removing or crosses kinds.
func TestOverlayRevokeAndLift(t *testing.T) {
	p, _, _ := newOverlayRig(t)
	g := create(t, p, grantsPath, oneHour)
	s := create(t, p, suspensionsPath, entryBody("keel", "*", time.Time{}, "r"))
	admin := fmt.Sprintf("admin:%d", os.Getuid())
	for _, c := range []struct {
		name, path string
		status     int
	}{
		{"a grant's id on the suspensions path", suspensionsPath + "/" + g.ID, 404},
		{"revoke", grantsPath + "/" + g.ID, 204},
		{"revoke again", grantsPath + "/" + g.ID, 404},
		{"lift", suspensionsPath + "/" + s.ID, 204},
	} {
		if a := p.request("admin", http.MethodDelete, c.path); a.status != c.status {
			t.Fatalf("%s: %d %q, want %d", c.name, a.status, a.raw, c.status)
		}
	}
	if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != 0 {
		t.Fatalf("left: %+v", o)
	}
	for _, want := range []string{
		"cred: overlay " + g.ID + " revoked subject=keel grant=grant-ghe by=" + admin,
		"cred: overlay " + s.ID + " lifted subject=keel grant=* by=" + admin,
	} {
		if got := logLine(t, p.logs.String(), " "+strings.Fields(want)[3]+" subject="); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// The overlay survives a restart with its sequence; an entry that expired
// while hush was down is expired (one exact audit line) on load, never served.
// RED if loading skips the sweep.
func TestOverlaySurvivesRestart(t *testing.T) {
	p, _, file := newOverlayRig(t)
	short := create(t, p, grantsPath, entryBody("keel", "grant-short", t0.Add(time.Hour), "r"))
	create(t, p, grantsPath, entryBody("keel", "grant-long", t0.Add(3*time.Hour), "r"))
	logs := &syncBuffer{}
	next := NewServer(p.cfg, p.mgr, 0, log.New(logs, "", 0))
	next.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	next.SetOverlayFile(file)
	if len(next.overlay.Grants) != 1 || next.overlay.Sequence != 3 {
		t.Fatalf("after restart: %+v, want 1 grant at sequence 3", next.overlay)
	}
	if got, want := strings.TrimSpace(logs.String()), "cred: overlay "+short.ID+" expired granted subject=keel grant=grant-short"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// What the gateway reads decides as the shared table says: a suspension of
// every service beats a standing grant.
func TestOverlayFeedsPolicy(t *testing.T) {
	p, _, _ := newOverlayRig(t)
	until := t0.Add(time.Hour)
	create(t, p, suspensionsPath, entryBody("keel", "*", until, "incident 7"))
	d := policy.Decide(policy.Request{Principal: "keel", Service: "ghe", Standing: true, Ceiling: true, Now: t0}, readOverlay(t, p))
	if want := (policy.Decision{Status: 403, Text: "suspended for ghe until " + until.Format(time.RFC3339)}); d != want {
		t.Fatalf("got %+v, want %+v", d, want)
	}
}

// The gateway's request id and verified SPIFFE ID ride into the /cred audit
// line, exactly; a value with anything outside the plain set is "invalid".
// RED if the sanitizer goes (the injected row forges a second audit line).
func TestCredAuditCarriesAuthzHeaders(t *testing.T) {
	const box = "spiffe://cheroot/node/n1/unit/sandbox.service/a"
	uid := os.Getuid()
	for _, c := range []struct {
		name, request, spiffe, want string
	}{
		{"plain", "4f1c-9a", box, fmt.Sprintf("cred: audit anthropic-work principal=rou2 uid=%d request=4f1c-9a spiffe=%s -> 200", uid, box)},
		{"injected", "x -> 200 cred: audit forged", box, fmt.Sprintf("cred: audit anthropic-work principal=rou2 uid=%d request=invalid spiffe=%s -> 200", uid, box)},
		{"unicode", "réq", "", fmt.Sprintf("cred: audit anthropic-work principal=rou2 uid=%d request=invalid -> 200", uid)},
		{"256 bytes", strings.Repeat("a", 256), "", fmt.Sprintf("cred: audit anthropic-work principal=rou2 uid=%d request=%s -> 200", uid, strings.Repeat("a", 256))},
		{"too long", strings.Repeat("a", 257), "", fmt.Sprintf("cred: audit anthropic-work principal=rou2 uid=%d request=invalid -> 200", uid)},
		{"absent", "", "", fmt.Sprintf("cred: audit anthropic-work principal=rou2 uid=%d -> 200", uid)},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, _ := newOverlayRig(t)
			h := map[string]string{}
			if c.request != "" {
				h["X-Authz-Request-Id"] = c.request
			}
			if c.spiffe != "" {
				h["X-Authz-Spiffe-Id"] = c.spiffe
			}
			if a := p.call("rou2", http.MethodGet, "/cred/"+instName, "", h); a.status != 200 {
				t.Fatalf("%s: fetch %d %q", c.name, a.status, a.raw)
			}
			if got := logLine(t, p.logs.String(), "cred: audit"); got != c.want {
				t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
			}
		})
	}
}
