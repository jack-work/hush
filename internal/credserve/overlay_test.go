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

// front reads the overlay, rou2 reads credentials only; the allow_user socket
// ("legacy") is the owner, the only writer.
const overlayPrincipals = `
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

// t0 is now, so the seeded token stays fresh while the clock moves.
var t0 = time.Now().UTC().Truncate(time.Second)

// newOverlayRig serves overlayPrincipals on clock, the overlay persisted in
// the rig's state dir; before runs once the overlay is loaded.
func newOverlayRig(t *testing.T, before ...func(*rig)) (*prig, *testClock, string) {
	t.Helper()
	clock := &testClock{t: t0}
	var file string
	p := newPrincipalRig(t, "me", overlayPrincipals, append([]func(*rig){func(r *rig) {
		r.srv.Now = clock.now
		file = filepath.Join(r.stateDir, "overlay.json")
		r.srv.SetOverlayFile(file)
	}}, before...)...)
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
	a := p.call("legacy", http.MethodPost, path, body, nil)
	var e policy.Entry
	if a.status != 201 || json.Unmarshal([]byte(a.raw), &e) != nil {
		t.Fatalf("create on %s: %d %q", path, a.status, a.raw)
	}
	return e
}

func TestOverlayAccessBySocket(t *testing.T) {
	for _, c := range []struct {
		socket, method, path, body string
		status, stored             int
	}{
		{"legacy", http.MethodPost, grantsPath, oneHour, 201, 1},
		{"legacy", http.MethodPost, suspensionsPath, oneHour, 201, 1},
		{"legacy", http.MethodGet, overlayReadPath, "", 200, 0},
		{"front", http.MethodGet, overlayReadPath, "", 200, 0},
		{"front", http.MethodPost, grantsPath, oneHour, 403, 0},
		{"front", http.MethodPost, suspensionsPath, oneHour, 403, 0},
		{"front", http.MethodDelete, suspensionsPath + "/0123456789abcdef", "", 403, 0},
		{"rou2", http.MethodGet, overlayReadPath, "", 404, 0},
		{"rou2", http.MethodPost, grantsPath, oneHour, 404, 0},
		{"legacy", http.MethodPut, grantsPath, oneHour, 405, 0},
		{"legacy", http.MethodPost, overlayReadPath, oneHour, 405, 0},
		{"legacy", http.MethodDelete, grantsPath + "/0123456789abcdef", "", 404, 0},
	} {
		t.Run(fmt.Sprintf("%s %s %s", c.socket, c.method, c.path), func(t *testing.T) {
			p, _, _ := newOverlayRig(t)
			if a := p.call(c.socket, c.method, c.path, c.body, nil); a.status != c.status {
				t.Fatalf("got %d %q, want %d", a.status, a.raw, c.status)
			}
			if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != c.stored {
				t.Fatalf("stored %+v, want %d entries", o, c.stored)
			}
		})
	}
}

func TestOverlayRefusesBadEntries(t *testing.T) {
	in := func(d time.Duration) time.Time { return t0.Add(d) }
	for _, c := range []struct{ name, path, body string }{
		{"subject", grantsPath, entryBody("Not a subject!", "grant-x", in(time.Hour), "r")},
		{"spiffe subject", grantsPath, entryBody("spiffe://cheroot/node/n1", "grant-x", in(time.Hour), "r")},
		{"grant name", grantsPath, entryBody("keel", "ghe", in(time.Hour), "r")},
		{"wildcard grant", grantsPath, entryBody("keel", "*", in(time.Hour), "r")},
		{"grant without expiry", grantsPath, entryBody("keel", "grant-x", time.Time{}, "r")},
		{"expired grant", grantsPath, entryBody("keel", "grant-x", in(0), "r")},
		{"grant past 30 d", grantsPath, entryBody("keel", "grant-x", in(overlayMaxTTL+time.Second), "r")},
		{"expired suspension", suspensionsPath, entryBody("keel", "*", in(-time.Second), "r")},
		{"suspension past 30 d", suspensionsPath, entryBody("keel", "*", in(overlayMaxTTL+time.Second), "r")},
		{"no reason", grantsPath, entryBody("keel", "grant-x", in(time.Hour), "")},
		{"two-line reason", grantsPath, entryBody("keel", "grant-x", in(time.Hour), "a\nb")},
		{"long reason", grantsPath, entryBody("keel", "grant-x", in(time.Hour), strings.Repeat("r", overlayReasonMax+1))},
		{"unknown field", grantsPath, `{"subject":"keel","grant":"grant-x","expires_at":"` + in(time.Hour).Format(time.RFC3339) + `","reason":"r","effect":"allow"}`},
		{"not JSON", suspensionsPath, `suspend everyone`},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, _ := newOverlayRig(t)
			if a := p.call("legacy", http.MethodPost, c.path, c.body, nil); a.status != 400 {
				t.Fatalf("got %d %q, want 400", a.status, a.raw)
			}
			if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != 0 {
				t.Fatalf("a refused entry was stored: %+v", o)
			}
		})
	}
}

// At most overlayMaxGrantsPerSub live temporary grants per subject; another
// subject is not affected.
func TestOverlayCapsGrantsPerSubject(t *testing.T) {
	p, _, _ := newOverlayRig(t)
	for i := 0; i < overlayMaxGrantsPerSub; i++ {
		create(t, p, grantsPath, entryBody("keel", fmt.Sprintf("grant-s%d", i), t0.Add(time.Hour), "r"))
	}
	if a := p.call("legacy", http.MethodPost, grantsPath, oneHour, nil); a.status != 409 || a.Error != "overlay_full" {
		t.Fatalf("over the cap: %d %q, want 409 overlay_full", a.status, a.raw)
	}
	create(t, p, grantsPath, entryBody("rou2", "grant-ghe", t0.Add(time.Hour), "r"))
}

// Only what still applies is served; every change moves the sequence; each
// expiry is audited once and leaves the disk.
func TestOverlayServesLiveEntriesOnly(t *testing.T) {
	p, clock, file := newOverlayRig(t)
	create(t, p, grantsPath, oneHour)
	create(t, p, suspensionsPath, entryBody("keel", "*", time.Time{}, "incident 7"))
	create(t, p, suspensionsPath, entryBody("rou2", "grant-ado", t0.Add(30*time.Minute), "r"))
	var seq uint64
	for _, c := range []struct {
		at                  time.Duration
		grants, suspensions int
	}{
		{0, 1, 2},
		{45 * time.Minute, 1, 1},
		{2 * time.Hour, 0, 1},
	} {
		clock.set(t0.Add(c.at))
		o := readOverlay(t, p)
		if len(o.Grants) != c.grants || len(o.Suspensions) != c.suspensions || o.Sequence <= seq {
			t.Fatalf("at +%s: %+v (previous sequence %d)", c.at, o, seq)
		}
		seq = o.Sequence
	}
	if n := strings.Count(p.logs.String(), " expired "); n != 2 {
		t.Fatalf("%d expiry audit lines, want 2:\n%s", n, p.logs.String())
	}
	if disk, _ := os.ReadFile(file); strings.Contains(string(disk), "grant-ghe") || !strings.Contains(string(disk), "incident 7") {
		t.Fatalf("disk after expiry: %s", disk)
	}
}

func TestOverlayRevokeAndLift(t *testing.T) {
	p, _, _ := newOverlayRig(t)
	g := create(t, p, grantsPath, oneHour)
	s := create(t, p, suspensionsPath, entryBody("keel", "*", time.Time{}, "r"))
	for _, c := range []struct {
		path   string
		status int
	}{
		{suspensionsPath + "/" + g.ID, 404}, // a grant's id on the suspensions path
		{grantsPath + "/" + g.ID, 204},
		{grantsPath + "/" + g.ID, 404},
		{suspensionsPath + "/" + s.ID, 204},
	} {
		if a := p.request("legacy", http.MethodDelete, c.path); a.status != c.status {
			t.Fatalf("DELETE %s: %d %q, want %d", c.path, a.status, a.raw, c.status)
		}
	}
	if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != 0 {
		t.Fatalf("left: %+v", o)
	}
	for _, line := range []string{g.ID + " revoked subject=keel grant=grant-ghe by=owner", s.ID + " lifted subject=keel grant=* by=owner"} {
		if !strings.Contains(p.logs.String(), line) {
			t.Fatalf("no audit line %q:\n%s", line, p.logs.String())
		}
	}
}

// The overlay survives a restart with its sequence; an entry that expired
// while hush was down is expired (and audited) on load, never served.
func TestOverlaySurvivesRestart(t *testing.T) {
	p, _, file := newOverlayRig(t)
	create(t, p, grantsPath, entryBody("keel", "grant-short", t0.Add(time.Hour), "r"))
	create(t, p, grantsPath, entryBody("keel", "grant-long", t0.Add(3*time.Hour), "r"))
	before := readOverlay(t, p).Sequence
	logs := &syncBuffer{}
	next := NewServer(p.cfg, p.mgr, 0, log.New(logs, "", 0))
	next.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	next.SetOverlayFile(file)
	if len(next.overlay.Grants) != 1 || next.overlay.Sequence <= before {
		t.Fatalf("after restart: %+v (sequence before %d)", next.overlay, before)
	}
	if !strings.Contains(logs.String(), "grant=grant-short") {
		t.Fatalf("expiry while down not audited:\n%s", logs.String())
	}
}

// What the gateway reads decides as the shared table says: a suspension of
// every service beats a standing grant.
func TestOverlayFeedsPolicy(t *testing.T) {
	p, _, _ := newOverlayRig(t)
	create(t, p, suspensionsPath, entryBody("keel", "*", t0.Add(time.Hour), "incident 7"))
	d := policy.Decide(policy.Request{Principal: "keel", Service: "ghe", Standing: true, Ceiling: true, Now: t0}, readOverlay(t, p))
	if d.Allow || d.Status != 403 || !strings.HasPrefix(d.Text, "suspended for ghe until ") {
		t.Fatalf("got %+v", d)
	}
}

// The gateway's request id and verified SPIFFE ID ride into the /cred audit
// line; a value with anything outside the plain set is logged as "invalid".
func TestCredAuditCarriesAuthzHeaders(t *testing.T) {
	const box = "spiffe://cheroot/node/n1/unit/sandbox.service/a"
	for _, c := range []struct {
		name, request, spiffe, want string
	}{
		{"plain", "4f1c-9a", box, " request=4f1c-9a spiffe=" + box + " "},
		{"injected", "x -> 200 cred: audit forged", box, " request=invalid spiffe=" + box + " "},
		{"absent", "", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, _, _ := newOverlayRig(t)
			h := map[string]string{}
			if c.request != "" {
				h["X-Authz-Request-Id"], h["X-Authz-Spiffe-Id"] = c.request, c.spiffe
			}
			if a := p.call("rou2", http.MethodGet, "/cred/"+instName, "", h); a.status != 200 {
				t.Fatalf("fetch: %d %q", a.status, a.raw)
			}
			logs := p.logs.String()
			if c.want == "" && strings.Contains(logs, "request=") || !strings.Contains(logs, c.want) ||
				strings.Contains(logs, "forged") || strings.Contains(logs, "at-seed") {
				t.Fatalf("audit line wrong (want %q, no token, no forged line):\n%s", c.want, logs)
			}
		})
	}
}
