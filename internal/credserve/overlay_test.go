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

// t0 is now, so the seeded token stays fresh while the clock moves.
var t0 = time.Now().UTC().Truncate(time.Second)

// newOverlayRig serves overlayPrincipals on clock, the overlay persisted in
// the rig's state dir and admin the overlay admin socket's one uid.
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

func TestOverlayAccessBySocket(t *testing.T) {
	for _, c := range []struct {
		socket, method, path, body string
		status, stored             int
	}{
		{"admin", http.MethodPost, grantsPath, oneHour, 201, 1},
		{"admin", http.MethodPost, suspensionsPath, oneHour, 201, 1},
		{"admin", http.MethodGet, overlayReadPath, "", 200, 0},
		{"admin", http.MethodGet, "/cred/" + instName, "", 404, 0},
		{"admin", http.MethodPut, grantsPath, oneHour, 405, 0},
		{"admin", http.MethodPost, overlayReadPath, oneHour, 405, 0},
		{"admin", http.MethodDelete, grantsPath + "/0123456789abcdef", "", 404, 0},
		{"legacy", http.MethodGet, overlayReadPath, "", 200, 0},
		{"legacy", http.MethodPost, grantsPath, oneHour, 403, 0},
		{"legacy", http.MethodPost, suspensionsPath, oneHour, 403, 0},
		{"front", http.MethodGet, overlayReadPath, "", 200, 0},
		{"front", http.MethodPost, grantsPath, oneHour, 403, 0},
		{"front", http.MethodPost, suspensionsPath, oneHour, 403, 0},
		{"front", http.MethodDelete, suspensionsPath + "/0123456789abcdef", "", 403, 0},
		{"rou2", http.MethodGet, overlayReadPath, "", 403, 0},
		{"rou2", http.MethodPost, grantsPath, oneHour, 403, 0},
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
			if a := p.call("admin", http.MethodPost, c.path, c.body, nil); a.status != 400 {
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
	if a := p.call("admin", http.MethodPost, grantsPath, oneHour, nil); a.status != 409 || a.Error != "overlay_full" {
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
		if a := p.request("admin", http.MethodDelete, c.path); a.status != c.status {
			t.Fatalf("DELETE %s: %d %q, want %d", c.path, a.status, a.raw, c.status)
		}
	}
	if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != 0 {
		t.Fatalf("left: %+v", o)
	}
	for _, line := range []string{g.ID + " revoked subject=keel grant=grant-ghe by=admin:", s.ID + " lifted subject=keel grant=* by=admin:"} {
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

// The admin socket serves only its listed uids: any other peer is refused
// before routing, and nothing is stored.
func TestOverlayAdminSocketRefusesOtherUIDs(t *testing.T) {
	p, _, _ := newOverlayRig(t, otherUID)
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, grantsPath, oneHour},
		{http.MethodPost, suspensionsPath, oneHour},
		{http.MethodGet, overlayReadPath, ""},
	} {
		if a := p.call("admin", c.method, c.path, c.body, nil); a.status != 403 {
			t.Fatalf("%s %s from a non-admin uid: %d %q", c.method, c.path, a.status, a.raw)
		}
	}
	if o := readOverlay(t, p); len(o.Grants)+len(o.Suspensions) != 0 {
		t.Fatalf("stored: %+v", o)
	}
	if !strings.Contains(p.logs.String(), "refused peer uid") {
		t.Fatalf("no refusal line:\n%s", p.logs.String())
	}
}

// TestOverlayWritesNeedTheGateSignIn: with a login gate, an overlay write on
// the admin socket also needs a bearer the provider honours for a member of
// the gate's group; reads do not.
func TestOverlayWritesNeedTheGateSignIn(t *testing.T) {
	var base string
	p := newPrincipalRig(t, "me", overlayPrincipals, func(r *rig) {
		base = r.ep.srv.URL
		r.cfg.LoginGate = &LoginGate{Issuer: base + "/idp", ClientID: "hush-cli", Group: "hush-admin",
			RedirectURI: "https://relay.example/cb", Relay: base + "/relay"}
		if err := r.cfg.LoginGate.validate(); err != nil {
			t.Fatal(err)
		}
		r.srv.LoginClient = FencedClient(r.cfg.EgressHosts(), r.ep.roots())
		r.srv.SetOverlayFile(filepath.Join(r.stateDir, "overlay.json"))
		r.srv.SetOverlayAdmins(map[uint32]bool{uint32(os.Getuid()): true})
		r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
			switch req.URL.Path {
			case "/idp/.well-known/openid-configuration":
				return 200, fmt.Sprintf(`{"issuer":%[1]q,"token_endpoint":"%[1]s/token","userinfo_endpoint":"%[1]s/userinfo"}`, base+"/idp")
			case "/idp/userinfo":
				switch req.Header.Get("Authorization") {
				case "Bearer tok-admin":
					return 200, `{"preferred_username":"jack","groups":["hush-admin@idm.example"]}`
				case "Bearer tok-other":
					return 200, `{"preferred_username":"eve","groups":["users@idm.example"]}`
				}
				return 401, `{"error":"invalid_token"}`
			}
			return 404, `{}`
		})
	})
	const signIn = `{"error":"sign_in_required","reason":"an overlay write needs the login gate's sign-in"}` + "\n"
	for _, c := range []struct {
		name, method, path, auth string
		status                   int
		raw                      string // the exact answer body ("" = not pinned: a created entry)
	}{
		{"a read needs no sign-in", http.MethodGet, overlayReadPath, "", 200, ""},
		{"a write without a sign-in", http.MethodPost, grantsPath, "", 401, signIn},
		{"an empty bearer", http.MethodPost, grantsPath, "Bearer ", 401, signIn},
		{"a lowercase scheme", http.MethodPost, grantsPath, "bearer tok-admin", 401, signIn},
		{"another scheme", http.MethodPost, grantsPath, "Basic dG9rLWFkbWlu", 401, signIn},
		{"a delete without a sign-in", http.MethodDelete, grantsPath + "/0123456789abcdef", "", 401, signIn},
		{"a token the provider no longer honours", http.MethodPost, grantsPath, "Bearer tok-expired", 403,
			`{"error":"forbidden","reason":"login gate: userinfo 401: the provider refused the token"}` + "\n"},
		{"a doubled scheme", http.MethodPost, grantsPath, "Bearer Bearer tok-admin", 403,
			`{"error":"forbidden","reason":"login gate: userinfo 401: the provider refused the token"}` + "\n"},
		{"a non-member", http.MethodPost, suspensionsPath, "Bearer tok-other", 403,
			`{"error":"forbidden","reason":"login gate: eve is not in hush-admin"}` + "\n"},
		{"a member", http.MethodPost, grantsPath, "Bearer tok-admin", 201, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			var h map[string]string
			if c.auth != "" {
				h = map[string]string{"Authorization": c.auth}
			}
			body := ""
			if c.method == http.MethodPost {
				body = oneHour
			}
			a := p.call("admin", c.method, c.path, body, h)
			if a.status != c.status || c.raw != "" && a.raw != c.raw {
				t.Fatalf("%s: got %d %q, want %d %q", c.name, a.status, a.raw, c.status, c.raw)
			}
			if c.status == 201 {
				var e policy.Entry
				_ = json.Unmarshal([]byte(a.raw), &e)
				if want := fmt.Sprintf("admin:%d:jack", os.Getuid()); e.ApprovedBy != want {
					t.Fatalf("%s: approved_by %q, want %q", c.name, e.ApprovedBy, want)
				}
			}
		})
	}
	if o := readOverlay(t, p); len(o.Grants) != 1 || len(o.Suspensions) != 0 {
		t.Fatalf("only the member's write may land: %+v", o)
	}
}
