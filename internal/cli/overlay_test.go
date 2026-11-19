//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// fakeAdmin serves an overlay admin socket that records each request and
// answers status with body.
type fakeAdmin struct {
	mu     sync.Mutex
	calls  int
	method string
	path   string
	auth   string
	body   map[string]any
}

func (f *fakeAdmin) seen() fakeAdmin {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fakeAdmin{calls: f.calls, method: f.method, path: f.path, auth: f.auth, body: f.body}
}

// overlayRig serves a fake admin socket and writes a cred config naming it;
// gate, when set, is a [login_gate] section appended to the config.
func overlayRig(t *testing.T, status int, answer, gate string) (string, *fakeAdmin) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ov")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAdmin{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls++
		f.method, f.path, f.auth, f.body = r.Method, r.URL.Path, r.Header.Get("Authorization"), nil
		_ = json.Unmarshal(raw, &f.body)
		f.mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, answer)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	cfg := writeCredConfig(t)
	fh, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fh.WriteString("\n[overlay_admin]\nsocket = \"" + sock + "\"\nusers = [\"0\"]\n" + gate)
	fh.Close()
	return cfg, f
}

func runOverlay(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	rootCmd.SetOut(out)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		for _, c := range []*cobra.Command{credOverlayGrantCmd, credOverlaySuspendCmd} { // cobra keeps flag values between runs
			c.Flags().Set("for", "0")
			c.Flags().Set("reason", "")
		}
	})
	err := runCred(t, append([]string{"cred", "overlay"}, args...)...)
	return out.String(), err
}

var overlayT0 = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

// A gate whose provider cannot be reached: a write must fail at sign-in,
// before anything reaches the socket; a read needs no sign-in.
const deadGate = "\n[login_gate]\nissuer = \"https://127.0.0.1:1/idp\"\nclient_id = \"hush-cli\"\ngroup = \"hush-admin\"\nredirect_uri = \"https://127.0.0.1:1/cb\"\nrelay = \"https://127.0.0.1:1/code\"\n"

func TestCredOverlayCommands(t *testing.T) {
	old := overlayNow
	overlayNow = func() time.Time { return overlayT0 }
	t.Cleanup(func() { overlayNow = old })
	entry := `{"id":"0123456789abcdef","subject":"keel","grant":"grant-ghe","expires_at":"2030-01-01T00:00:00Z","reason":"r","approved_by":"admin:0"}`
	cases := []struct {
		name   string
		args   []string
		gate   string
		status int
		answer string
		calls  int // requests that reached the socket
		method string
		path   string
		body   map[string]any // the exact JSON sent, when calls == 1 and a body is sent
		out    string         // the exact stdout
		err    string         // the exact error ("" = none)
	}{
		{"grant", []string{"grant", "keel", "grant-ghe", "--for", "1h", "--reason", "review"}, "", 201, entry, 1, "POST", "/v1/grants",
			map[string]any{"subject": "keel", "grant": "grant-ghe", "reason": "review", "expires_at": "2026-11-19T13:00:00Z"}, "0123456789abcdef\n", ""},
		{"grant for the 30 d cap", []string{"grant", "keel", "grant-ghe", "--for", "720h", "--reason", "r"}, "", 201, entry, 1, "POST", "/v1/grants",
			map[string]any{"subject": "keel", "grant": "grant-ghe", "reason": "r", "expires_at": "2026-12-19T12:00:00Z"}, "0123456789abcdef\n", ""},
		{"suspend until lifted sends no expiry", []string{"suspend", "keel", "*", "--reason", "incident"}, "", 201, entry, 1, "POST", "/v1/suspensions",
			map[string]any{"subject": "keel", "grant": "*", "reason": "incident"}, "0123456789abcdef\n", ""},
		{"suspend for an hour", []string{"suspend", "keel", "grant-ghe", "--for", "1h", "--reason", "x"}, "", 201, entry, 1, "POST", "/v1/suspensions",
			map[string]any{"subject": "keel", "grant": "grant-ghe", "reason": "x", "expires_at": "2026-11-19T13:00:00Z"}, "0123456789abcdef\n", ""},
		{"revoke", []string{"revoke", "0123456789abcdef"}, "", 204, "", 1, "DELETE", "/v1/grants/0123456789abcdef", nil, "", ""},
		{"lift", []string{"lift", "0123456789abcdef"}, "", 204, "", 1, "DELETE", "/v1/suspensions/0123456789abcdef", nil, "", ""},
		{"ls", []string{"ls"}, "", 200, `{"sequence":3,"grants":[` + entry + `],"suspensions":[]}`, 1, "GET", "/v1/overlay", nil,
			"KIND   ID                SUBJECT  GRANT      EXPIRES               BY       REASON\ngrant  0123456789abcdef  keel     grant-ghe  2030-01-01T00:00:00Z  admin:0  r\n", ""},
		{"ls reads without the gate's sign-in", []string{"ls"}, deadGate, 200, `{"sequence":0,"grants":[],"suspensions":[]}`, 1, "GET", "/v1/overlay", nil,
			"KIND  ID  SUBJECT  GRANT  EXPIRES  BY  REASON\n", ""},
		{"a server refusal surfaces exactly", []string{"grant", "keel", "grant-ghe", "--for", "1h", "--reason", "x"}, "", 409, `{"error":"overlay_full","reason":"keel holds 16 temporary grants; revoke one first"}`, 1, "POST", "/v1/grants",
			map[string]any{"subject": "keel", "grant": "grant-ghe", "reason": "x", "expires_at": "2026-11-19T13:00:00Z"}, "", "POST /v1/grants: 409 overlay_full: keel holds 16 temporary grants; revoke one first"},
		{"a write with a gate signs in first (no request on failure)", []string{"grant", "keel", "grant-ghe", "--for", "1h", "--reason", "x"}, deadGate, 201, entry, 0, "", "", nil, "", "login gate: discover https://127.0.0.1:1/idp/.well-known/openid-configuration: Get \"https://127.0.0.1:1/idp/.well-known/openid-configuration\": dial tcp 127.0.0.1:1: connect: connection refused"},
		{"a delete with a gate signs in first", []string{"revoke", "0123456789abcdef"}, deadGate, 204, "", 0, "", "", nil, "", "login gate: discover https://127.0.0.1:1/idp/.well-known/openid-configuration: Get \"https://127.0.0.1:1/idp/.well-known/openid-configuration\": dial tcp 127.0.0.1:1: connect: connection refused"},
		{"a grant without --for", []string{"grant", "keel", "grant-ghe", "--reason", "x"}, "", 201, entry, 0, "", "", nil, "", "--for must be positive (a grant always expires)"},
		{"a negative --for", []string{"suspend", "keel", "*", "--for", "-1s", "--reason", "x"}, "", 201, entry, 0, "", "", nil, "", "--for must be positive (a grant always expires)"},
		{"no --reason", []string{"grant", "keel", "grant-ghe", "--for", "1h"}, "", 201, entry, 0, "", "", nil, "", "--reason is required"},
		{"a whitespace --reason", []string{"suspend", "keel", "*", "--reason", " \t"}, "", 201, entry, 0, "", "", nil, "", "--reason is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, f := overlayRig(t, c.status, c.answer, c.gate)
			out, err := runOverlay(t, append(c.args, "--config", cfg)...)
			got := f.seen()
			if c.err == "" && err != nil || c.err != "" && (err == nil || err.Error() != c.err) {
				t.Fatalf("%s: error %v, want %q", c.name, err, c.err)
			}
			if out != c.out {
				t.Fatalf("%s: stdout %q, want %q", c.name, out, c.out)
			}
			if got.calls != c.calls || got.method != c.method || got.path != c.path {
				t.Fatalf("%s: socket saw %d calls, last %q %q; want %d %q %q", c.name, got.calls, got.method, got.path, c.calls, c.method, c.path)
			}
			if gb, _ := json.Marshal(got.body); c.body != nil {
				if wb, _ := json.Marshal(c.body); string(gb) != string(wb) {
					t.Fatalf("%s: sent %s, want %s", c.name, gb, wb)
				}
			}
			if got.auth != "" {
				t.Fatalf("%s: no gate, yet sent Authorization %q", c.name, got.auth)
			}
		})
	}
}

// TestCredOverlayCarriesTheSignIn: after a sign-in, every request carries the
// bearer (RED if the header goes: the admin socket would answer 401).
func TestCredOverlayCarriesTheSignIn(t *testing.T) {
	cfg, f := overlayRig(t, 204, "", "")
	cmd := &cobra.Command{}
	cmd.Flags().String("config", cfg, "")
	o, err := newOverlayClient(cmd)
	if err != nil {
		t.Fatal(err)
	}
	o.bearer = "tok-admin"
	if err := o.do(context.Background(), http.MethodDelete, "/v1/grants/0123456789abcdef", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := f.seen().auth; got != "Bearer tok-admin" {
		t.Fatalf("Authorization %q, want %q", got, "Bearer tok-admin")
	}
}

func TestCredOverlayNeedsAnAdminSocket(t *testing.T) {
	cfg := writeCredConfig(t)
	_, err := runOverlay(t, "ls", "--config", cfg)
	if want := cfg + " has no overlay_admin socket"; err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
}
