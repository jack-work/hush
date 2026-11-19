//go:build linux

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// fakeAdmin serves an overlay admin socket that records each request and
// answers status with body.
type fakeAdmin struct {
	mu     sync.Mutex
	method string
	path   string
	body   map[string]any
}

func overlayRig(t *testing.T, status int, answer string) (string, *fakeAdmin) {
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
		f.method, f.path, f.body = r.Method, r.URL.Path, nil
		_ = json.Unmarshal(raw, &f.body)
		f.mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, answer)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	cfg := writeCredConfig(t)
	extra := "\n[overlay_admin]\nsocket = \"" + sock + "\"\nusers = [\"0\"]\n"
	f2, _ := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	f2.WriteString(extra)
	f2.Close()
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

func TestCredOverlayCommands(t *testing.T) {
	entry := `{"id":"0123456789abcdef","subject":"keel","grant":"grant-ghe","expires_at":"2030-01-01T00:00:00Z","reason":"r","approved_by":"admin:0"}`
	cases := []struct {
		name       string
		args       []string
		status     int
		answer     string
		method     string // "" = no request may reach the socket
		path, want string
	}{
		{"grant", []string{"grant", "keel", "grant-ghe", "--for", "1h", "--reason", "review"}, 201, entry, "POST", "/v1/grants", "0123456789abcdef"},
		{"suspend until lifted", []string{"suspend", "keel", "*", "--reason", "incident"}, 201, entry, "POST", "/v1/suspensions", "0123456789abcdef"},
		{"revoke", []string{"revoke", "0123456789abcdef"}, 204, "", "DELETE", "/v1/grants/0123456789abcdef", ""},
		{"lift", []string{"lift", "0123456789abcdef"}, 204, "", "DELETE", "/v1/suspensions/0123456789abcdef", ""},
		{"ls", []string{"ls"}, 200, `{"sequence":3,"grants":[` + entry + `],"suspensions":[]}`, "GET", "/v1/overlay", "0123456789abcdef  keel"},
		{"server refusal surfaces", []string{"grant", "keel", "grant-ghe", "--for", "1h", "--reason", "x"}, 409, `{"error":"overlay_full","reason":"keel holds 16"}`, "POST", "/v1/grants", "409 overlay_full: keel holds 16"},
		{"grant without --for", []string{"grant", "keel", "grant-ghe", "--reason", "x"}, 201, entry, "", "", "--for must be positive"},
		{"no --reason", []string{"grant", "keel", "grant-ghe", "--for", "1h"}, 201, entry, "", "", "--reason is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, f := overlayRig(t, c.status, c.answer)
			out, err := runOverlay(t, append(c.args, "--config", cfg)...)
			f.mu.Lock()
			defer f.mu.Unlock()
			got := out
			if err != nil {
				got = err.Error()
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("got %q (err %v), want %q", out, err, c.want)
			}
			if f.method != c.method || f.path != c.path {
				t.Fatalf("socket saw %q %q, want %q %q", f.method, f.path, c.method, c.path)
			}
			if c.name == "grant" {
				exp, _ := time.Parse(time.RFC3339, f.body["expires_at"].(string))
				if f.body["subject"] != "keel" || f.body["grant"] != "grant-ghe" || f.body["reason"] != "review" || time.Until(exp) < 59*time.Minute {
					t.Fatalf("sent %v", f.body)
				}
			}
			if c.name == "suspend until lifted" {
				if _, has := f.body["expires_at"]; has {
					t.Fatalf("a suspension without --for sent an expiry: %v", f.body)
				}
			}
		})
	}
}

func TestCredOverlayNeedsAnAdminSocket(t *testing.T) {
	_, err := runOverlay(t, "ls", "--config", writeCredConfig(t))
	if err == nil || !strings.Contains(err.Error(), "no overlay_admin socket") {
		t.Fatalf("got %v", err)
	}
}
