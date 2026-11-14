//go:build linux

package e2e

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/BurntSushi/toml"

	"github.com/jack-work/hush/internal/oauth"
	"github.com/jack-work/hush/internal/secrets"
)

const (
	credName     = "anthropic-work"
	credSeedRT   = "rt-canary-seed-0123456789"
	credKilledAT = "at-killed"
	credKilledRT = "rt-canary-killed-0123456789"
	credLaterAT  = "at-later"
	credLaterRT  = "rt-canary-later-0123456789"
)

type credMinter struct {
	dir, conf, state, idFile, sock, certFile string
	key                                      *age.X25519Identity
}

func newCredMinter(t *testing.T, ep *httptest.Server) *credMinter {
	t.Helper()
	dir, err := os.MkdirTemp("", "hush-cred-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	m := &credMinter{
		dir: dir, key: key,
		conf:     filepath.Join(dir, "config.toml"),
		state:    filepath.Join(dir, "state"),
		idFile:   filepath.Join(dir, "identity"),
		sock:     filepath.Join(dir, "cred.sock"),
		certFile: filepath.Join(dir, "ca.pem"),
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(m.state, 0o700))
	must(os.WriteFile(m.idFile, []byte(key.String()+"\n"), 0o600))
	must(os.WriteFile(m.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ep.Certificate().Raw}), 0o644))
	must(os.WriteFile(m.conf, []byte(fmt.Sprintf(`recipient = %q
allow_user = "%d"
[instances.%s]
kind = "anthropic"
authorize_url = "https://claude.example/oauth/authorize"
token_url = %q
redirect_uri = "https://console.example/oauth/code/callback"
client_id = "client-1"
`, key.Recipient(), os.Getuid(), credName, ep.URL+"/v1/oauth/token")), 0o600))
	return m
}

func (m *credMinter) seed(t *testing.T, tok oauth.Tokens) {
	t.Helper()
	mgr := oauth.NewManager(m.state, nil, m.key.Recipient(), log.New(io.Discard, "", 0))
	defer mgr.Stop()
	cfg := oauth.Config{Name: credName, TokenURL: "unused", ClientID: "client-1", Grant: oauth.GrantRefreshToken}
	raw, _ := os.ReadFile(m.conf)
	var c struct {
		Instances map[string]struct {
			TokenURL string `toml:"token_url"`
		} `toml:"instances"`
	}
	toml.Unmarshal(raw, &c)
	cfg.TokenURL = c.Instances[credName].TokenURL
	if err := mgr.Register(cfg, tok); err != nil {
		t.Fatal(err)
	}
}

func (m *credMinter) start(t *testing.T, stderr io.Writer) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(hushBin, "cred", "serve", "--config", m.conf, "--state-dir", m.state, "--socket", m.sock)
	cmd.Env = append(os.Environ(), "HUSH_CRED_IDENTITY_FILE="+m.idFile, "SSL_CERT_FILE="+m.certFile, "HOME="+m.dir)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("unix", m.sock); err == nil {
			c.Close()
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("cred serve never listened: %s", stderr)
	return nil
}

func (m *credMinter) get(t *testing.T) (int, string) {
	t.Helper()
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", m.sock)
		},
	}}
	res, err := c.Get("http://minter/cred/" + url.PathEscape(credName))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

func (m *credMinter) diskRefresh(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(m.state, "oauth", credName+".toml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Refresh string `toml:"refresh_token"`
	}
	if _, err := toml.Decode(string(raw), &f); err != nil {
		t.Fatal(err)
	}
	v, err := secrets.DecryptValue(f.Refresh, []age.Identity{m.key})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// Persist-before-use: the minter dies between the token POST and the write.
// The rotation it never persisted is never served, and the next life refreshes
// from the refresh token that is on disk.
func TestCredServeKilledMidRefreshServesNothingUnpersisted(t *testing.T) {
	var phase atomic.Int32
	posted := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	var refreshUsed []string
	ep := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		refreshUsed = append(refreshUsed, r.PostForm.Get("refresh_token"))
		mu.Unlock()
		if phase.Load() == 0 {
			posted <- struct{}{}
			<-release
			fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"expires_in":3600}`, credKilledAT, credKilledRT)
			return
		}
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"expires_in":3600}`, credLaterAT, credLaterRT)
	}))
	defer ep.Close()
	defer close(release)

	m := newCredMinter(t, ep)
	m.seed(t, oauth.Tokens{AccessToken: "at-seed", RefreshToken: credSeedRT, ExpiresIn: 5})

	logs := &lockedBuffer{}
	first := m.start(t, logs)
	go func() {
		c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", m.sock)
		}}}
		if res, err := c.Get("http://minter/cred/" + credName); err == nil {
			res.Body.Close()
		}
	}()
	select {
	case <-posted:
	case <-time.After(10 * time.Second):
		t.Fatalf("no refresh POST: %s", logs)
	}
	first.Process.Kill()
	first.Wait()
	release <- struct{}{}

	if got := m.diskRefresh(t); got != credSeedRT {
		t.Fatalf("disk holds %q after the kill, want the seed", got)
	}

	phase.Store(1)
	m.start(t, logs)
	status, body := m.get(t)
	if strings.Contains(body, credKilledAT) {
		t.Fatalf("the unpersisted rotation was served: %s", body)
	}
	if status != 200 || !strings.Contains(body, credLaterAT) {
		t.Fatalf("got %d %s", status, body)
	}
	mu.Lock()
	used := append([]string(nil), refreshUsed...)
	mu.Unlock()
	if len(used) != 2 || used[1] != credSeedRT {
		t.Fatalf("the second life refreshed with %v, want the persisted seed", used)
	}
	if got := m.diskRefresh(t); got != credLaterRT {
		t.Fatalf("disk holds %q, want the rotation that was served", got)
	}

	for _, secret := range []string{credSeedRT, credKilledRT, credLaterRT} {
		if strings.Contains(logs.String(), secret) || strings.Contains(body, secret) {
			t.Fatalf("a refresh token reached the log or a reply:\n%s\n%s", logs, body)
		}
	}
}

func TestCredServeRefusesToStartWithTheWrongIdentity(t *testing.T) {
	ep := httptest.NewTLSServer(http.NotFoundHandler())
	defer ep.Close()
	m := newCredMinter(t, ep)
	other, _ := age.GenerateX25519Identity()
	os.WriteFile(m.idFile, []byte(other.String()+"\n"), 0o600)
	cmd := exec.Command(hushBin, "cred", "serve", "--config", m.conf, "--state-dir", m.state, "--socket", m.sock, "--identity-file", m.idFile)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "no key for the config's recipient") {
		t.Fatalf("started with a key logins do not encrypt to: %v %s", err, out)
	}
	if strings.Contains(string(out), other.String()) {
		t.Fatal("the identity was printed")
	}
}
