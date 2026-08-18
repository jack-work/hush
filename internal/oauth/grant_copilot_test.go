package oauth

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// newGrantManager builds a manager with a throwaway identity and state dir.
func newGrantManager(t *testing.T) *Manager {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(t.TempDir(), []age.Identity{id}, id.Recipient(), testLogger())
	t.Cleanup(m.Stop)
	return m
}

// copilotServer stands in for api.github.com/copilot_internal/v2/token.
type copilotServer struct {
	*httptest.Server
	hits   int
	status int
	body   string
}

func newCopilotServer(t *testing.T) *copilotServer {
	t.Helper()
	cs := &copilotServer{status: 200}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.hits++
		if r.Method != "GET" {
			t.Errorf("exchange method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer gho_") {
			t.Errorf("Authorization = %q: the durable secret must travel as a bearer", got)
		}
		if r.Header.Get("Editor-Version") == "" {
			t.Error("editor headers missing: the endpoint refuses requests without them")
		}
		w.WriteHeader(cs.status)
		if cs.body != "" {
			fmt.Fprint(w, cs.body)
			return
		}
		fmt.Fprintf(w, `{"token":"sess-%d","expires_at":%d,"endpoints":{"api":"https://api.example.com/"}}`,
			cs.hits, time.Now().Add(28*time.Minute).Unix())
	}))
	t.Cleanup(cs.Close)
	return cs
}

func copilotConfig(url string) Config {
	return Config{Name: "copilot", TokenURL: url, Grant: GrantCopilot}
}

// Registration with only the durable GitHub token must mint the first
// session itself: a human has nothing else to give, and failing here is far
// kinder than failing on someone's first turn.
func TestCopilotRegisterMintsFirstSession(t *testing.T) {
	srv := newCopilotServer(t)
	m := newGrantManager(t)

	if err := m.Register(copilotConfig(srv.URL), Tokens{RefreshToken: "gho_durable"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if srv.hits != 1 {
		t.Fatalf("exchanges = %d, want 1", srv.hits)
	}

	tok, meta, err := m.GetFull("copilot")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "sess-1" {
		t.Fatalf("token = %q", tok)
	}
	if meta[CopilotAPIBaseKey] != "https://api.example.com" {
		t.Fatalf("metadata = %v: the API host must survive, with no trailing slash", meta)
	}
}

// Every reader shares one session token, and reading never re-mints: this is
// the property the whole change exists for.
func TestCopilotGetIsCachedAcrossReaders(t *testing.T) {
	srv := newCopilotServer(t)
	m := newGrantManager(t)
	if err := m.Register(copilotConfig(srv.URL), Tokens{RefreshToken: "gho_durable"}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		tok, _, err := m.GetFull("copilot")
		if err != nil {
			t.Fatal(err)
		}
		if tok != "sess-1" {
			t.Fatalf("read %d saw %q: readers diverged", i, tok)
		}
	}
	if srv.hits != 1 {
		t.Fatalf("exchanges = %d, want 1: reading minted a new session", srv.hits)
	}
}

// The durable GitHub token does not rotate, so it must survive every mint
// unchanged - otherwise the second refresh has nothing to present.
func TestCopilotDurableSecretSurvivesMints(t *testing.T) {
	srv := newCopilotServer(t)
	m := newGrantManager(t)
	if err := m.Register(copilotConfig(srv.URL), Tokens{RefreshToken: "gho_durable"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := m.Refresh("copilot"); err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
	}
	if srv.hits != 4 {
		t.Fatalf("exchanges = %d, want 4 (register + 3)", srv.hits)
	}
	st := m.lookup("copilot")
	if got := st.tokens.Load().refresh; got != "gho_durable" {
		t.Fatalf("durable secret = %q, want it unchanged", got)
	}
}

// THE BUG THAT STARTED ALL THIS. GitHub answers a burst on the exchange
// endpoint with 403 and an HTML error page. Read as permanent, it stops the
// proactive loop forever and every consumer is told its credential is gone -
// which is how a working Copilot subscription came to print "No provider
// connected". 403 is a throttle. Only 401 is a revocation.
func TestCopilotStatusClassification(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{200, nil},
		{401, ErrRefreshPermanent},
		{403, ErrRefreshTransient},
		{429, ErrRefreshTransient},
		{500, ErrRefreshTransient},
		{502, ErrRefreshTransient},
	}
	for _, c := range cases {
		got := copilotStatusClass(c.status)
		if c.want == nil && got != nil {
			t.Errorf("status %d: got %v, want nil", c.status, got)
			continue
		}
		if c.want != nil && !errors.Is(got, c.want) {
			t.Errorf("status %d: got %v, want %v", c.status, got, c.want)
		}
	}
}

func TestCopilotUnicornPageIsTransient(t *testing.T) {
	srv := newCopilotServer(t)
	m := newGrantManager(t)
	if err := m.Register(copilotConfig(srv.URL), Tokens{RefreshToken: "gho_durable"}); err != nil {
		t.Fatal(err)
	}

	srv.status = 403
	srv.body = "<!DOCTYPE html>\n<html>\n<head><title>Unicorn! · GitHub</title></head>\n</html>"
	_, err := m.Refresh("copilot")
	if !errors.Is(err, ErrRefreshTransient) {
		t.Fatalf("403 + HTML classified as %v, want transient", err)
	}
	if strings.Count(err.Error(), "\n") > 0 {
		t.Fatalf("an HTML body was pasted whole into the error:\n%s", err)
	}

	// And the credential recovers by itself once GitHub calms down.
	srv.status, srv.body = 200, ""
	tok, err := m.Refresh("copilot")
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if tok == "" {
		t.Fatal("recovery produced no token")
	}
}

func TestCopilotRevokedTokenIsPermanent(t *testing.T) {
	srv := newCopilotServer(t)
	m := newGrantManager(t)
	if err := m.Register(copilotConfig(srv.URL), Tokens{RefreshToken: "gho_durable"}); err != nil {
		t.Fatal(err)
	}
	srv.status, srv.body = 401, `{"message":"Bad credentials"}`
	if _, err := m.Refresh("copilot"); !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("401 classified as %v, want permanent (re-login)", err)
	}
}

// A registration that cannot mint must not be written to disk: a config file
// whose credential never worked is worse than no file.
func TestCopilotRegisterRefusesBadCredential(t *testing.T) {
	srv := newCopilotServer(t)
	srv.status, srv.body = 401, `{"message":"Bad credentials"}`
	m := newGrantManager(t)

	if err := m.Register(copilotConfig(srv.URL), Tokens{RefreshToken: "gho_bogus"}); err == nil {
		t.Fatal("register accepted a credential the exchange rejected")
	}
	if _, err := os.Stat(filepath.Join(m.oauthDir(), "copilot.toml")); !os.IsNotExist(err) {
		t.Fatal("a rejected registration left a file behind")
	}
}

// Grant and metadata must survive a restart, and the metadata must be
// readable without decrypting anything.
func TestCopilotStateSurvivesRestart(t *testing.T) {
	srv := newCopilotServer(t)
	m := newGrantManager(t)
	if err := m.Register(copilotConfig(srv.URL), Tokens{RefreshToken: "gho_durable"}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(m.oauthDir(), "copilot.toml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `grant = "copilot"`) {
		t.Fatalf("grant not persisted:\n%s", text)
	}
	if !strings.Contains(text, "api.example.com") {
		t.Fatalf("metadata not persisted in plaintext:\n%s", text)
	}
	if strings.Contains(text, "gho_durable") || strings.Contains(text, "sess-1") {
		t.Fatal("a secret was written in plaintext")
	}

	cfg, tok, err := m.loadFile(filepath.Join(m.oauthDir(), "copilot.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Grant != GrantCopilot {
		t.Fatalf("reloaded grant = %q", cfg.Grant)
	}
	if tok.metadata[CopilotAPIBaseKey] != "https://api.example.com" {
		t.Fatalf("reloaded metadata = %v", tok.metadata)
	}
	if tok.access != "sess-1" || tok.refresh != "gho_durable" {
		t.Fatal("reloaded tokens do not round-trip")
	}
}

// A file written before grants existed has no `grant` key and must keep
// behaving exactly as it did: refresh_token.
func TestMissingGrantDefaultsToRefreshToken(t *testing.T) {
	g, err := grantFor(Config{Name: "anthropic", TokenURL: "https://example", ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != GrantRefreshToken {
		t.Fatalf("default grant = %q", g.Name())
	}
}

func TestUnknownGrantIsRejected(t *testing.T) {
	if _, err := grantFor(Config{Name: "x", Grant: "wishful"}); !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("unknown grant error = %v", err)
	}
	if err := (&Manager{configs: map[string]*configState{}}).Register(Config{Name: "x", Grant: "wishful"}, Tokens{}); err == nil {
		t.Fatal("registering an unknown grant succeeded")
	}
}
