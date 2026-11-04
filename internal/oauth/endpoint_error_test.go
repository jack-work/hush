package oauth

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

const (
	leakAccess  = "acc-0123456789abcdef0123456789abcdef"
	leakRefresh = "rt_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
	leakPrev    = "rt_prev_00112233445566778899aabbccdd"
)

type echoDoer struct {
	status int
	body   string
}

func (d echoDoer) Do(req *http.Request) (*http.Response, error) {
	_, _ = io.ReadAll(req.Body)
	return &http.Response{StatusCode: d.status, Body: io.NopCloser(strings.NewReader(d.body))}, nil
}

func loggedManager(t *testing.T, dir string, key *age.X25519Identity) (*Manager, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	m := NewManager(dir, []age.Identity{key}, key.Recipient(), log.New(&buf, "", 0))
	t.Cleanup(m.Stop)
	return m, &buf
}

func registerLeaky(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.Register(testCfg, Tokens{AccessToken: leakAccess, RefreshToken: leakRefresh, ExpiresIn: 600}); err != nil {
		t.Fatalf("register: %v", err)
	}
	st := m.lookup(testCfg.Name)
	withPrev := *st.tokens.Load()
	withPrev.prevRefresh = leakPrev
	st.tokens.Store(&withPrev)
}

func assertNoToken(t *testing.T, where, s string) {
	t.Helper()
	for _, tok := range []string{leakAccess, leakRefresh, leakPrev} {
		if strings.Contains(s, tok) {
			t.Errorf("%s carries a token: %q", where, s)
		}
	}
}

// An endpoint may echo request fields in its error body; none of it may reach
// the error the agent forwards, the persisted relogin mark, or the log.
func TestARefusalNeverCarriesTheTokenEndpointBody(t *testing.T) {
	for name, body := range map[string]string{
		"json description": `{"error":"invalid_grant","error_description":"unknown refresh_token ` + leakRefresh + ` for client-1"}`,
		"json extra field": `{"error":"invalid_grant","refresh_token":"` + leakRefresh + `","access_token":"` + leakAccess + `"}`,
		"form echo":        "grant_type=refresh_token&refresh_token=" + leakRefresh + "&client_id=client-1",
		"html page":        "<html><body>bad request: " + leakPrev + "</body></html>",
	} {
		t.Run(name, func(t *testing.T) {
			dir, key := t.TempDir(), newTestKey(t)
			m, logs := loggedManager(t, dir, key)
			registerLeaky(t, m)
			m.httpClient = echoDoer{status: 400, body: body}

			_, _, err := m.RefreshFull(testCfg.Name)
			if !errors.Is(err, ErrRefreshPermanent) {
				t.Fatalf("err = %v, want ErrRefreshPermanent", err)
			}
			assertNoToken(t, "error", err.Error())
			assertNoToken(t, "log", logs.String())

			_, disk, _, lerr := m.loadFile(m.filePath(testCfg.Name))
			if lerr != nil {
				t.Fatalf("load: %v", lerr)
			}
			assertNoToken(t, "persisted relogin mark", disk.relogin)

			raw, rerr := os.ReadFile(m.filePath(testCfg.Name))
			if rerr != nil {
				t.Fatalf("read: %v", rerr)
			}
			assertNoToken(t, "token file", string(raw))
		})
	}
}

// A transient failure is never latched, so its error reaches the caller as the
// grant wrote it.
func TestATransientFailureNeverCarriesTheBody(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m, logs := loggedManager(t, dir, key)
	registerLeaky(t, m)
	m.httpClient = echoDoer{status: 503, body: "upstream said: refresh_token=" + leakRefresh}

	_, _, err := m.RefreshFull(testCfg.Name)
	if err == nil || errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v, want a transient failure", err)
	}
	assertNoToken(t, "error", err.Error())
	assertNoToken(t, "log", logs.String())
}

// The latch redacts every token the grant holds, including ones the endpoint
// echo did not send and that are too short for the long-run pattern.
func TestTheLatchRedactsTheGrantsOwnTokens(t *testing.T) {
	const access, refresh = "acc-short-123456", "rt-short-1234567"
	dir, key := t.TempDir(), newTestKey(t)
	m, _ := loggedManager(t, dir, key)
	if err := m.Register(testCfg, Tokens{AccessToken: access, RefreshToken: refresh, ExpiresIn: 600}); err != nil {
		t.Fatalf("register: %v", err)
	}
	m.httpClient = echoDoer{status: 400, body: `{"error":"invalid_grant","error_description":"bearer ` + access + ` is stale"}`}

	_, _, err := m.RefreshFull(testCfg.Name)
	if !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v, want ErrRefreshPermanent", err)
	}
	if strings.Contains(err.Error(), access) {
		t.Errorf("error carries the access token: %v", err)
	}
	if got := m.lookup(testCfg.Name).tokens.Load().relogin; strings.Contains(got, access) {
		t.Errorf("relogin mark carries the access token: %q", got)
	}
}

func TestScrubReasonRedactsKnownSecrets(t *testing.T) {
	got := scrubReason("token endpoint 400: invalid_grant: no such token abcdefghij", "abcdefghij", "short")
	if want := "token endpoint 400: invalid_grant: no such token " + redacted; got != want {
		t.Errorf("scrubReason = %q, want %q", got, want)
	}
}

func TestAnInvalidGrantStillSaysInvalidGrant(t *testing.T) {
	m, _, _, _ := deadGrant(t)
	_, err := m.Refresh(testCfg.Name)
	if !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v, want ErrRefreshPermanent", err)
	}
	if !strings.Contains(err.Error(), "invalid_grant: The refresh token has not been found") {
		t.Errorf("error lost the RFC 6749 code and description: %v", err)
	}
	if got := m.lookup(testCfg.Name).tokens.Load().relogin; !strings.HasPrefix(got, "token endpoint 400: invalid_grant") {
		t.Errorf("relogin mark = %q", got)
	}
}

// A mark persisted by an older hush may hold the raw body; loading rewrites it.
func TestALoadedReloginMarkHoldingABodyIsRewritten(t *testing.T) {
	for name, tc := range map[string]struct{ mark, want string }{
		"json body with a code": {`token endpoint 400: {"error":"invalid_grant","echo":"` + leakRefresh + `"}`, "invalid_grant"},
		"body without a code":   {"token endpoint 400: <html>" + leakPrev + "</html>", refusedReason},
		"clean mark kept":       {"token endpoint 400: invalid_grant: token revoked", "token endpoint 400: invalid_grant: token revoked"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, key := t.TempDir(), newTestKey(t)
			m, _ := loggedManager(t, dir, key)
			registerLeaky(t, m)
			st := m.lookup(testCfg.Name)
			marked := *st.tokens.Load()
			marked.relogin = tc.mark
			if err := m.saveFile(st.cfg, marked); err != nil {
				t.Fatalf("save: %v", err)
			}

			restarted, logs := loggedManager(t, dir, key)
			if err := restarted.Start(); err != nil {
				t.Fatalf("start: %v", err)
			}
			if got := restarted.lookup(testCfg.Name).tokens.Load().relogin; got != tc.want {
				t.Errorf("loaded relogin = %q, want %q", got, tc.want)
			}
			raw, err := os.ReadFile(m.filePath(testCfg.Name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			assertNoToken(t, "token file after load", string(raw))
			assertNoToken(t, "log", logs.String())
			if tc.mark != tc.want && !strings.Contains(logs.String(), "relogin mark rewritten") {
				t.Errorf("rewrite not logged: %q", logs.String())
			}
		})
	}
}

func TestEndpointDetail(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"code only":         {`{"error":"invalid_client"}`, "invalid_client"},
		"control chars":     {`{"error":"invalid_grant","error_description":"line one\nline\ttwo"}`, "invalid_grant: line one line two"},
		"not an error code": {`{"error":"<script>"}`, "body of 20 bytes"},
		"not json":          {"Bad Gateway", "body of 11 bytes"},
		"echoed token":      {`{"error":"invalid_grant","error_description":"bad token ` + leakRefresh + `"}`, "invalid_grant: bad token " + redacted},
		"long description":  {`{"error":"invalid_grant","error_description":"` + strings.Repeat("x ", 100) + `"}`, "invalid_grant: " + strings.Repeat("x ", 60)[:descriptionMax] + "..."},
	} {
		t.Run(name, func(t *testing.T) {
			if got := endpointDetail([]byte(tc.body)); got != tc.want {
				t.Errorf("endpointDetail = %q, want %q", got, tc.want)
			}
		})
	}
}
