//go:build linux

package credserve

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

func getStatus(t *testing.T, c *http.Client) (int, map[string]credStatus, string) {
	t.Helper()
	res, err := c.Get("http://minter/status")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var doc map[string]credStatus
	if res.StatusCode == 200 {
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("status is not JSON: %q", body)
		}
	}
	return res.StatusCode, doc, string(body)
}

func TestStatusReportsOAuthStatesWithoutMintingOrTokens(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	status, doc, raw := getStatus(t, r.client)
	if status != 200 {
		t.Fatalf("got %d %q", status, raw)
	}
	// Seeded on disk (loaded at start): ok; never signed in: unminted.
	if doc[instName].State != stateOK || doc["copilot-work"].State != stateUnminted {
		t.Fatalf("before any read: %q", raw)
	}
	r.get(instName)
	_, doc, raw = getStatus(t, r.client)
	if st := doc[instName]; st.State != stateOK || st.Kind != "refresh_token" || st.ExpiresAt == 0 {
		t.Fatalf("after a read: %q", raw)
	}
	if strings.Contains(raw, "at-seed") || strings.Contains(raw, "rt-canary") {
		t.Fatalf("a token reached /status: %q", raw)
	}
	if n := r.ep.posts.Load(); n != 0 {
		t.Fatalf("/status cost %d POSTs", n)
	}
}

func TestStatusStaleCarriesSinceAndClears(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	r.get(instName)
	r.ep.setAnswer(func(int64, *http.Request) (int, string) { return 400, `{"error":"invalid_grant"}` })
	r.skew(2 * time.Hour)
	r.get(instName) // refresh refused: sign-in needed
	_, doc, raw := getStatus(t, r.client)
	st := doc[instName]
	if st.State != stateStale || st.Since == 0 || st.Reason != reasonSignIn {
		t.Fatalf("after a refused refresh: %q", raw)
	}
	_, again, _ := getStatus(t, r.client)
	if again[instName].Since != st.Since {
		t.Fatalf("since moved between polls: %d then %d", st.Since, again[instName].Since)
	}
}

func TestStatusReportsExecStatesWithoutRunning(t *testing.T) {
	e := newExecRig(t, "ok")
	if _, doc, raw := getStatus(t, e.client); doc["ado-feed"].State != stateUnminted || e.runs() != 0 {
		t.Fatalf("before any read: %q, runs %d", raw, e.runs())
	}
	e.do(http.MethodGet, "/cred/ado-feed")
	if _, doc, raw := getStatus(t, e.client); doc["ado-feed"].State != stateOK || strings.Contains(raw, "tok-1") {
		t.Fatalf("after a read: %q", raw)
	}
	e2 := newExecRig(t, "signin")
	e2.do(http.MethodGet, "/cred/ado-feed")
	if _, doc, raw := getStatus(t, e2.client); doc["ado-feed"].State != stateStale || doc["ado-feed"].Since == 0 {
		t.Fatalf("after sign-in needed: %q", raw)
	}
	e3 := newExecRig(t, "fail")
	e3.do(http.MethodGet, "/cred/ado-feed")
	if _, doc, raw := getStatus(t, e3.client); doc["ado-feed"].State != stateFailing {
		t.Fatalf("after a failure: %q", raw)
	}
	if n := e3.runs(); n != 1 {
		t.Fatalf("/status ran the command (%d runs)", n)
	}
}

func TestStatusIsTheAllowedUsersOnly(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	r.srv.allowUID = r.srv.allowUID + 1
	if status, _, raw := getStatus(t, r.client); status != http.StatusForbidden {
		t.Fatalf("another uid read /status: %d %q", status, raw)
	}
}

func readStaleFile(t *testing.T, path string) map[string]int64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]int64
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("stale file is not JSON: %q", data)
	}
	return m
}

// E4: a stale episode starts at the first credential_stale answer (no /status
// poll needed), is kept on disk, reports the same "since" after a restart, and
// ends (file entry gone) when a new sign-in lands.
func TestStaleEpisodeIsOnDiskAndSurvivesRestart(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	file := filepath.Join(r.stateDir, "stale.json")
	r.srv.SetStaleFile(file)
	r.get(instName)
	if m := readStaleFile(t, file); len(m) != 0 {
		t.Fatalf("a fresh credential has an episode: %v", m)
	}
	r.ep.setAnswer(func(int64, *http.Request) (int, string) { return 400, `{"error":"invalid_grant"}` })
	r.skew(2 * time.Hour)
	if a := r.get(instName); a.status != 503 || a.Error != "credential_stale" {
		t.Fatalf("got %d %q", a.status, a.raw)
	}
	since := readStaleFile(t, file)[instName]
	if since == 0 {
		t.Fatalf("the stale answer did not start an episode on disk: %v", readStaleFile(t, file))
	}
	raw, _ := os.ReadFile(file)
	if strings.Contains(string(raw), "rt-canary") || strings.Contains(string(raw), "at-seed") {
		t.Fatalf("a token reached the stale file: %q", raw)
	}

	_ = r.mgr.Stop()
	r.start(uint32(os.Getuid()))
	r.srv.SetStaleFile(file)
	_, doc, body := getStatus(t, r.client)
	if st := doc[instName]; st.State != stateStale || st.Since != since {
		t.Fatalf("after a restart want stale since %d: %q", since, body)
	}

	login := oauth.NewManager(r.stateDir, nil, r.key.Recipient(), log.New(io.Discard, "", 0))
	if err := login.Register(r.cfg.Instances[instName].OAuthConfig(instName), oauth.Tokens{AccessToken: "at-relogin", RefreshToken: "rt-relogin-abcdefgh", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	login.Stop()
	if a := r.get(instName); a.status != 200 {
		t.Fatalf("new sign-in not served: %q", a.raw)
	}
	if _, doc, body := getStatus(t, r.client); doc[instName].State != stateOK || doc[instName].Since != 0 {
		t.Fatalf("after a new sign-in: %q", body)
	}
	if m := readStaleFile(t, file); m[instName] != 0 {
		t.Fatalf("the episode outlived the sign-in: %v", m)
	}
}

// A stale file naming a credential this server does not serve, a zero start,
// or garbage never invents or corrupts an episode, and orphans are dropped on
// the next write.
func TestStaleFileIgnoresUnknownNamesAndGarbage(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	file := filepath.Join(r.stateDir, "stale.json")
	if err := os.WriteFile(file, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.srv.SetStaleFile(file)
	if _, doc, body := getStatus(t, r.client); doc[instName].State != stateOK {
		t.Fatalf("garbage stale file broke status: %q", body)
	}

	if err := os.WriteFile(file, []byte(`{"no-such-credential": 12345, "`+instName+`": 0}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.srv.SetStaleFile(file)
	r.get(instName)
	r.ep.setAnswer(func(int64, *http.Request) (int, string) { return 400, `{"error":"invalid_grant"}` })
	r.skew(2 * time.Hour)
	r.get(instName)
	if _, doc, body := getStatus(t, r.client); doc[instName].State != stateStale || doc[instName].Since == 0 {
		t.Fatalf("a zero start on disk leaked into the episode: %q", body)
	}
	if m := readStaleFile(t, file); m["no-such-credential"] != 0 || m[instName] == 0 {
		t.Fatalf("stale file after a write: %v", m)
	}
}
