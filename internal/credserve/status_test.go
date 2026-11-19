//go:build linux

package credserve

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
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
	r.refuseRefresh()
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
	r.refuseRefresh()
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

	r.signIn(oauth.Tokens{AccessToken: "at-relogin", RefreshToken: "rt-relogin-abcdefgh", ExpiresIn: 3600})
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

// Whatever an old stale file holds (garbage, a credential this server does not
// serve, a zero start), the next episode starts fresh and the rewrite keeps
// only served names.
func TestStaleFileNeverInventsAnEpisode(t *testing.T) {
	for name, disk := range map[string]string{
		"garbage":          `not json`,
		"unknown and zero": `{"no-such-credential": 12345, "` + instName + `": 0}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, seedTokens(3600))
			file := filepath.Join(r.stateDir, "stale.json")
			if err := os.WriteFile(file, []byte(disk), 0o600); err != nil {
				t.Fatal(err)
			}
			r.srv.SetStaleFile(file)
			if _, doc, body := getStatus(t, r.client); doc[instName].State != stateOK || doc[instName].Since != 0 {
				t.Fatalf("before any stale answer: %q", body)
			}
			r.get(instName)
			r.refuseRefresh()
			r.get(instName)
			if _, doc, body := getStatus(t, r.client); doc[instName].State != stateStale || doc[instName].Since == 0 {
				t.Fatalf("the old file leaked into the episode: %q", body)
			}
			if m := readStaleFile(t, file); len(m) != 1 || m[instName] == 0 {
				t.Fatalf("stale file after a write: %v", m)
			}
		})
	}
}

// An exec credential's episode ends only on confirmed recovery: a restart
// before the next fetch keeps it, and a served token closes it so the next
// sign-in failure is a new episode even with no /status poll in between.
func TestExecStaleEpisodeEndsOnlyOnRecovery(t *testing.T) {
	for name, run := range map[string]func(t *testing.T, e *erig, file string){
		"restart before the first fetch": func(t *testing.T, e *erig, file string) {
			e.do(http.MethodGet, "/cred/ado-feed")
			before := e.srv.status()["ado-feed"]
			restarted := NewServer(e.srv.cfg, nil, e.srv.allowUID, e.srv.logger)
			restarted.SetStaleFile(file)
			if after := restarted.status()["ado-feed"]; after.State != stateStale || after.Since != before.Since || before.Since == 0 {
				t.Fatalf("restart lost the episode: before %+v after %+v disk %v", before, after, readStaleFile(t, file))
			}
		},
		"stale, served, stale again": func(t *testing.T, e *erig, file string) {
			now := time.Now()
			e.srv.Now = func() time.Time { return now }
			e.srv.MinRefreshInterval = 0
			e.do(http.MethodGet, "/cred/ado-feed")
			first := readStaleFile(t, file)["ado-feed"]
			e.setMode("far")
			if a := e.do(http.MethodGet, "/cred/ado-feed"); a.status != 200 {
				t.Fatalf("recovery: %q", a.raw)
			}
			if m := readStaleFile(t, file); len(m) != 0 {
				t.Fatalf("a served token left the episode open: %v", m)
			}
			now = now.Add(3 * time.Hour)
			e.setMode("signin")
			e.do(http.MethodGet, "/cred/ado-feed")
			if second := e.srv.status()["ado-feed"].Since; first == 0 || second <= first {
				t.Fatalf("two episodes collapsed: first %d second %d", first, second)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newExecRig(t, "signin")
			file := filepath.Join(e.dir, "stale.json")
			e.srv.SetStaleFile(file)
			run(t, e, file)
		})
	}
}
