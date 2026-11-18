//go:build linux

package credserve

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
	if st := doc[instName]; st.State != stateOK || st.Kind != "anthropic" || st.ExpiresAt == 0 {
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
