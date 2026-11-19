//go:build linux

package credserve

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// POST /refresh/<name> on the owner socket forces a refresh: the next answer
// carries the new token and a later expires_at. A principal socket without
// refresh = true keeps refusing the route (TestPrincipalSocketServesCredOnly).
func TestOwnerRefreshMovesExpiresAt(t *testing.T) {
	r := newRig(t, seedTokens(1200))
	before := r.get(instName)
	if before.status != 200 || before.Token != "at-seed" {
		t.Fatalf("seed: got %d %q", before.status, before.raw)
	}
	post := func() (int, string) {
		res, err := r.client.Post("http://minter/refresh/"+instName, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, strings.TrimSpace(string(b))
	}
	if code, body := post(); code != 200 || body != `{"ready":true,"refreshed":true}` {
		t.Fatalf("owner refresh: got %d %q", code, body)
	}
	if n := r.ep.posts.Load(); n != 1 {
		t.Fatalf("owner refresh cost %d POSTs, want 1", n)
	}
	after := r.get(instName)
	if after.status != 200 || after.Token != "at-1" {
		t.Fatalf("after refresh: got %d %q", after.status, after.raw)
	}
	if moved := time.Unix(after.Expiry, 0).Sub(time.Unix(before.Expiry, 0)); moved < 30*time.Minute {
		t.Fatalf("expires_at moved %s, want about 40 min", moved)
	}
	if strings.Contains(r.logs.String(), "at-1") {
		t.Fatalf("a token reached the log: %q", r.logs.String())
	}
}

func TestOwnerRefreshIsPostOnly(t *testing.T) {
	r := newRig(t, seedTokens(1200))
	res, err := r.client.Get("http://minter/refresh/" + instName)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /refresh: got %d, want 405", res.StatusCode)
	}
	if n := r.ep.posts.Load(); n != 0 {
		t.Fatalf("a refused refresh cost %d POSTs", n)
	}
}
