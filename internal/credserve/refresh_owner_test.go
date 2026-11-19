//go:build linux

package credserve

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// /refresh/<name> on the owner socket: a POST forces one refresh and the next
// answer carries the new token with a later expires_at; any other method is
// refused at no token-endpoint cost. Principal sockets without refresh = true
// keep refusing the route (TestPrincipalSocketServesCredOnly).
func TestOwnerRefresh(t *testing.T) {
	for _, c := range []struct {
		method string
		status int
		body   string
		posts  int64
		token  string
		moved  time.Duration // at least
	}{
		{http.MethodPost, 200, `{"ready":true,"refreshed":true}`, 1, "at-1", 30 * time.Minute},
		{http.MethodGet, 405, "", 0, "at-seed", 0},
		{http.MethodPut, 405, "", 0, "at-seed", 0},
	} {
		t.Run(c.method, func(t *testing.T) {
			r := newRig(t, seedTokens(1200))
			before := r.get(instName)
			req, _ := http.NewRequest(c.method, "http://minter/refresh/"+instName, strings.NewReader("{}"))
			res, err := r.client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode != c.status || c.body != "" && strings.TrimSpace(string(b)) != c.body {
				t.Fatalf("got %d %q", res.StatusCode, b)
			}
			if n := r.ep.posts.Load(); n != c.posts {
				t.Fatalf("%d token-endpoint POSTs, want %d", n, c.posts)
			}
			after := r.get(instName)
			if after.Token != c.token {
				t.Fatalf("next answer: %q", after.raw)
			}
			if moved := time.Unix(after.Expiry, 0).Sub(time.Unix(before.Expiry, 0)); moved < c.moved {
				t.Fatalf("expires_at moved %s, want at least %s", moved, c.moved)
			}
			if strings.Contains(r.logs.String(), "at-1") {
				t.Fatalf("a token reached the log: %q", r.logs.String())
			}
		})
	}
}
