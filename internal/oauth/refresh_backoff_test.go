package oauth

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

type countingDoer struct {
	status int
	body   string
	posts  int
}

func (d *countingDoer) Do(*http.Request) (*http.Response, error) {
	d.posts++
	return fakeDoer{status: d.status, body: d.body}.Do(nil)
}

// TestTransientRefreshBacksOff: a token endpoint that keeps failing with a
// 5xx is asked again only after a growing, jittered wait capped at
// refreshBackoffMax, however often callers ask in between.
func TestTransientRefreshBacksOff(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 600}); err != nil {
		t.Fatalf("register: %v", err)
	}
	clock := time.Unix(1_000_000, 0)
	m.now = func() time.Time { return clock }
	doer := &countingDoer{status: 503, body: "upstream down"}
	m.httpClient = doer

	var postedAt []time.Time
	step := 100 * time.Millisecond
	for clock.Before(time.Unix(1_000_000, 0).Add(30 * time.Minute)) {
		before := doer.posts
		_, err := m.Refresh(testCfg.Name)
		if !errors.Is(err, ErrRefreshTransient) {
			t.Fatalf("at %s: err = %v, want ErrRefreshTransient", clock, err)
		}
		if doer.posts > before {
			postedAt = append(postedAt, clock)
		}
		clock = clock.Add(step)
	}

	if len(postedAt) < 3 {
		t.Fatalf("only %d POSTs in 30 minutes: backoff never retries", len(postedAt))
	}
	want := refreshBackoffBase
	for i := 1; i < len(postedAt); i++ {
		gap := postedAt[i].Sub(postedAt[i-1])
		if gap < want/2 {
			t.Fatalf("gap %d = %s, want at least %s (half of %s)", i, gap, want/2, want)
		}
		if gap > refreshBackoffMax+step {
			t.Fatalf("gap %d = %s, above the ceiling %s", i, gap, refreshBackoffMax)
		}
		want = nextRefreshBackoff(want)
	}
	if max := 30*time.Minute/(refreshBackoffMax/2) + 8; len(postedAt) > int(max) {
		t.Fatalf("%d POSTs in 30 minutes, want at most %d", len(postedAt), max)
	}

	doer.status, doer.body = 200, `{"access_token":"A2","refresh_token":"R2","expires_in":600}`
	clock = clock.Add(refreshBackoffMax)
	if got, err := m.Refresh(testCfg.Name); err != nil || got != "A2" {
		t.Fatalf("recovery: %q, %v", got, err)
	}
	doer.status, doer.body = 503, "down again"
	if _, err := m.Refresh(testCfg.Name); !errors.Is(err, ErrRefreshTransient) {
		t.Fatalf("err = %v", err)
	}
	clock = clock.Add(refreshBackoffBase)
	before := doer.posts
	m.Refresh(testCfg.Name)
	if doer.posts != before+1 {
		t.Fatalf("a success did not reset the backoff: no POST %s after a fresh failure", refreshBackoffBase)
	}
}
