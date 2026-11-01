package oauth

import (
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
)

// deadGrant registers prov with a refresh token the endpoint no longer
// knows, and a predecessor it does not know either: the state that cost
// ~63k token POSTs on 10-31 when every reactive Refresh retried both.
func deadGrant(t *testing.T) (*Manager, *tokenAwareDoer, string, *age.X25519Identity) {
	t.Helper()
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 600}); err != nil {
		t.Fatalf("register: %v", err)
	}
	st := m.lookup(testCfg.Name)
	withPrev := *st.tokens.Load()
	withPrev.prevRefresh = "R0"
	st.tokens.Store(&withPrev)
	doer := &tokenAwareDoer{accept: map[string]string{}}
	m.httpClient = doer
	return m, doer, dir, key
}

// TestInvalidGrantLatchesReactiveRefresh is the 10-31 storm: callers kept
// asking for a refresh after invalid_grant, and each one cost two POSTs.
// However many callers ask, a dead grant costs at most the two POSTs of the
// first rejection.
func TestInvalidGrantLatchesReactiveRefresh(t *testing.T) {
	m, doer, _, _ := deadGrant(t)

	var last error
	for i := 0; i < 50; i++ {
		_, _, err := m.RefreshFull(testCfg.Name)
		if !errors.Is(err, ErrRefreshPermanent) {
			t.Fatalf("call %d: err = %v, want ErrRefreshPermanent", i, err)
		}
		last = err
	}
	if len(doer.seen) > 2 {
		t.Errorf("token endpoint saw %d POSTs for a dead grant, want at most 2", len(doer.seen))
	}
	if !strings.Contains(last.Error(), "hush oauth login "+testCfg.Name) {
		t.Errorf("error does not tell the human what to run: %v", last)
	}
}

// TestDeadGrantSurvivesRestart: a restarted agent must not resume the loop
// against the same dead token.
func TestDeadGrantSurvivesRestart(t *testing.T) {
	m, _, dir, key := deadGrant(t)
	if _, err := m.Refresh(testCfg.Name); !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v, want ErrRefreshPermanent", err)
	}

	restarted := newTestManager(t, dir, key)
	if err := restarted.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	after := &tokenAwareDoer{accept: map[string]string{}}
	restarted.httpClient = after
	for i := 0; i < 10; i++ {
		if _, err := restarted.Refresh(testCfg.Name); !errors.Is(err, ErrRefreshPermanent) {
			t.Fatalf("after restart: err = %v, want ErrRefreshPermanent", err)
		}
	}
	if len(after.seen) != 0 {
		t.Fatalf("restarted agent POSTed %v for a grant already known dead", after.seen)
	}
}

// TestLoginRevivesDeadGrant: a new login is the way out, and it must work.
func TestLoginRevivesDeadGrant(t *testing.T) {
	m, _, _, _ := deadGrant(t)
	if _, err := m.Refresh(testCfg.Name); !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v, want ErrRefreshPermanent", err)
	}
	if err := m.Register(testCfg, Tokens{AccessToken: "A5", RefreshToken: "R5", ExpiresIn: 600}); err != nil {
		t.Fatalf("login: %v", err)
	}
	doer := &tokenAwareDoer{accept: map[string]string{
		"R5": `{"access_token":"A6","refresh_token":"R6","expires_in":600}`,
	}}
	m.httpClient = doer
	got, err := m.Refresh(testCfg.Name)
	if err != nil || got != "A6" {
		t.Fatalf("refresh after login = %q, %v; want A6", got, err)
	}
}

// TestNewerDiskTokensReviveDeadGrant: a login made by another process (a
// second agent, the CLI) lands on disk; the latched agent adopts it without
// a POST.
func TestNewerDiskTokensReviveDeadGrant(t *testing.T) {
	m, _, dir, key := deadGrant(t)
	if _, err := m.Refresh(testCfg.Name); !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("err = %v, want ErrRefreshPermanent", err)
	}
	other := newTestManager(t, dir, key)
	if err := other.Register(testCfg, Tokens{AccessToken: "A9", RefreshToken: "R9", ExpiresIn: 600}); err != nil {
		t.Fatalf("other login: %v", err)
	}
	doer := &tokenAwareDoer{accept: map[string]string{}}
	m.httpClient = doer
	got, err := m.Refresh(testCfg.Name)
	if err != nil || got != "A9" {
		t.Fatalf("refresh = %q, %v; want A9 adopted from disk", got, err)
	}
	if len(doer.seen) != 0 {
		t.Fatalf("adopting a newer login POSTed %v", doer.seen)
	}
}
