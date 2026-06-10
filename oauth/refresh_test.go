package oauth

import (
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

// fakeDoer answers every token-endpoint POST with a fixed status/body.
type fakeDoer struct {
	status int
	body   string
}

func (f fakeDoer) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
	}, nil
}

func newTestKey(t *testing.T) *age.X25519Identity {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return key
}

// newTestManager builds a manager over stateDir. Managers sharing a state
// dir must share the key, or they cannot read each other's files.
func newTestManager(t *testing.T, stateDir string, key *age.X25519Identity) *Manager {
	t.Helper()
	m := NewManager(stateDir, []age.Identity{key}, key.Recipient(), log.New(os.Stderr, "test: ", 0))
	t.Cleanup(m.Stop)
	return m
}

var testCfg = Config{
	Name:     "prov",
	TokenURL: "https://token.invalid/oauth/token",
	ClientID: "client-1",
}

// TestRefreshAdoptsRotatedDiskTokens is the split-brain self-heal: our
// refresh token was rotated away by another process, the endpoint rejects
// ours permanently, but the other process persisted its success — so
// Refresh must adopt the disk tokens instead of failing.
func TestRefreshAdoptsRotatedDiskTokens(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Another process rotates the tokens on disk behind our back.
	other := newTestManager(t, dir, key)
	if err := other.Register(testCfg, Tokens{AccessToken: "A2", RefreshToken: "R2", ExpiresIn: 3600}); err != nil {
		t.Fatalf("rotate on disk: %v", err)
	}

	// The endpoint permanently rejects our (stale) refresh token.
	m.httpClient = fakeDoer{status: 400, body: `{"error":"invalid_grant"}`}

	tok, err := m.Refresh("prov")
	if err != nil {
		t.Fatalf("refresh should self-heal from disk, got error: %v", err)
	}
	if tok != "A2" {
		t.Fatalf("refresh returned %q, want disk-rotated access token A2", tok)
	}
	if got, _ := m.Get("prov"); got != "A2" {
		t.Fatalf("in-memory cache holds %q after self-heal, want A2", got)
	}
}

// TestRefreshPermanentWhenDiskUnchanged: with no newer disk state the
// permanent rejection must surface, not be masked by the self-heal path.
func TestRefreshPermanentWhenDiskUnchanged(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatalf("register: %v", err)
	}
	m.httpClient = fakeDoer{status: 400, body: `{"error":"invalid_grant"}`}

	if _, err := m.Refresh("prov"); !errors.Is(err, ErrRefreshPermanent) {
		t.Fatalf("want ErrRefreshPermanent, got %v", err)
	}
}

// TestRefreshSuccessRotatesDisk: the ordinary path still persists what the
// endpoint returns.
func TestRefreshSuccessRotatesDisk(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatalf("register: %v", err)
	}
	m.httpClient = fakeDoer{status: 200, body: `{"access_token":"A2","refresh_token":"R2","expires_in":3600}`}

	tok, err := m.Refresh("prov")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok != "A2" {
		t.Fatalf("refresh returned %q, want A2", tok)
	}

	// A fresh manager loading from disk must see the rotated pair.
	reader := newTestManager(t, dir, key)
	if err := reader.Start(); err != nil {
		t.Fatalf("start reader: %v", err)
	}
	if got, err := reader.Get("prov"); err != nil || got != "A2" {
		t.Fatalf("disk state after refresh: got %q, %v; want A2", got, err)
	}
}
