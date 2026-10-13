package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIDP is a minimal RFC 8628 provider: it hands out a device code, then
// answers authorization_pending until told the user approved.
type fakeIDP struct {
	mu        sync.Mutex
	approved  bool
	polls     int
	slowDowns int
	srv       *httptest.Server
	clientID  string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	f := &fakeIDP{clientID: "herald"}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                        f.srv.URL,
			"authorization_endpoint":        f.srv.URL + "/authorize",
			"token_endpoint":                f.srv.URL + "/token",
			"device_authorization_endpoint": f.srv.URL + "/device",
			"jwks_uri":                      f.srv.URL + "/jwks.json",
		})
	})

	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("client_id") != f.clientID {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid_client", "error_description": "unknown client",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "dev-code-1",
			"user_code":                 "WDJB-MJHT",
			"verification_uri":          f.srv.URL + "/activate",
			"verification_uri_complete": f.srv.URL + "/activate?code=WDJB-MJHT",
			"expires_in":                600,
			"interval":                  1,
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.polls++
		n, approved, slow := f.polls, f.approved, f.slowDowns
		f.mu.Unlock()

		if slow > 0 && n <= slow {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
			return
		}
		if !approved {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-123", "refresh_token": "rt-456",
			"expires_in": 3600, "token_type": "bearer",
		})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) approve() {
	f.mu.Lock()
	f.approved = true
	f.mu.Unlock()
}

func TestDiscoverReadsEndpoints(t *testing.T) {
	f := newFakeIDP(t)
	d, err := Discover(context.Background(), http.DefaultClient, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !d.SupportsDeviceFlow() {
		t.Error("device flow not detected")
	}
	if d.TokenEndpoint != f.srv.URL+"/token" {
		t.Errorf("token endpoint = %q", d.TokenEndpoint)
	}
}

// A discovery document served by one host but claiming another issuer is a
// mix-up (or an attack); it must not be trusted.
func TestDiscoverRejectsIssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         "https://somewhere.else",
			"token_endpoint": "https://somewhere.else/token",
		})
	}))
	defer srv.Close()

	if _, err := Discover(context.Background(), http.DefaultClient, srv.URL); err == nil {
		t.Fatal("issuer mismatch must be refused")
	}
}

func TestDiscoverRejectsMetadataWithoutTokenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if _, err := Discover(context.Background(), http.DefaultClient, srv.URL); err == nil {
		t.Fatal("metadata without a token_endpoint must be refused")
	}
}

func TestDeviceCodeRequestAndApproval(t *testing.T) {
	f := newFakeIDP(t)
	ctx := context.Background()
	d, err := Discover(ctx, http.DefaultClient, f.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	da, err := RequestDeviceCode(ctx, http.DefaultClient, d.DeviceAuthorizationEndpoint, "herald", "openid")
	if err != nil {
		t.Fatal(err)
	}
	if da.UserCode != "WDJB-MJHT" || da.VerificationURIComplete == "" {
		t.Fatalf("device auth = %+v", da)
	}

	// Approve almost immediately; the poll must notice quickly rather than
	// sleeping a full interval first.
	go func() {
		time.Sleep(50 * time.Millisecond)
		f.approve()
	}()

	start := time.Now()
	toks, err := PollDeviceToken(ctx, http.DefaultClient, d.TokenEndpoint, "herald", da)
	if err != nil {
		t.Fatal(err)
	}
	if toks.AccessToken != "at-123" || toks.RefreshToken != "rt-456" {
		t.Errorf("tokens = %+v", toks)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s to notice approval — is it sleeping before the first poll?", elapsed)
	}
}

// An unknown client yields a flat 400; the message must say what that
// usually means, since it otherwise reads like a malformed request.
func TestUnknownClientGivesAnActionableError(t *testing.T) {
	f := newFakeIDP(t)
	ctx := context.Background()
	d, _ := Discover(ctx, http.DefaultClient, f.srv.URL)

	_, err := RequestDeviceCode(ctx, http.DefaultClient, d.DeviceAuthorizationEndpoint, "not-registered", "openid")
	if err == nil {
		t.Fatal("expected refusal")
	}
	if !strings.Contains(err.Error(), "registered") {
		t.Errorf("error should hint at client registration, got: %v", err)
	}
}

// slow_down means keep waiting with a longer gap — not an error.
func TestSlowDownBacksOffRatherThanFailing(t *testing.T) {
	f := newFakeIDP(t)
	f.mu.Lock()
	f.slowDowns = 2
	f.approved = true
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d, _ := Discover(ctx, http.DefaultClient, f.srv.URL)
	da, err := RequestDeviceCode(ctx, http.DefaultClient, d.DeviceAuthorizationEndpoint, "herald", "openid")
	if err != nil {
		t.Fatal(err)
	}
	toks, err := PollDeviceToken(ctx, http.DefaultClient, d.TokenEndpoint, "herald", da)
	if err != nil {
		t.Fatalf("slow_down should not be terminal: %v", err)
	}
	if toks.AccessToken == "" {
		t.Error("no token after backing off")
	}
}

func TestExpiredDeviceCodeStopsPolling(t *testing.T) {
	f := newFakeIDP(t)
	ctx := context.Background()
	d, _ := Discover(ctx, http.DefaultClient, f.srv.URL)
	da, _ := RequestDeviceCode(ctx, http.DefaultClient, d.DeviceAuthorizationEndpoint, "herald", "openid")

	// A code whose deadline has already passed must not be polled at all.
	past := *da
	past.Expires = time.Now().Add(-time.Second)

	done := make(chan error, 1)
	go func() {
		_, err := PollDeviceToken(ctx, http.DefaultClient, d.TokenEndpoint, "herald", &past)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expected an expiry error, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("poll did not stop on an expired device code")
	}
}

func TestPollHonoursContextCancellation(t *testing.T) {
	f := newFakeIDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	d, _ := Discover(ctx, http.DefaultClient, f.srv.URL)
	da, _ := RequestDeviceCode(ctx, http.DefaultClient, d.DeviceAuthorizationEndpoint, "herald", "openid")

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	if _, err := PollDeviceToken(ctx, http.DefaultClient, d.TokenEndpoint, "herald", da); err == nil {
		t.Fatal("cancellation should stop the poll")
	}
}
