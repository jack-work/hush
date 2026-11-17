package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestAnthropicLoginExchangesOnePinnedJSONRequestAndStoresTheRotatedPair(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	var logs bytes.Buffer
	m.logger.SetOutput(&logs)
	var got map[string]string
	var contentType string
	m.SetHTTPClient(anthropicEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &got)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "access-login", "refresh_token": "refresh-login", "expires_in": 28800})
	}))
	cfg := anthropicConfig()
	if err := m.BeginLogin(cfg.Name); err != nil {
		t.Fatal(err)
	}
	if err := m.CompleteAnthropicLogin(context.Background(), cfg, "the-code", "the-state", "the-verifier"); err != nil {
		t.Fatal(err)
	}
	if contentType != "application/json" || got["grant_type"] != "authorization_code" || got["code"] != "the-code" || got["state"] != "the-state" || got["code_verifier"] != "the-verifier" || got["client_id"] != AnthropicClientID || got["redirect_uri"] != AnthropicRedirectURI {
		t.Fatalf("exchange sent %q %v", contentType, got)
	}
	lease, err := m.Lease(cfg.Name)
	if err != nil || lease.AccessToken != "access-login" || lease.SignInNeeded {
		t.Fatalf("login not published: %v", err)
	}
	m.Stop()
	next := newTestManager(t, dir, key)
	if err := next.Adopt(cfg.Name); err != nil {
		t.Fatal(err)
	}
	if st := next.lookup(cfg.Name).tokens.Load(); st.refresh != "refresh-login" || st.access != "access-login" {
		t.Fatal("rotated pair did not reach the persist path")
	}
	raw, _ := os.ReadFile(next.filePath(cfg.Name))
	for _, secret := range []string{"access-login", "refresh-login", "the-code"} {
		if strings.Contains(string(raw), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("%s in the clear on disk or in the log", secret)
		}
	}
}

func TestAnthropicLoginNeedsAReservationAndThePinnedConfig(t *testing.T) {
	for name, prepare := range map[string]func(*Manager, *Config){
		"no reservation": func(*Manager, *Config) {},
		"foreign token url": func(m *Manager, c *Config) {
			m.BeginLogin(c.Name)
			c.TokenURL = "https://attacker.invalid/token"
		},
		"wrong grant": func(m *Manager, c *Config) {
			m.BeginLogin(c.Name)
			c.Grant = GrantRefreshToken
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t, t.TempDir(), newTestKey(t))
			doer := &unreachableDoer{}
			m.httpClient = doer
			cfg := anthropicConfig()
			prepare(m, &cfg)
			if err := m.CompleteAnthropicLogin(context.Background(), cfg, "c", "s", "v"); err != ErrOperationBusy || doer.calls != 0 {
				t.Fatalf("code spent without a pinned reservation: calls %d err %v", doer.calls, err)
			}
		})
	}
}

func TestAnthropicFailedLoginLeavesTheOldChainAlone(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	cfg := anthropicConfig()
	if err := m.Register(cfg, anthropicSeed()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(m.filePath(cfg.Name))
	m.httpClient = fakeDoer{status: 400, body: `{"error":"invalid_grant","error_description":"CODE_CANARY"}`}
	if err := m.BeginLogin(cfg.Name); err != nil {
		t.Fatal(err)
	}
	err := m.CompleteAnthropicLogin(context.Background(), cfg, "CODE_CANARY", "s", "v")
	if err == nil || strings.Contains(err.Error(), "CODE_CANARY") {
		t.Fatalf("failed exchange: %v", err)
	}
	after, _ := os.ReadFile(m.filePath(cfg.Name))
	lease, _ := m.Lease(cfg.Name)
	if !bytes.Equal(before, after) || lease.AccessToken != "access-seed" {
		t.Fatal("a refused code replaced the live chain")
	}
}
