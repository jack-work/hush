package oauth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"filippo.io/age"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func chatGPTJWT(account string) string {
	raw, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account}})
	return "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
}
func chatGPTConfig() Config {
	return Config{Name: "chatgpt-personal", Grant: GrantChatGPT, TokenURL: ChatGPTTokenURL, AuthorizeURL: ChatGPTAuthorizeURL, ClientID: ChatGPTClientID, RedirectURI: ChatGPTRedirectURI, Scopes: ChatGPTScopes}
}
func chatGPTSeed() Tokens {
	return Tokens{AccessToken: chatGPTJWT("account_1"), RefreshToken: "refresh-seed", ExpiresIn: 3600, Metadata: map[string]string{"account_id": "account_1"}}
}

type rewriteRoundTrip struct {
	target *url.URL
	next   http.RoundTripper
	t      *testing.T
}

func (r rewriteRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != ChatGPTTokenURL {
		r.t.Errorf("token URL not pinned")
	}
	clone := req.Clone(req.Context())
	u := *req.URL
	u.Scheme = r.target.Scheme
	u.Host = r.target.Host
	clone.URL = &u
	return r.next.RoundTrip(clone)
}

func TestChatGPTRefreshRotationTupleAndRestart(t *testing.T) {
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	cfg := chatGPTConfig()
	if err := m.Register(cfg, chatGPTSeed()); err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := posts.Add(1)
		r.ParseForm()
		expected := "refresh-seed"
		if n > 1 {
			expected = fmt.Sprintf("refresh-%d", n-1)
		}
		if r.Form.Get("refresh_token") != expected || r.Form.Get("client_id") != ChatGPTClientID {
			t.Error("wrong refresh chain")
		}
		if n == 1 {
			close(entered)
			<-release
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": chatGPTJWT("account_1"), "refresh_token": fmt.Sprintf("refresh-%d", n), "expires_in": 3600})
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	client := server.Client()
	client.Transport = rewriteRoundTrip{target, client.Transport, t}
	m.SetHTTPClient(client)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := m.Refresh(cfg.Name); err != nil {
				t.Error(err)
			}
		})
	}
	<-entered
	close(release)
	wg.Wait()
	if posts.Load() != 1 {
		t.Fatalf("refresh raced %d times", posts.Load())
	}
	lease, err := m.Lease(cfg.Name)
	if err != nil || lease.AccountID != "account_1" || lease.AccessToken == "" {
		t.Fatal("tuple publication lost account")
	}
	m.Stop()
	next := newTestManager(t, dir, key)
	next.SetHTTPClient(client)
	if err := next.Adopt(cfg.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := next.Refresh(cfg.Name); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 2 {
		t.Fatal("restart did not rotate successor")
	}
}

func TestChatGPTTokenFailuresNeverEchoSecrets(t *testing.T) {
	for _, body := range []string{`{"error":"TOKEN_CANARY","error_description":"refresh-seed callback_code id_token access_token"}`, `{"access_token":"TOKEN_CANARY","refresh_token":"refresh-seed"}`, `<html>TOKEN_CANARY</html>`} {
		_, err := chatGPTGrant{}.Mint(context.Background(), fakeDoer{status: 400, body: body}, chatGPTConfig(), "refresh-seed")
		if err == nil || strings.Contains(err.Error(), "TOKEN_CANARY") || strings.Contains(err.Error(), "refresh-seed") {
			t.Fatalf("unsafe token error %v", err)
		}
	}
}

func TestChatGPTRejectsAccountChangesAndFailedPersistence(t *testing.T) {
	for _, mode := range []string{"account", "persist"} {
		t.Run(mode, func(t *testing.T) {
			dir, key := t.TempDir(), newTestKey(t)
			m := newTestManager(t, dir, key)
			var logs bytes.Buffer
			m.logger = log.New(&logs, "", 0)
			cfg := chatGPTConfig()
			seed := chatGPTSeed()
			if err := m.Register(cfg, seed); err != nil {
				t.Fatal(err)
			}
			account := "account_1"
			if mode == "account" {
				account = "other"
			}
			if mode == "persist" {
				if err := os.Rename(m.oauthDir(), m.oauthDir()+"-saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(m.oauthDir(), []byte("blocked"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			raw, _ := json.Marshal(map[string]any{"access_token": chatGPTJWT(account), "refresh_token": "successor-secret", "expires_in": 3600})
			m.httpClient = fakeDoer{status: 200, body: string(raw)}
			if _, err := m.Refresh(cfg.Name); err == nil {
				t.Fatal("invalid successor published")
			}
			got, _ := m.Lease(cfg.Name)
			if got.AccessToken != seed.AccessToken || got.AccountID != "account_1" {
				t.Fatal("old tuple replaced")
			}
			if strings.Contains(logs.String(), "successor-secret") {
				t.Fatal("secret logged")
			}
		})
	}
}

func TestChatGPTRegistrationRejectsUnsafeConfiguration(t *testing.T) {
	seed := chatGPTSeed()
	cfg := chatGPTConfig()
	cfg.TokenURL = "https://other.invalid/token"
	if (chatGPTGrant{}).Validate(cfg, seed) == nil {
		t.Fatal("unpinned endpoint")
	}
	cfg = chatGPTConfig()
	seed.Metadata["account_id"] = "wrong"
	if (chatGPTGrant{}).Validate(cfg, seed) == nil {
		t.Fatal("mismatched metadata")
	}
	for _, id := range []string{"", "contains space", "account\r\nheader", strings.Repeat("a", 129), "ü"} {
		if ValidAccountID(id) {
			t.Fatal("unsafe account id")
		}
	}
}

func TestChatGPTPublishedRotationSurvivesProcessCrash(t *testing.T) {
	if dir := os.Getenv("HUSH_TEST_CHATGPT_CRASH_DIR"); dir != "" {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			os.Exit(3)
		}
		key, err := age.ParseX25519Identity(strings.TrimSpace(line))
		if err != nil {
			os.Exit(4)
		}
		manager := NewManager(dir, []age.Identity{key}, key.Recipient(), log.New(io.Discard, "", 0))
		if manager.Adopt("chatgpt-personal") != nil {
			os.Exit(5)
		}
		raw, _ := json.Marshal(map[string]any{"access_token": chatGPTJWT("account_1"), "refresh_token": "persisted-successor", "expires_in": 3600})
		manager.httpClient = fakeDoer{status: 200, body: string(raw)}
		if _, err := manager.Refresh("chatgpt-personal"); err != nil {
			os.Exit(6)
		}
		fmt.Fprintln(os.Stdout, "published")
		io.Copy(io.Discard, reader)
		os.Exit(0)
	}
	dir, key := t.TempDir(), newTestKey(t)
	m := newTestManager(t, dir, key)
	cfg := chatGPTConfig()
	if err := m.Register(cfg, chatGPTSeed()); err != nil {
		t.Fatal(err)
	}
	m.Stop()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChatGPTPublishedRotationSurvivesProcessCrash$")
	cmd.Env = append(os.Environ(), "HUSH_TEST_CHATGPT_CRASH_DIR="+dir)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	fmt.Fprintln(input, key.String())
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "published\n" {
		t.Fatal("child did not publish rotation")
	}
	cmd.Process.Kill()
	cmd.Wait()
	next := newTestManager(t, dir, key)
	if err := next.Adopt(cfg.Name); err != nil {
		t.Fatal(err)
	}
	state := next.lookup(cfg.Name).tokens.Load()
	if state.refresh != "persisted-successor" || state.metadata["account_id"] != "account_1" || state.access == "" {
		t.Fatal("published rotated tuple lost after process crash")
	}
}
