//go:build linux

package credserve

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jack-work/hush/internal/oauth"
)

func fakeChatGPTJWT(account string) string {
	raw, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "https://api.openai.com/auth": map[string]string{"chatgpt_account_id": account}})
	return "head." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
}

type loginOutput struct{ url chan string }

func (o loginOutput) Write(p []byte) (int, error) {
	for _, part := range strings.Fields(string(p)) {
		if strings.HasPrefix(part, oauth.ChatGPTAuthorizeURL+"?") {
			o.url <- part
		}
	}
	return len(p), nil
}

type tokenRouting struct {
	next   http.RoundTripper
	target *url.URL
	t      *testing.T
}

func (r tokenRouting) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() != oauth.ChatGPTTokenURL {
		r.t.Error("unpinned token URL")
	}
	copy := req.Clone(req.Context())
	u := *req.URL
	u.Scheme = r.target.Scheme
	u.Host = r.target.Host
	copy.URL = &u
	return r.next.RoundTrip(copy)
}

func TestChatGPTLoopbackPKCEAndAtomicMinterTuple(t *testing.T) {
	for _, mode := range []string{"success", "state", "cancel", "occupied"} {
		t.Run(mode, func(t *testing.T) {
			r, l, _ := loginRig(t)
			in := (Instance{Kind: KindChatGPT}).chatGPTDefaults()
			r.cfg.Instances[instName] = in
			out := loginOutput{url: make(chan string, 1)}
			l.Out = out
			var exchange url.Values
			posts := 0
			tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				posts++
				req.ParseForm()
				exchange = req.Form
				json.NewEncoder(w).Encode(map[string]any{"access_token": fakeChatGPTJWT("account_1"), "refresh_token": "REFRESH_NEVER_PUBLISH", "expires_in": 3600})
			}))
			defer tokenServer.Close()
			target, _ := url.Parse(tokenServer.URL)
			l.Client = tokenServer.Client()
			l.Client.Transport = tokenRouting{l.Client.Transport, target, t}
			var callback net.Listener
			l.Listen = func(network, address string) (net.Listener, error) {
				if address != "127.0.0.1:1455" || network != "tcp" {
					t.Error("callback not pinned")
				}
				if mode == "occupied" {
					return nil, errors.New("busy")
				}
				var err error
				callback, err = net.Listen("tcp", "127.0.0.1:0")
				return callback, err
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- l.Run(ctx) }()
			if mode == "occupied" {
				if err := <-done; err == nil {
					t.Fatal("occupied callback accepted")
				}
				if posts != 0 {
					t.Fatal("code exchange before bind")
				}
				return
			}
			authURL, _ := url.Parse(<-out.url)
			q := authURL.Query()
			if q.Get("redirect_uri") != oauth.ChatGPTRedirectURI || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
				t.Fatal("invalid authorization parameters")
			}
			if mode == "cancel" {
				cancel()
				if err := <-done; err == nil {
					t.Fatal("cancel accepted")
				}
				if c, err := net.Dial("tcp", callback.Addr().String()); err == nil {
					c.Close()
					t.Fatal("listener survived cancellation")
				}
				return
			}
			state := q.Get("state")
			if mode == "state" {
				state = "foreign"
			}
			request, _ := http.NewRequest("GET", "http://"+callback.Addr().String()+"/auth/callback?"+url.Values{"state": {state}, "code": {"CODE_NEVER_LOG"}}.Encode(), nil)
			request.Host = "localhost:1455"
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			err = <-done
			if mode == "state" {
				if err == nil || posts != 0 {
					t.Fatal("foreign state spent code")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(exchange.Get("code_verifier")))
			if exchange.Get("redirect_uri") != oauth.ChatGPTRedirectURI || exchange.Get("code") != "CODE_NEVER_LOG" || exchange.Get("grant_type") != "authorization_code" || base64.RawURLEncoding.EncodeToString(digest[:]) != q.Get("code_challenge") || exchange.Get("code_verifier") == q.Get("state") {
				t.Fatal("PKCE exchange mismatch")
			}
			a := r.get(instName)
			var doc map[string]any
			json.Unmarshal([]byte(a.raw), &doc)
			if a.status != 200 || doc["account_id"] != "account_1" || doc["token"] != fakeChatGPTJWT("account_1") || strings.Contains(a.raw, "REFRESH_NEVER_PUBLISH") || strings.Contains(a.raw, "id_token") {
				t.Fatalf("minter tuple status%d", a.status)
			}
		})
	}
}

func TestChatGPTConfigPinsEveryEndpoint(t *testing.T) {
	key := newRig(t, oauth.Tokens{}).key
	prefix := fmt.Sprintf("recipient = %q\nallow_user = 'rou2'\n[instances.chatgpt-personal]\nkind = 'chatgpt'\n", key.Recipient().String())
	cfg, err := ParseConfig([]byte(prefix))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Instances["chatgpt-personal"].TokenURL != oauth.ChatGPTTokenURL {
		t.Fatal("default not pinned")
	}
	for _, setting := range []string{"token_url='https://attacker.invalid/token'", "authorize_url='https://attacker.invalid/auth'", "redirect_uri='http://localhost:5555/callback'", "client_id='other'", "scopes='other'"} {
		if _, err := ParseConfig([]byte(prefix + setting)); err == nil {
			t.Fatalf("unsafe %s", setting)
		}
	}
}

func TestCredentialStateHasOneOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	first, err := LockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := LockState(dir); err == nil {
		second.Close()
		t.Fatal("two credential owners")
	}
	first.Close()
	next, err := LockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestRefreshStatusNeverPublishesCredentials(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	post := func() *http.Response {
		req, _ := http.NewRequest("POST", "http://minter/refresh/"+instName, nil)
		resp, err := r.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	r.ep.setAnswer(func(_ int64, _ *http.Request) (int, string) {
		return 400, `{"error":"SECRET_ECHO_CANARY","error_description":"NEW_TOKEN_CANARY refresh-access-id-token"}`
	})
	response := post()
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 503 || strings.Contains(string(raw), "CANARY") || strings.Contains(r.logs.String(), "CANARY") {
		t.Fatalf("unsafe refresh error status%d", response.StatusCode)
	}
	r.srv.allowUID = uint32(os.Getuid()) + 1
	response = post()
	raw, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 403 || strings.Contains(string(raw), "at-seed") {
		t.Fatal("nonowner refresh allowed")
	}
}

func TestRefreshStatusSuccessContainsNoBearer(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	req, _ := http.NewRequest("POST", "http://minter/refresh/"+instName, nil)
	resp, err := r.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(bytes.TrimSpace(raw)) != `{"ready":true,"refreshed":true}` || strings.Contains(string(raw), "token") {
		t.Fatalf("unsafe ready reply %s", raw)
	}
}

func TestCredentialOwnerProcessCrashReleasesLock(t *testing.T) {
	if dir := os.Getenv("HUSH_TEST_OWNER_DIR"); dir != "" {
		lock, err := LockState(dir)
		if err != nil {
			os.Exit(3)
		}
		defer lock.Close()
		fmt.Fprintln(os.Stdout, "locked")
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCredentialOwnerProcessCrashReleasesLock$")
	cmd.Env = append(os.Environ(), "HUSH_TEST_OWNER_DIR="+dir)
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
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatal("child owner not ready")
	}
	if owner, err := LockState(dir); err == nil {
		owner.Close()
		t.Fatal("crossprocess duplicate owner")
	}
	cmd.Process.Kill()
	cmd.Wait()
	owner, err := LockState(dir)
	if err != nil {
		t.Fatal("lock did not survive crash safely")
	}
	owner.Close()
}
