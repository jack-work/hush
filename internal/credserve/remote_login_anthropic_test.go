package credserve

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jack-work/hush/internal/oauth"
)

type controlPost struct {
	t *testing.T
	r *rig
}

func (c controlPost) do(path string, body any) (int, map[string]any, string) {
	c.t.Helper()
	raw, _ := json.Marshal(body)
	response, err := c.r.client.Post("http://minter/"+path+"/"+maxName, "application/json", bytes.NewReader(raw))
	if err != nil {
		c.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	var result map[string]any
	if json.Unmarshal(data, &result) != nil {
		c.t.Fatalf("control reply is not JSON: %q", data)
	}
	return response.StatusCode, result, string(data)
}

func TestAnthropicRemoteLoginIsPinnedPKCEAndRefusesForeignCallbacks(t *testing.T) {
	r, _ := anthropicRig(t, oauth.Tokens{AccessToken: "OLD_ACCESS", RefreshToken: "OLD_REFRESH_CANARY", ExpiresIn: 3600})
	r.srv.MinRefreshInterval = 0
	before, err := os.ReadFile(filepath.Join(r.stateDir, "oauth", maxName+".toml"))
	if err != nil {
		t.Fatal(err)
	}
	var exchange map[string]string
	r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
		raw, _ := io.ReadAll(req.Body)
		exchange = nil
		json.Unmarshal(raw, &exchange)
		if exchange["code"] == "bad-code" {
			return 400, `{"error":"invalid_grant","error_description":"CODE_SECRET_CANARY"}`
		}
		return 200, `{"access_token":"NEW_ACCESS_CANARY","refresh_token":"NEW_REFRESH_CANARY","expires_in":28800}`
	})
	post := controlPost{t, r}
	var transcript strings.Builder
	note := func(raw string) { transcript.WriteString(raw) }

	status, started, raw := post.do("login-start", map[string]any{})
	note(raw)
	if status != 200 || started["status"] != "started" {
		t.Fatalf("login did not start: %d %s", status, raw)
	}
	authorize, err := url.Parse(started["authorize_url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	q := authorize.Query()
	if got := authorize.Scheme + "://" + authorize.Host + authorize.Path; got != oauth.AnthropicAuthorizeURL {
		t.Fatalf("authorize endpoint %s", got)
	}
	if q.Get("client_id") != oauth.AnthropicClientID || q.Get("redirect_uri") != oauth.AnthropicRedirectURI || q.Get("scope") != oauth.AnthropicScopes || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || len(q.Get("state")) < 32 {
		t.Fatalf("authorize parameters %v", q)
	}
	handle, state := started["handle"].(string), q.Get("state")
	if len(handle) < 16 || handle == state {
		t.Fatal("handle is weak or reused as state")
	}
	if status, _, _ = post.do("refresh", map[string]any{}); status != 409 {
		t.Fatalf("refresh overlapped a pending login: %d", status)
	}
	if status, _, _ = post.do("login-start", map[string]any{}); status != 409 {
		t.Fatal("second login overlapped")
	}
	for name, body := range map[string]map[string]any{
		"foreign state":   {"handle": handle, "code": "the-code#" + state + "x"},
		"no state":        {"handle": handle, "code": "the-code"},
		"empty code":      {"handle": handle, "code": "#" + state},
		"empty state":     {"handle": handle, "code": "the-code#"},
		"callback url":    {"handle": handle, "code": "https://console.anthropic.com/oauth/code/callback?code=the-code&state=" + state},
		"foreign handle":  {"handle": handle + "x", "code": "the-code#" + state},
		"whitespace code": {"handle": handle, "code": "the code#" + state},
	} {
		status, _, raw = post.do("login-complete", body)
		note(raw)
		if status != 400 {
			t.Fatalf("%s accepted: %d %s", name, status, raw)
		}
	}
	if r.ep.posts.Load() != 0 {
		t.Fatal("a refused callback spent a code")
	}
	status, _, raw = post.do("login-complete", map[string]any{"handle": handle, "code": "bad-code#" + state})
	note(raw)
	if status == 200 {
		t.Fatal("a refused code signed in")
	}
	lease, err := r.mgr.Lease(maxName)
	after, _ := os.ReadFile(filepath.Join(r.stateDir, "oauth", maxName+".toml"))
	if err != nil || lease.AccessToken != "OLD_ACCESS" || !bytes.Equal(before, after) {
		t.Fatal("a failed login changed the old chain")
	}
	if status, _, raw = post.do("login-complete", map[string]any{"handle": handle, "code": "good-code#" + state}); status != 400 {
		t.Fatalf("consumed handle replayed: %d", status)
	}
	note(raw)

	_, started, raw = post.do("login-start", map[string]any{})
	note(raw)
	authorize, _ = url.Parse(started["authorize_url"].(string))
	q = authorize.Query()
	status, done, raw := post.do("login-complete", map[string]any{"handle": started["handle"], "code": "good-code#" + q.Get("state")})
	note(raw)
	if status != 200 || done["status"] != "signed-in" || len(done) != 1 {
		t.Fatalf("login did not commit: %d %s", status, raw)
	}
	digest := sha256.Sum256([]byte(exchange["code_verifier"]))
	if base64.RawURLEncoding.EncodeToString(digest[:]) != q.Get("code_challenge") || exchange["code_verifier"] == q.Get("state") || exchange["state"] != q.Get("state") || exchange["code"] != "good-code" || exchange["redirect_uri"] != oauth.AnthropicRedirectURI || exchange["client_id"] != oauth.AnthropicClientID || exchange["grant_type"] != "authorization_code" {
		t.Fatalf("exchange does not match the authorize request: %v", exchange)
	}
	served := r.get(maxName)
	if served.status != 200 || served.Token != "NEW_ACCESS_CANARY" {
		t.Fatalf("new login not served: %d", served.status)
	}
	stored, _ := os.ReadFile(filepath.Join(r.stateDir, "oauth", maxName+".toml"))
	for _, secret := range []string{"OLD_ACCESS", "OLD_REFRESH_CANARY", "NEW_REFRESH_CANARY", "NEW_ACCESS_CANARY", "CODE_SECRET_CANARY", "good-code", "bad-code"} {
		for where, text := range map[string]string{"reply": transcript.String(), "log": r.logs.String(), "disk": string(stored)} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s leaked into the %s", secret, where)
			}
		}
	}
	if !strings.Contains(served.raw, "NEW_ACCESS_CANARY") || strings.Contains(served.raw, "REFRESH") {
		t.Fatal("minter reply is not the access token alone")
	}
}

func TestAnthropicRemoteRefreshAnswersReadinessAndRotatesTheChain(t *testing.T) {
	r, _ := anthropicRig(t, oauth.Tokens{AccessToken: "at-seed", RefreshToken: "REFRESH_SEED_CANARY", ExpiresIn: 3600})
	r.srv.MinRefreshInterval = 0
	var spent string
	r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
		req.ParseForm()
		spent = req.Form.Get("refresh_token")
		return 200, `{"access_token":"at-rotated","refresh_token":"REFRESH_ROTATED_CANARY","expires_in":28800}`
	})
	status, result, raw := controlPost{t, r}.do("refresh", map[string]any{})
	if status != 200 || string(bytes.TrimSpace([]byte(raw))) != `{"ready":true,"refreshed":true}` || result["ready"] != true {
		t.Fatalf("refresh reply %d %s", status, raw)
	}
	if spent != "REFRESH_SEED_CANARY" || strings.Contains(raw+r.logs.String(), "CANARY") {
		t.Fatalf("refresh spent %q or leaked", spent)
	}
	if a := r.get(maxName); a.status != 200 || a.Token != "at-rotated" {
		t.Fatalf("rotated token not served: %q", a.raw)
	}
}

func TestRemoteLoginRoutesRefuseUnpinnedKinds(t *testing.T) {
	r := newRig(t, oauth.Tokens{})
	for _, path := range []string{"login-start", "login-complete"} {
		for _, name := range []string{instName, "copilot-work", "unknown"} {
			body := `{}`
			if path == "login-complete" {
				body = `{"handle":"h","code":"c#s"}`
			}
			response, err := r.client.Post("http://minter/"+path+"/"+name, "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 404 {
				t.Fatalf("%s %s: %d", path, name, response.StatusCode)
			}
		}
	}
	if r.ep.posts.Load() != 0 {
		t.Fatal("a refused route reached the token endpoint")
	}
}
