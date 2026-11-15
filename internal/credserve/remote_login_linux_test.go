package credserve

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jack-work/hush/internal/oauth"
)

func TestRemoteLoginKeepsOldChainUntilSuccessfulCompletion(t *testing.T) {
	r, _, _ := loginRig(t)
	in := (Instance{Kind: KindChatGPT}).chatGPTDefaults()
	r.cfg.Instances[instName] = in
	r.srv.MinRefreshInterval = 0
	oldAccess := fakeChatGPTJWT("old_account")
	if err := r.mgr.Register(in.OAuthConfig(instName), oauth.Tokens{AccessToken: oldAccess, RefreshToken: "OLD_FAKE_REFRESH", ExpiresIn: 3600, Metadata: map[string]string{"account_id": "old_account"}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(r.stateDir, "oauth", instName+".toml"))
	if err != nil {
		t.Fatal(err)
	}
	newAccess := fakeChatGPTJWT("new_account")
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		request.ParseForm()
		if request.Form.Get("code") == "bad-code" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error_description":"CODE_SECRET_CANARY"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": newAccess, "refresh_token": "NEW_FAKE_REFRESH", "expires_in": 3600})
	}))
	defer endpoint.Close()
	target, _ := url.Parse(endpoint.URL)
	client := endpoint.Client()
	client.Transport = tokenRouting{client.Transport, target, t}
	if err := r.mgr.SetHTTPClient(client); err != nil {
		t.Fatal(err)
	}
	post := func(path string, body any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		response, err := r.client.Post("http://minter/"+path+"/"+instName, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		if strings.Contains(string(data), oldAccess) || strings.Contains(string(data), newAccess) || strings.Contains(string(data), "FAKE_REFRESH") || strings.Contains(string(data), "CODE_SECRET_CANARY") {
			t.Fatal("control response leaked credential material")
		}
		var result map[string]any
		if json.Unmarshal(data, &result) != nil {
			t.Fatal("invalid control response")
		}
		return response.StatusCode, result
	}
	status, started := post("login-start", map[string]any{})
	if status != 200 || started["status"] != "started" {
		t.Fatal("login did not start")
	}
	if status, _ = post("refresh", map[string]any{}); status != 409 {
		t.Fatal("refresh overlapped pending login")
	}
	if _, err := r.mgr.TryRefresh(instName); err != oauth.ErrOperationBusy {
		t.Fatal("manager refresh bypassed login reservation")
	}
	if status, _ = post("login-start", map[string]any{}); status != 409 {
		t.Fatal("second login overlapped")
	}
	if status, _ = post("login-complete", map[string]any{"handle": started["handle"], "code": "bad-code"}); status != 503 {
		t.Fatal("failed code accepted")
	}
	lease, err := r.mgr.Lease(instName)
	after, readErr := os.ReadFile(filepath.Join(r.stateDir, "oauth", instName+".toml"))
	if err != nil || readErr != nil || lease.AccessToken != oldAccess || !bytes.Equal(before, after) {
		t.Fatal("failed login changed old chain")
	}
	if status, _ = post("login-complete", map[string]any{"handle": started["handle"], "code": "good-code"}); status != 400 {
		t.Fatal("consumed handle replayed")
	}
	_, started = post("login-start", map[string]any{})
	if status, result := post("login-complete", map[string]any{"handle": started["handle"], "code": "good-code"}); status != 200 || result["status"] != "signed-in" {
		t.Fatal("new login did not commit")
	}
	lease, err = r.mgr.Lease(instName)
	if err != nil || lease.AccessToken != newAccess || lease.AccountID != "new_account" {
		t.Fatal("new token/account tuple not published")
	}
}
