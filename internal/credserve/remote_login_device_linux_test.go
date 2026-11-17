//go:build linux

package credserve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// deviceRig: a copilot instance whose device, GitHub and Copilot endpoints
// are the rig's fake endpoint; polls says what the GitHub token endpoint
// answers on each poll.
func deviceRig(t *testing.T, polls func(n int64) string) (*rig, *atomic.Int64) {
	t.Helper()
	r := newRig(t, seedTokens(3600))
	base := r.ep.srv.URL
	r.cfg.Instances["copilot-work"] = Instance{
		Kind: KindCopilot, ClientID: "Iv1.test", Scopes: "read:user",
		DeviceURL:      base + "/login/device/code",
		GitHubTokenURL: base + "/login/oauth/access_token",
		TokenURL:       base + "/copilot_internal/v2/token",
	}
	r.srv.LoginClient = FencedClient(r.cfg.EgressHosts(), r.ep.roots())
	r.srv.MinRefreshInterval = 0
	var pollN atomic.Int64
	r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
		switch req.URL.Path {
		case "/login/device/code":
			return 200, `{"device_code":"DEVICE-SECRET","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":1}`
		case "/login/oauth/access_token":
			switch polls(pollN.Add(1)) {
			case "ok":
				return 200, `{"access_token":"gho_GITHUB_SECRET","token_type":"bearer"}`
			case "denied":
				return 200, `{"error":"access_denied"}`
			case "expired":
				return 200, `{"error":"expired_token"}`
			case "slow":
				return 200, `{"error":"slow_down"}`
			}
			return 200, `{"error":"authorization_pending"}`
		case "/copilot_internal/v2/token":
			return 200, fmt.Sprintf(`{"token":"COPILOT_SECRET","expires_at":%d,"endpoints":{"api":"https://api.example"}}`, time.Now().Add(30*time.Minute).Unix())
		}
		return 404, `{}`
	})
	old := completePollWait
	completePollWait = 1500 * time.Millisecond
	t.Cleanup(func() { completePollWait = old })
	return r, &pollN
}

func (r *rig) control(path string, body any) (int, map[string]any) {
	r.t.Helper()
	raw, _ := json.Marshal(body)
	res, err := r.client.Post("http://minter/"+path+"/copilot-work", "application/json", bytes.NewReader(raw))
	if err != nil {
		r.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	for _, secret := range []string{"DEVICE-SECRET", "GITHUB_SECRET", "COPILOT_SECRET"} {
		if strings.Contains(string(data), secret) {
			r.t.Fatalf("a control answer carried %s: %q", secret, data)
		}
	}
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	return res.StatusCode, doc
}

func TestDeviceLoginStartsPendsThenSignsIn(t *testing.T) {
	r, _ := deviceRig(t, func(n int64) string {
		if n <= 3 {
			return "pending"
		}
		return "ok"
	})
	status, start := r.control("login-start", struct{}{})
	if status != 200 || start["status"] != "started" || start["verification_uri"] != "https://github.com/login/device" || start["user_code"] != "ABCD-1234" {
		t.Fatalf("start: %d %v", status, start)
	}
	if exp, _ := start["expires_in"].(float64); exp < 800 || exp > 900 {
		t.Fatalf("expires_in %v", start["expires_in"])
	}
	handle, _ := start["handle"].(string)
	if len(handle) < 16 {
		t.Fatalf("handle %q", handle)
	}
	if status, _ := r.control("login-start", struct{}{}); status != 409 {
		t.Fatalf("a second start while one is pending: %d", status)
	}
	status, doc := r.control("login-complete", map[string]string{"handle": handle})
	if status != http.StatusAccepted || doc["status"] != "pending" {
		t.Fatalf("first complete: %d %v", status, doc)
	}
	for i := 0; i < 5 && status == http.StatusAccepted; i++ {
		status, doc = r.control("login-complete", map[string]string{"handle": handle})
	}
	if status != 200 || doc["status"] != "signed-in" {
		t.Fatalf("complete: %d %v", status, doc)
	}
	if a := r.get("copilot-work"); a.status != 200 || a.Token != "COPILOT_SECRET" {
		t.Fatalf("after sign-in the credential serves: %d %q", a.status, a.raw)
	}
	if strings.Contains(r.logs.String(), "SECRET") {
		t.Fatalf("a secret reached the log: %q", r.logs.String())
	}
	if status, _ := r.control("login-complete", map[string]string{"handle": handle}); status != 400 {
		t.Fatalf("the handle must be one-use: %d", status)
	}
}

func TestDeviceLoginDeniedExpiredAndBadHandle(t *testing.T) {
	for _, tc := range []struct{ answer, want string }{{"denied", "invalid_login"}, {"expired", "login_expired"}} {
		r, _ := deviceRig(t, func(int64) string { return tc.answer })
		_, start := r.control("login-start", struct{}{})
		handle, _ := start["handle"].(string)
		if status, doc := r.control("login-complete", map[string]string{"handle": "not-the-handle-0123456789"}); status != 400 || doc["error"] != "invalid_handle" {
			t.Fatalf("%s: wrong handle: %d %v", tc.answer, status, doc)
		}
		if status, doc := r.control("login-complete", map[string]string{"handle": handle}); status != 400 || doc["error"] != tc.want {
			t.Fatalf("%s: got %d %v, want 400 %s", tc.answer, status, doc, tc.want)
		}
		if status, _ := r.control("login-start", struct{}{}); status != 200 {
			t.Fatalf("%s: a new start after the failed one: %d", tc.answer, status)
		}
	}
}

func TestDeviceLoginRejectsACodeAndHonoursSlowDown(t *testing.T) {
	r, polls := deviceRig(t, func(n int64) string {
		if n == 1 {
			return "slow"
		}
		return "pending"
	})
	_, start := r.control("login-start", struct{}{})
	handle, _ := start["handle"].(string)
	if status, _ := r.control("login-complete", map[string]string{"handle": handle, "code": "x"}); status != 400 {
		t.Fatalf("a code on a device sign-in: %d", status)
	}
	if status, _ := r.control("login-complete", map[string]string{"handle": handle}); status != http.StatusAccepted {
		t.Fatalf("pending: %d", status)
	}
	// slow_down widened the interval to 6 s, so a 1.5 s call polls once.
	if n := polls.Load(); n != 1 {
		t.Fatalf("polled %d times after a slow_down inside one 1.5 s call", n)
	}
}

func TestChatGPTRemoteLoginUnchangedForOtherKinds(t *testing.T) {
	r := newRig(t, seedTokens(3600))
	res, err := r.client.Post("http://minter/login-start/"+instName, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("a refresh_token instance must still have no remote sign-in: %d", res.StatusCode)
	}
}
