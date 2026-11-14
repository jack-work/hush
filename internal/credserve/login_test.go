//go:build linux

package credserve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/jack-work/hush/internal/oauth"
)

func loginRig(t *testing.T) (*rig, *Login, *bytes.Buffer) {
	t.Helper()
	r := newRig(t, oauth.Tokens{})
	out := &bytes.Buffer{}
	l := &Login{
		Config:   r.cfg,
		StateDir: r.stateDir,
		Name:     instName,
		Client:   FencedClient(r.cfg.EgressHosts(), r.ep.roots()),
		Out:      out,
	}
	return r, l, out
}

func stateFromURL(t *testing.T, out string) string {
	t.Helper()
	m := regexp.MustCompile(`https://\S+`).FindString(out)
	u, err := url.Parse(m)
	if err != nil || u.Query().Get("state") == "" {
		t.Fatalf("no authorize URL with a state in %q", out)
	}
	return u.Query().Get("state")
}

func TestLoginExchangesThePastedCodeAndTheServerServesIt(t *testing.T) {
	r, l, out := loginRig(t)
	var exchange map[string]string
	r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
		body, _ := io.ReadAll(req.Body)
		json.Unmarshal(body, &exchange)
		return 200, `{"access_token":"at-login","refresh_token":"rt-login-abcdefgh","expires_in":28800}`
	})
	l.ReadCode = func(string) (string, error) { return "the-code#" + stateFromURL(t, out.String()), nil }
	if err := l.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if exchange["code"] != "the-code" || exchange["grant_type"] != "authorization_code" || exchange["code_verifier"] == "" {
		t.Fatalf("the exchange sent %v", exchange)
	}
	if a := r.get(instName); a.status != 200 || a.Token != "at-login" {
		t.Fatalf("got %q", a.raw)
	}
}

func TestLoginRefusesAStateFromAnotherLogin(t *testing.T) {
	r, l, _ := loginRig(t)
	l.ReadCode = func(string) (string, error) { return "the-code#not-this-one", nil }
	if err := l.Run(context.Background()); err == nil {
		t.Fatal("a foreign state was accepted")
	}
	if r.ep.posts.Load() != 0 {
		t.Fatal("the code was exchanged anyway")
	}
}

func TestLoginWillNotOverwriteALiveCredential(t *testing.T) {
	r, l, out := loginRig(t)
	seeder := oauth.NewManager(r.stateDir, nil, r.key.Recipient(), log.New(io.Discard, "", 0))
	if err := seeder.Register(r.cfg.Instances[instName].OAuthConfig(instName), seedTokens(3600)); err != nil {
		t.Fatal(err)
	}
	seeder.Stop()
	l.ReadCode = func(string) (string, error) { return "c#" + stateFromURL(t, out.String()), nil }
	if err := l.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("a live credential was signed over: %v", err)
	}
	l.Replace = true
	if err := l.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLoginDoesNotNeedTheIdentity(t *testing.T) {
	r, l, out := loginRig(t)
	l.ReadCode = func(string) (string, error) { return "c#" + stateFromURL(t, out.String()), nil }
	if err := l.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := oauth.NewManager(r.stateDir, []age.Identity{r.key}, r.key.Recipient(), log.New(io.Discard, "", 0))
	defer m.Stop()
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if tok, err := m.Get(instName); err != nil || tok != "at-1" {
		t.Fatalf("the server's key cannot read what login wrote: %q %v", tok, err)
	}
}

func TestCopilotLoginRunsTheDeviceFlowAndMintsASession(t *testing.T) {
	r, l, out := loginRig(t)
	base := r.ep.srv.URL
	in := Instance{
		Kind:           KindCopilot,
		DeviceURL:      base + "/login/device/code",
		GitHubTokenURL: base + "/login/oauth/access_token",
		TokenURL:       base + "/copilot_internal/v2/token",
		ClientID:       "Iv1.x",
	}
	r.cfg.Instances["copilot-work"] = in
	l.Name = "copilot-work"
	var exchangeAuth string
	r.ep.setAnswer(func(_ int64, req *http.Request) (int, string) {
		switch req.URL.Path {
		case "/login/device/code":
			return 200, `{"device_code":"dc","user_code":"ABCD-1234","verification_uri":"https://github.example/login/device","expires_in":900,"interval":1}`
		case "/login/oauth/access_token":
			return 200, `{"access_token":"gho-durable-abcdefgh","token_type":"bearer"}`
		default:
			exchangeAuth = req.Header.Get("Authorization")
			return 200, `{"token":"copilot-session","expires_at":` + strconv.FormatInt(time.Now().Add(30*time.Minute).Unix(), 10) + `,"endpoints":{"api":"https://api.copilot.example"}}`
		}
	})
	l.ReadCode = func(string) (string, error) { t.Fatal("the device flow asked for a code"); return "", nil }
	if err := l.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ABCD-1234") {
		t.Fatalf("the user code was not shown: %q", out)
	}
	if exchangeAuth != "Bearer gho-durable-abcdefgh" {
		t.Fatalf("the session was minted with %q", exchangeAuth)
	}
	if a := r.get("copilot-work"); a.status != 200 || a.Token != "copilot-session" {
		t.Fatalf("got %q", a.raw)
	}
	if strings.Contains(out.String(), "gho-durable") {
		t.Fatal("the GitHub token was printed")
	}
}
