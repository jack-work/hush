package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jack-work/hush/internal/oauth"
)

func TestDrainStoppedRPCsNeverBecomePermanentOrTransientLoginErrors(t *testing.T) {
	a := newTestAgent(t, t.TempDir(), t.TempDir())
	if err := a.oauth.Stop(); err != nil {
		t.Fatal(err)
	}
	req := Request{OAuth: &OAuthRequest{Name: "fake"}}
	for _, reply := range [][]byte{a.handleOAuthGet(req), a.handleOAuthRefresh(req), a.handleOAuthDelete(req), a.handleOAuthRegister(req), a.handleOAuthList()} {
		var response Response
		if json.Unmarshal(reply, &response) != nil || response.OK || response.ErrorCode != ErrCodeOAuthStopped || strings.Contains(response.Error, "re-login") {
			t.Fatal("stopped RPC became a retry or login instruction")
		}
	}
	if oauthErrCode(oauth.ErrDrainUncertain) != ErrCodeOAuthDrainUncertain {
		t.Fatal("uncertain drain code lost")
	}
}

func TestDrainGenericAgentPropagatesUncertaintyInsteadOfClaimingCleanExit(t *testing.T) {
	root := t.TempDir()
	runtime := filepath.Join(root, "runtime-blocked")
	if err := os.WriteFile(runtime, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	a := newTestAgent(t, runtime, filepath.Join(root, "state"))
	var logs bytes.Buffer
	a.log = log.New(&logs, "", 0)
	cfg := oauth.Config{Name: "fake", TokenURL: "https://fake.invalid/token", ClientID: "fake"}
	if err := a.oauth.Register(cfg, oauth.Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "state", "oauth")
	if err := os.Rename(dir, dir+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.oauth.Register(cfg, oauth.Tokens{AccessToken: "A2", RefreshToken: "R2", ExpiresIn: 3600}); err == nil {
		t.Fatal("fake commit failure not established")
	}
	if err := a.Run(); !errors.Is(err, oauth.ErrDrainUncertain) {
		t.Fatal("generic agent ignored manager drain failure")
	}
	if !strings.Contains(logs.String(), "unresolved credential state") || strings.Contains(logs.String(), "agent stopped\n") {
		t.Fatal("generic agent log called uncertain custody clean")
	}
}
