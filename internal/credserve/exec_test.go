//go:build linux

package credserve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
)

// erig serves one exec instance whose command is a shell script steered by
// files in dir: mode (ok | signin | fail | garbage | short), and a run count.
type erig struct {
	t      *testing.T
	dir    string
	srv    *Server
	logs   *syncBuffer
	client *http.Client
}

const execScript = `#!/bin/sh
d=$(dirname "$0")
n=$(( $(cat "$d/count" 2>/dev/null || echo 0) + 1 ))
echo $n > "$d/count"
echo "SECRET-STDERR-$n" >&2
case $(cat "$d/mode") in
  ok) echo "{\"token\":\"tok-$n\",\"expires_at\":$(( $(date +%s) + 3600 ))}" ;;
  far) echo "{\"token\":\"tok-$n\",\"expires_at\":$(( $(date +%s) + 7200 ))}" ;;
  short) echo "{\"token\":\"tok-$n\",\"expires_at\":$(( $(date +%s) + 5 ))}" ;;
  signin) exit 3 ;;
  garbage) echo "not json" ;;
  slow) sleep 0.3; echo "{\"token\":\"tok-$n\",\"expires_at\":$(( $(date +%s) + 3600 ))}" ;;
  *) exit 1 ;;
esac
`

func newExecRig(t *testing.T, mode string) *erig {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "token.sh")
	if err := os.WriteFile(script, []byte(execScript), 0o755); err != nil {
		t.Fatal(err)
	}
	e := &erig{t: t, dir: dir, logs: &syncBuffer{}}
	e.setMode(mode)
	key, _ := age.GenerateX25519Identity()
	cfg, err := ParseConfig([]byte(fmt.Sprintf(`
recipient = %q
allow_user = "rou2"

[instances.ado-feed]
kind = "exec"
command = [%q, "--resource", "x"]
timeout = "5s"
`, key.Recipient().String(), script)))
	if err != nil {
		t.Fatal(err)
	}
	e.srv = NewServer(cfg, nil, uint32(os.Getuid()), log.New(e.logs, "", 0))
	sockDir, err := os.MkdirTemp("", "credsock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "cred.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := e.srv.HTTPServer()
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	e.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	return e
}

func (e *erig) setMode(m string) {
	if err := os.WriteFile(filepath.Join(e.dir, "mode"), []byte(m+"\n"), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *erig) runs() int {
	b, _ := os.ReadFile(filepath.Join(e.dir, "count"))
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func (e *erig) do(method, path string) answer {
	e.t.Helper()
	req, _ := http.NewRequest(method, "http://minter"+path, nil)
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	a := answer{status: res.StatusCode, raw: string(body)}
	_ = json.Unmarshal(body, &a)
	return a
}

func TestExecServesAndCachesTheCommandsToken(t *testing.T) {
	e := newExecRig(t, "ok")
	a := e.do(http.MethodGet, "/cred/ado-feed")
	if a.status != 200 || a.Token != "tok-1" || a.Name != "ado-feed" {
		t.Fatalf("got %d %q", a.status, a.raw)
	}
	if left := time.Until(time.Unix(a.Expiry, 0)); left < 59*time.Minute {
		t.Fatalf("expires_at %s away", left)
	}
	if b := e.do(http.MethodGet, "/cred/ado-feed"); b.Token != "tok-1" || e.runs() != 1 {
		t.Fatalf("second read ran the command again: %q, runs %d", b.raw, e.runs())
	}
	e.setMode("far")
	e.srv.Now = func() time.Time { return time.Now().Add(3590 * time.Second) }
	if c := e.do(http.MethodGet, "/cred/ado-feed"); c.Token != "tok-2" {
		t.Fatalf("a token within the serve floor of expiry was served again: %q", c.raw)
	}
}

func TestExecConcurrentReadsRunTheCommandOnce(t *testing.T) {
	e := newExecRig(t, "slow")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a := e.do(http.MethodGet, "/cred/ado-feed"); a.Token != "tok-1" {
				t.Errorf("got %q", a.raw)
			}
		}()
	}
	wg.Wait()
	if n := e.runs(); n != 1 {
		t.Fatalf("20 concurrent reads ran the command %d times", n)
	}
}

func TestExecExitThreeIsSignInNeeded(t *testing.T) {
	e := newExecRig(t, "signin")
	a := e.do(http.MethodGet, "/cred/ado-feed")
	if a.status != http.StatusServiceUnavailable || a.Error != "credential_stale" || a.Reason != reasonSignIn {
		t.Fatalf("got %d %q", a.status, a.raw)
	}
}

func TestExecFailureIsTransientPacedAndNeverLogsStderr(t *testing.T) {
	for _, mode := range []string{"fail", "garbage", "short"} {
		e := newExecRig(t, mode)
		a := e.do(http.MethodGet, "/cred/ado-feed")
		if a.status != http.StatusBadGateway || a.Error != "transient" || a.Token != "" {
			t.Fatalf("%s: got %d %q", mode, a.status, a.raw)
		}
		e.do(http.MethodGet, "/cred/ado-feed")
		if n := e.runs(); n != 1 {
			t.Fatalf("%s: a failure was retried at once (%d runs)", mode, n)
		}
		if strings.Contains(e.logs.String(), "SECRET-STDERR") {
			t.Fatalf("%s: the command's stderr reached the log: %q", mode, e.logs.String())
		}
		e.setMode("ok")
		e.srv.Now = func() time.Time { return time.Now().Add(DefaultMinRefreshInterval + time.Second) }
		if b := e.do(http.MethodGet, "/cred/ado-feed"); b.status != 200 || b.Token != "tok-2" {
			t.Fatalf("%s: after the pause: got %d %q", mode, b.status, b.raw)
		}
	}
}

func TestExecRefreshRunsTheCommandAgain(t *testing.T) {
	e := newExecRig(t, "ok")
	e.do(http.MethodGet, "/cred/ado-feed")
	res, err := e.client.Post("http://minter/refresh/ado-feed", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || e.runs() != 2 {
		t.Fatalf("refresh: status %d, runs %d", res.StatusCode, e.runs())
	}
	if a := e.do(http.MethodGet, "/cred/ado-feed"); a.Token != "tok-2" {
		t.Fatalf("after refresh: %q", a.raw)
	}
}

func TestExecRefreshIsSingleFlightAndPaced(t *testing.T) {
	e := newExecRig(t, "ok")
	var wg sync.WaitGroup
	codes := make(chan int, 25)
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.client.Post("http://minter/refresh/ado-feed", "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Error(err)
				return
			}
			res.Body.Close()
			codes <- res.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 && c != http.StatusConflict {
			t.Errorf("a concurrent refresh answered %d", c)
		}
	}
	if n := e.runs(); n != 1 {
		t.Fatalf("25 concurrent refreshes ran the command %d times, want 1", n)
	}
	res, err := e.client.Post("http://minter/refresh/ado-feed", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	var body struct{ Refreshed bool }
	_ = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close()
	if res.StatusCode != 200 || body.Refreshed || e.runs() != 1 {
		t.Fatalf("a refresh inside the floor: status %d, refreshed %v, runs %d", res.StatusCode, body.Refreshed, e.runs())
	}
}

func TestExecConfigValidation(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	base := fmt.Sprintf("recipient = %q\nallow_user = \"rou2\"\n", key.Recipient().String())
	for name, tc := range map[string]struct{ body, want string }{
		"no command":   {"[instances.a]\nkind = \"exec\"\n", "command is required"},
		"relative":     {"[instances.a]\nkind = \"exec\"\ncommand = [\"az\"]\n", "not an absolute path"},
		"oauth field":  {"[instances.a]\nkind = \"exec\"\ncommand = [\"/bin/true\"]\nclient_id = \"x\"\n", "takes command and timeout only"},
		"bad timeout":  {"[instances.a]\nkind = \"exec\"\ncommand = [\"/bin/true\"]\ntimeout = \"10m\"\n", "timeout"},
		"command else": {"[instances.a]\nkind = \"copilot\"\ncommand = [\"/bin/true\"]\n", "belong to kind \"exec\""},
	} {
		_, err := ParseConfig([]byte(base + tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}
