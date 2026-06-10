// Package e2e exercises the real hush binary end to end in a hermetic
// environment: a freshly built binary, temp XDG dirs, and a generated
// identity piped to the agent child the same way `hush up --daemon`
// does it. Nothing touches the developer's real config, state, runtime
// dirs, or identity.
package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/jack-work/hush/client"
)

var hushBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "hush-e2e-bin-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	hushBin = filepath.Join(dir, "hush")
	out, err := exec.Command("go", "build", "-buildvcs=false", "-o", hushBin, "..").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build hush: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// world is one isolated hush installation: its own XDG dirs and identity.
type world struct {
	base     string
	env      []string
	id       []byte
	sockPath string
	pidPath  string
}

// newWorld uses os.MkdirTemp rather than t.TempDir to keep the socket
// path under the 108-byte sun_path limit.
func newWorld(t *testing.T) *world {
	t.Helper()
	base, err := os.MkdirTemp("", "hush-e2e-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })

	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	runDir := filepath.Join(base, "run")
	for _, d := range []string{"config", "state", "run"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return &world{
		base: base,
		env: []string{
			"HOME=" + base,
			"XDG_CONFIG_HOME=" + filepath.Join(base, "config"),
			"XDG_STATE_HOME=" + filepath.Join(base, "state"),
			"XDG_RUNTIME_DIR=" + runDir,
		},
		id:       []byte(key.String() + "\n"),
		sockPath: filepath.Join(runDir, "hush", "agent.sock"),
		pidPath:  filepath.Join(runDir, "hush", "agent.pid"),
	}
}

func (w *world) command(args ...string) *exec.Cmd {
	cmd := exec.Command(hushBin, args...)
	cmd.Env = append(os.Environ(), w.env...)
	return cmd
}

// spawnAgent starts `hush up` in agent-child mode, piping the identity
// over fd 3 exactly like the daemon spawn path. Does not wait for the
// socket; callers decide whether they expect success.
func (w *world) spawnAgent(t *testing.T) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := w.command("up", "--ttl", "1m")
	cmd.Env = append(cmd.Env, "HUSH_AGENT_CHILD=1")
	cmd.ExtraFiles = []*os.File{pr}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	pr.Close()
	pw.Write(w.id)
	pw.Close()
	return cmd, &stderr
}

func (w *world) startAgent(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd, stderr := w.spawnAgent(t)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w.client().Ping() == nil {
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("agent never came up; stderr: %s", stderr.String())
	return nil
}

func (w *world) client() *client.Client {
	return client.NewWithSocket(w.sockPath)
}

func (w *world) lockFree(t *testing.T) bool {
	t.Helper()
	f, err := os.Open(w.pidPath)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return false
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return true
}

// TestUpDownLifecycle: full happy path — encrypt/decrypt round trip,
// oauth persistence across an agent restart, clean `hush down`, and the
// lock-file invariants after shutdown.
func TestUpDownLifecycle(t *testing.T) {
	w := newWorld(t)
	agent := w.startAgent(t)
	c := w.client()

	enc, err := c.Encrypt(map[string]string{"k": "sesame"})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(enc["k"], "AGE-ENC[") {
		t.Fatalf("encrypt returned %q, want AGE-ENC[...]", enc["k"])
	}
	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec["k"] != "sesame" {
		t.Fatalf("round trip got %q, want sesame", dec["k"])
	}

	err = c.OAuthRegister(client.OAuthRegisterRequest{
		Name:         "prov",
		TokenURL:     "https://token.invalid/oauth/token",
		ClientID:     "client-1",
		AccessToken:  "A1",
		RefreshToken: "R1",
		ExpiresIn:    3600,
	})
	if err != nil {
		t.Fatalf("oauth register: %v", err)
	}
	if tok, err := c.OAuthGet("prov"); err != nil || tok != "A1" {
		t.Fatalf("oauth get: %q, %v; want A1", tok, err)
	}

	if out, err := w.command("down").CombinedOutput(); err != nil {
		t.Fatalf("hush down: %v\n%s", err, out)
	}
	if err := agent.Wait(); err != nil {
		t.Fatalf("agent exit after down: %v", err)
	}

	if _, err := os.Stat(w.sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket should be gone after down, stat err: %v", err)
	}
	if _, err := os.Stat(w.pidPath); err != nil {
		t.Fatalf("pid (lock) file should persist after down: %v", err)
	}
	if !w.lockFree(t) {
		t.Fatal("lock still held after down")
	}

	// Restart: oauth state must come back from disk.
	agent2 := w.startAgent(t)
	if tok, err := w.client().OAuthGet("prov"); err != nil || tok != "A1" {
		t.Fatalf("oauth get after restart: %q, %v; want A1", tok, err)
	}
	if out, err := w.command("down").CombinedOutput(); err != nil {
		t.Fatalf("second down: %v\n%s", err, out)
	}
	agent2.Wait()
}

// TestSecondAgentRejected: a duplicate up must exit non-zero and leave
// the live agent fully intact (its socket used to be deleted by the
// loser's shutdown path).
func TestSecondAgentRejected(t *testing.T) {
	w := newWorld(t)
	agent := w.startAgent(t)

	dup, stderr := w.spawnAgent(t)
	err := dup.Wait()
	if err == nil {
		t.Fatal("duplicate agent exited 0, want failure")
	}
	if !strings.Contains(stderr.String(), "already running") {
		t.Fatalf("duplicate agent stderr %q, want 'already running'", stderr.String())
	}

	if err := w.client().Ping(); err != nil {
		t.Fatalf("live agent unreachable after duplicate was rejected: %v", err)
	}
	if _, err := os.Stat(w.sockPath); err != nil {
		t.Fatalf("live agent's socket missing after duplicate was rejected: %v", err)
	}

	if out, err := w.command("down").CombinedOutput(); err != nil {
		t.Fatalf("down: %v\n%s", err, out)
	}
	agent.Wait()
}

// TestSigkillRecovery: SIGKILL leaves the socket and pid file behind,
// but the kernel released the lock with the process — a successor must
// start cleanly and replace the stale socket.
func TestSigkillRecovery(t *testing.T) {
	w := newWorld(t)
	agent := w.startAgent(t)

	agent.Process.Kill()
	agent.Wait()

	if _, err := os.Stat(w.sockPath); err != nil {
		t.Fatalf("expected stale socket to remain after SIGKILL: %v", err)
	}
	if !w.lockFree(t) {
		t.Fatal("lock should be free after SIGKILL")
	}

	successor := w.startAgent(t)
	if err := w.client().Ping(); err != nil {
		t.Fatalf("successor unreachable: %v", err)
	}
	if out, err := w.command("down").CombinedOutput(); err != nil {
		t.Fatalf("down: %v\n%s", err, out)
	}
	successor.Wait()
}

// TestDownWithoutAgent: `hush down` against an empty world reports
// cleanly instead of crashing or deleting anything it shouldn't.
func TestDownWithoutAgent(t *testing.T) {
	w := newWorld(t)
	out, err := w.command("down").CombinedOutput()
	if err == nil {
		t.Fatalf("down with no agent exited 0:\n%s", out)
	}
	if !strings.Contains(string(out), "no agent running") {
		t.Fatalf("down output %q, want 'no agent running'", out)
	}
}
