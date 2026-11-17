//go:build !windows

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// `hush oauth get keel`, run by paperd's keel-viewer units before every
// request, sat for up to seven days with no agent up and an agent start
// that never finished. Whatever step of the start stalls, the command must
// give up at its deadline with an error that says so, and must not leave
// the unlock helper it launched behind.
func TestOAuthGetGivesUpWhenStartingTheAgentNeverFinishes(t *testing.T) {
	w := newWorld(t)
	cfgDir := filepath.Join(w.base, "config", "hush")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	helperPid := filepath.Join(w.base, "helper.pid")
	toml := fmt.Sprintf("[unlock]\nmethod = \"exec\"\nexec = [\"sh\", \"-c\", \"echo $$ > %s; exec sleep 300\"]\n", helperPid)
	if err := os.WriteFile(filepath.Join(cfgDir, "hush.toml"), []byte(toml), 0600); err != nil {
		t.Fatal(err)
	}

	limit := 2 * time.Second
	cmd := w.command("oauth", "get", "keel", "--timeout", limit.String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	exited := make(chan error, 1)
	start := time.Now()
	go func() { exited <- cmd.Wait() }()

	select {
	case err := <-exited:
		if err == nil {
			t.Fatalf("oauth get succeeded with no agent and a stalled unlock; stdout %q", stdout.String())
		}
		if took := time.Since(start); took > limit+5*time.Second {
			t.Fatalf("oauth get gave up after %s, well past its %s deadline", took, limit)
		}
	case <-time.After(limit + 20*time.Second):
		t.Fatalf("oauth get never gave up; stderr: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("a failed oauth get printed to stdout: %q", stdout.String())
	}
	if want := "no token within " + limit.String(); !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr does not say %q:\n%s", want, stderr.String())
	}

	raw, err := os.ReadFile(helperPid)
	if err != nil {
		t.Fatalf("the unlock helper never ran, so the test proved nothing: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("the unlock helper (pid %d) outlived oauth get: kill(0) = %v", pid, err)
	}
}
