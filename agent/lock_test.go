package agent

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/jack-work/hush/identity"
)

func newTestAgent(t *testing.T, runtimeDir, stateDir string) *Agent {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	id, err := identity.ParseRaw([]byte(key.String() + "\n"))
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	return New(id, time.Minute, runtimeDir, stateDir, log.New(os.Stderr, "test: ", 0))
}

func waitForSocket(t *testing.T, sockPath string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ping(sockPath) == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent socket %s never came up", sockPath)
}

// TestSecondAgentRejected proves the single-instance lock: a second Run in
// the same runtime dir fails fast, and — regression for the old behavior
// where a failed startup's shutdown deleted the live agent's files — the
// first agent's socket must remain reachable afterward.
func TestSecondAgentRejected(t *testing.T) {
	rt, st := t.TempDir(), t.TempDir()

	a1 := newTestAgent(t, rt, st)
	done := make(chan error, 1)
	go func() { done <- a1.Run() }()
	waitForSocket(t, a1.sockPath())

	a2 := newTestAgent(t, rt, st)
	err := a2.Run()
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second agent: want 'already running' error, got %v", err)
	}

	if perr := ping(a1.sockPath()); perr != nil {
		t.Fatalf("first agent's socket unreachable after rejected second start: %v", perr)
	}

	data, err := os.ReadFile(filepath.Join(rt, "agent.pid"))
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr != nil || pid != os.Getpid() {
		t.Fatalf("pid file content %q, want our pid %d", data, os.Getpid())
	}

	a1.listener.Close()
	if rerr := <-done; rerr != nil {
		t.Fatalf("first agent exit: %v", rerr)
	}
}

// TestLockReleasedOnShutdown proves a clean shutdown releases the lock and
// leaves the pid file in place (it is the lock inode), so a successor can
// start in the same runtime dir.
func TestLockReleasedOnShutdown(t *testing.T) {
	rt, st := t.TempDir(), t.TempDir()

	a1 := newTestAgent(t, rt, st)
	done := make(chan error, 1)
	go func() { done <- a1.Run() }()
	waitForSocket(t, a1.sockPath())
	a1.listener.Close()
	if err := <-done; err != nil {
		t.Fatalf("first agent exit: %v", err)
	}

	if _, err := os.Stat(filepath.Join(rt, "agent.pid")); err != nil {
		t.Fatalf("pid (lock) file should persist after shutdown: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rt, "agent.sock")); !os.IsNotExist(err) {
		t.Fatalf("socket should be removed after shutdown, stat err: %v", err)
	}

	a2 := newTestAgent(t, rt, st)
	done2 := make(chan error, 1)
	go func() { done2 <- a2.Run() }()
	waitForSocket(t, a2.sockPath())
	a2.listener.Close()
	if err := <-done2; err != nil {
		t.Fatalf("successor agent exit: %v", err)
	}
}
