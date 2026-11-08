package daemon

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const spawnInUnitEnv = "HUSH_TEST_SPAWN_IN_UNIT"

// TestHelperSpawnInUnit is the process a transient unit runs: it spawns an
// agent stand-in the way the embedded agent is spawned, prints its pid and
// exits, which ends the unit.
func TestHelperSpawnInUnit(t *testing.T) {
	out := os.Getenv(spawnInUnitEnv)
	if out == "" {
		t.Skip("run by TestAnAgentSpawnedByAUnitOutlivesIt")
	}
	pid, err := Spawn("/bin/sh", []string{"-c", "exec sleep 300"}, nil, bytes.NewReader([]byte("id")), Options{Instance: out})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func spawnInUnit(t *testing.T, extra ...string) (pid int, cgroup string) {
	t.Helper()
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if testing.Short() || xdg == "" || !ownManagerSocket(filepath.Join(xdg, "systemd", "private")) {
		t.Skip("no systemd user manager here")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("no systemd-run here")
	}
	out := filepath.Join(t.TempDir(), "pid")
	args := []string{"--user", "--wait", "--collect", "--quiet", "--pipe", "--setenv", spawnInUnitEnv + "=" + out}
	for _, kv := range extra {
		args = append(args, "--setenv", kv)
	}
	args = append(args, "--", os.Args[0], "-test.run", "^TestHelperSpawnInUnit$", "-test.count=1")
	cmd := exec.Command("systemd-run", args...)
	cmd.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS=unix:path="+filepath.Join(xdg, "bus"))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("systemd-run: %v\n%s", err, b)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the unit never reported its agent: %v", err)
	}
	pid, _ = strconv.Atoi(string(raw))
	t.Cleanup(func() {
		if strings.Contains(cgroupOf(pid), "hush-agent-") || strings.Contains(cgroupOf(pid), "run-") {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return pid, cgroupOf(pid)
}

func cgroupOf(pid int) string {
	raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	return strings.TrimSpace(string(raw))
}

func TestAnAgentSpawnedByAUnitOutlivesIt(t *testing.T) {
	pid, cg := spawnInUnit(t)
	if syscall.Kill(pid, 0) != nil {
		t.Fatalf("the agent %d died with the unit that spawned it", pid)
	}
	if !strings.Contains(cg, "/hush-agent-") || !strings.HasSuffix(cg, ".scope") {
		t.Fatalf("the agent %d is in %q, want a hush-agent scope of its own", pid, cg)
	}
}

func TestAnAgentTheKnobKeepsInItsUnitEndsWithIt(t *testing.T) {
	pid, _ := spawnInUnit(t, noScopeEnv+"=1")
	if syscall.Kill(pid, 0) == nil {
		t.Fatalf("the agent %d outlived its unit though %s=1 kept it there", pid, noScopeEnv)
	}
}
