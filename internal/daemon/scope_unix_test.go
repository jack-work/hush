//go:build !windows

package daemon

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func managerDir(t *testing.T, mode os.FileMode) (dir, socket string) {
	t.Helper()
	base, err := os.MkdirTemp("", "hush-mgr-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir = filepath.Join(base, "systemd")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket = filepath.Join(dir, "private")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir, socket
}

// An inherited XDG_RUNTIME_DIR can name someone else's directory or a
// container bind; the agent is handed only to a manager whose socket sits in
// a directory this user owns and nobody else can write.
func TestAManagerInADirectoryWeOwnAloneIsUsed(t *testing.T) {
	_, socket := managerDir(t, 0o700)
	if !ownManagerSocket(socket) {
		t.Fatal("a manager socket in our own 0700 directory was refused")
	}
}

func TestAManagerInADirectoryOthersCanWriteIsRefused(t *testing.T) {
	for name, mode := range map[string]os.FileMode{"group-writable": 0o770, "world-writable": 0o707} {
		t.Run(name, func(t *testing.T) {
			_, socket := managerDir(t, mode)
			if ownManagerSocket(socket) {
				t.Fatalf("a manager socket in a %s directory was used", name)
			}
		})
	}
}

func TestAManagerInADirectoryAnotherUserOwnsIsRefused(t *testing.T) {
	dir, _ := managerDir(t, 0o700)
	if trustedManagerDir(dir, os.Getuid()+1) {
		t.Fatal("a directory owned by another uid was trusted")
	}
}

func TestAManagerReachedThroughASymlinkIsRefused(t *testing.T) {
	dir, _ := managerDir(t, 0o700)
	link := filepath.Join(t.TempDir(), "systemd")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if ownManagerSocket(filepath.Join(link, "private")) {
		t.Fatal("a manager directory reached through a symlink was trusted")
	}
}

func sessionOf(t *testing.T, pid int) int {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Skipf("no /proc here: %v", err)
	}
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
	sid, _ := strconv.Atoi(fields[3])
	return sid
}

// Before, the child ran in its spawner's session with its stderr thrown
// away: an agent that failed to start said why to no one.
func TestASpawnedAgentLeadsItsOwnSessionAndLogsItsStderr(t *testing.T) {
	t.Setenv(noScopeEnv, "1")
	log := filepath.Join(t.TempDir(), "state", "agent.log")
	pid, err := Spawn("/bin/sh", []string{"-c", "echo the agent says why >&2; exec sleep 30"}, nil, bytes.NewReader([]byte("id")), Options{LogPath: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if sid := sessionOf(t, pid); sid != pid {
		t.Fatalf("the agent %d is in session %d, not one of its own", pid, sid)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		raw, _ := os.ReadFile(log)
		if strings.Contains(string(raw), "the agent says why") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the agent's stderr never reached %s: %q", log, raw)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
