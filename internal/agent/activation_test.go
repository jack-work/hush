//go:build !windows

package agent

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// activationEnv points the adoption path at fd, as a service manager
// would, and restores the environment when the test ends.
func activationEnv(t *testing.T, fd int, pid int, count string) {
	t.Helper()
	prev := listenFdsStart
	listenFdsStart = fd
	t.Cleanup(func() { listenFdsStart = prev })
	t.Setenv("LISTEN_PID", strconv.Itoa(pid))
	t.Setenv("LISTEN_FDS", count)
}

// listeningFd binds path and returns a descriptor for the listening
// socket, detached from Go's listener the way systemd hands one over:
// the node stays on disk and nothing else will unlink it.
func listeningFd(t *testing.T, path string) *os.File {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("bind %s: %v", path, err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	f, err := ul.File() // a dup; survives the Close below
	if err != nil {
		t.Fatalf("dup listener fd: %v", err)
	}
	ul.Close()
	t.Cleanup(func() { f.Close() })
	return f
}

// TestRunAdoptsInheritedSocket is the socket-activation path end to end:
// the agent serves on a socket it never bound, and — the part that keeps
// activation working — leaves the node in place when it stops, because
// the service manager is still listening on that inode.
func TestRunAdoptsInheritedSocket(t *testing.T) {
	rt, st := tempRuntimeDir(t), t.TempDir()
	sock := filepath.Join(rt, "agent.sock")

	f := listeningFd(t, sock)
	activationEnv(t, int(f.Fd()), os.Getpid(), "1")

	a := newTestAgent(t, rt, st)
	done := make(chan error, 1)
	go func() { done <- a.Run() }()

	// A dial cannot be the readiness signal here: the node is already
	// listening (that is the point of activation), so connect(2)
	// succeeds while the agent is still unlocking. Wait for an answer
	// instead — which also proves the queued connection is served.
	waitForReply(t, sock)

	if !a.activated {
		t.Fatal("agent bound its own socket; expected it to adopt the inherited one")
	}
	if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" {
		t.Errorf("activation env still set after claim: LISTEN_PID=%q LISTEN_FDS=%q",
			os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"))
	}

	a.listener.Close()
	if err := <-done; err != nil {
		t.Fatalf("agent exit: %v", err)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Fatalf("inherited socket node must survive shutdown (it is the manager's): %v", err)
	}
}

// TestRunBindsItselfWhenNotActivated is the `hush up -d` path: a stale
// LISTEN_PID belonging to some other process must not tempt the agent
// into adopting a stranger's descriptor.
func TestRunBindsItselfWhenNotActivated(t *testing.T) {
	rt, st := tempRuntimeDir(t), t.TempDir()

	// A descriptor is there for the taking, but the claim names another
	// process — systemd sets LISTEN_PID after fork precisely so this
	// case is detectable.
	f := listeningFd(t, filepath.Join(rt, "someone-else.sock"))
	activationEnv(t, int(f.Fd()), os.Getpid()+1, "1")

	a := newTestAgent(t, rt, st)
	done := make(chan error, 1)
	go func() { done <- a.Run() }()
	waitForSocket(t, a.sockPath())

	if a.activated {
		t.Fatal("agent adopted a descriptor claimed by another pid")
	}

	a.listener.Close()
	if err := <-done; err != nil {
		t.Fatalf("agent exit: %v", err)
	}
	if _, err := os.Stat(a.sockPath()); !os.IsNotExist(err) {
		t.Fatalf("a self-bound socket is ours to clean up, stat err: %v", err)
	}
}

// TestBindSocketRefusesLiveNode covers the collision the two paths can
// have on one box: the socket unit is armed, and someone types
// `hush up -d`. Unlinking the unit's node would leave activation
// permanently dead, so the self-bind path refuses.
func TestBindSocketRefusesLiveNode(t *testing.T) {
	if !hasProcNetUnix() {
		t.Skip("no /proc/net/unix; liveness cannot be answered passively here")
	}
	rt, st := tempRuntimeDir(t), t.TempDir()
	sock := filepath.Join(rt, "agent.sock")
	listeningFd(t, sock) // armed, but nobody holds hush's lock

	a := newTestAgent(t, rt, st)
	err := a.Run()
	if err == nil {
		t.Fatal("expected a refusal; got a bind over a live socket node")
	}
	if _, serr := os.Stat(sock); serr != nil {
		t.Fatalf("refusal must leave the node alone: %v", serr)
	}
}

func TestInheritedListener(t *testing.T) {
	t.Run("no activation env", func(t *testing.T) {
		t.Setenv("LISTEN_PID", "")
		t.Setenv("LISTEN_FDS", "")
		ln, err := inheritedListener()
		if ln != nil || err != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", ln, err)
		}
	})

	t.Run("zero descriptors", func(t *testing.T) {
		activationEnv(t, 0, os.Getpid(), "0")
		ln, err := inheritedListener()
		if ln != nil || err != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", ln, err)
		}
	})

	t.Run("more than one descriptor", func(t *testing.T) {
		activationEnv(t, 0, os.Getpid(), "2")
		if _, err := inheritedListener(); err == nil {
			t.Fatal("expected a loud failure for an unexpected descriptor count")
		}
	})

	t.Run("unparseable count", func(t *testing.T) {
		activationEnv(t, 0, os.Getpid(), "many")
		if _, err := inheritedListener(); err == nil {
			t.Fatal("expected a loud failure for a non-numeric LISTEN_FDS")
		}
	})
}

func TestSocketIsListening(t *testing.T) {
	if !hasProcNetUnix() {
		t.Skip("no /proc/net/unix")
	}
	dir := tempRuntimeDir(t)

	live := filepath.Join(dir, "live.sock")
	listeningFd(t, live)
	if !socketIsListening(live) {
		t.Errorf("%s is listening, reported dead", live)
	}

	dead := filepath.Join(dir, "dead.sock")
	if err := os.WriteFile(dead, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if socketIsListening(dead) {
		t.Errorf("%s is a plain file, reported live", dead)
	}

	if socketIsListening(filepath.Join(dir, "absent.sock")) {
		t.Error("a path that does not exist reported live")
	}
}

// waitForReply blocks until an agent answers a status request on the
// socket. Unlike a bare dial it cannot be satisfied by an armed but
// unserved socket node.
func waitForReply(t *testing.T, sockPath string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lastErr = statusRoundTrip(sockPath)
		if lastErr == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no agent answered on %s: %v", sockPath, lastErr)
}

func statusRoundTrip(sockPath string) error {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(`{"op":"status"}` + "\n")); err != nil {
		return err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

func hasProcNetUnix() bool {
	_, err := os.Stat("/proc/net/unix")
	return err == nil
}

// tempRuntimeDir keeps socket paths under the 108-byte sun_path limit,
// which t.TempDir() names can blow through on a long test name.
func tempRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hush-act-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
