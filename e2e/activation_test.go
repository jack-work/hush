//go:build linux

package e2e

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
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// TestSocketActivation runs the real binary the way systemd runs it:
// something else binds the socket, hush inherits it, and the client that
// triggered the start gets its answer on the connection it already has.
//
// The unit tests can drive an inherited descriptor, but only a real
// activator can catch the failure that shipped in v0.10.1 — an activated
// `hush up` probing its own socket to see whether an agent was already
// answering, and waiting for a reply that only it could send. Everything
// looked healthy; the client just timed out.
func TestSocketActivation(t *testing.T) {
	activate, err := exec.LookPath("systemd-socket-activate")
	if err != nil {
		t.Skip("systemd-socket-activate not installed; cannot drive a real activation")
	}

	w := newWorld(t)
	const passphrase = "e2e-activation-passphrase"
	w.writeUnlockableIdentity(t, passphrase)

	sockDir := filepath.Dir(w.sockPath)
	if err := os.MkdirAll(sockDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Without --accept this is systemd's default socket-unit shape: one
	// listening descriptor handed to one process, which does its own
	// accepting.
	// The activator does not hand its own environment to the child, so
	// the world's directories travel by --setenv.
	argv := []string{"--listen", w.sockPath}
	for _, kv := range w.env {
		argv = append(argv, "--setenv", kv)
	}
	argv = append(argv, hushBin, "up", "--ttl", "1m")
	cmd := exec.Command(activate, argv...)
	cmd.Env = append(os.Environ(), w.env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start activator: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	waitForListener(t, w.sockPath)

	// The first client connection is what starts the agent. It must be
	// answered on that same connection: no refusal, no retry, no
	// "agent is not running".
	values, err := w.client().Encrypt(map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("first client call after activation failed: %v\nactivator output:\n%s", err, out.String())
	}
	if !strings.HasPrefix(values["k"], "AGE-ENC[") {
		t.Fatalf("encrypt returned %q, want an AGE-ENC value", values["k"])
	}

	if w.lockFree(t) {
		t.Error("an agent is serving, but its single-instance lock is free")
	}

	// The socket node belongs to the activator. Stopping the agent must
	// leave it exactly where it was, or the next activation has nothing
	// to fire on.
	if err := w.client().Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !w.lockFree(t) {
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(w.sockPath); err != nil {
		t.Fatalf("activated agent removed the manager's socket node: %v", err)
	}
}

// writeUnlockableIdentity gives the world a passphrase-wrapped identity
// file and a hush.toml that unlocks it without a terminal — the shape
// every non-interactive start has, activated or not. The work factor is
// the lowest age allows, because this test is about plumbing, not scrypt.
func (w *world) writeUnlockableIdentity(t *testing.T, passphrase string) {
	t.Helper()

	cfgDir := filepath.Join(w.base, "config", "hush")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}

	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatalf("scrypt recipient: %v", err)
	}
	r.SetWorkFactor(10)

	f, err := os.OpenFile(filepath.Join(cfgDir, "identity.age"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	armorWriter := armor.NewWriter(f)
	wc, err := age.Encrypt(armorWriter, r)
	if err != nil {
		t.Fatalf("encrypt identity: %v", err)
	}
	if _, err := wc.Write(w.id); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	for _, c := range []interface{ Close() error }{wc, armorWriter, f} {
		if err := c.Close(); err != nil {
			t.Fatalf("close identity file: %v", err)
		}
	}

	passFile := filepath.Join(w.base, "passphrase")
	if err := os.WriteFile(passFile, []byte(passphrase), 0600); err != nil {
		t.Fatal(err)
	}
	toml := fmt.Sprintf("[unlock]\nmethod = \"exec\"\nexec = [\"cat\", %q]\n", passFile)
	if err := os.WriteFile(filepath.Join(cfgDir, "hush.toml"), []byte(toml), 0600); err != nil {
		t.Fatal(err)
	}
}

// waitForListener waits until the activator's socket is LISTENING, without
// connecting to it: connecting is what starts the agent. The node exists from
// bind(), before listen(); a client in that gap is refused ("ain't running").
func waitForListener(t *testing.T, sockPath string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if listening(t, sockPath) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("activator never listened on %s", sockPath)
}

// soAcceptCon is __SO_ACCEPTCON, the /proc/net/unix Flags bit of a socket
// that has called listen().
const soAcceptCon = 0x10000

// listening reports whether a unix socket bound at path is listening, from
// /proc/net/unix (columns: Num RefCount Protocol Flags Type St Inode Path).
func listening(t *testing.T, path string) bool {
	t.Helper()
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		t.Fatalf("read /proc/net/unix: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[7] != path {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			t.Fatalf("/proc/net/unix flags %q: %v", f[3], err)
		}
		if flags&soAcceptCon != 0 {
			return true
		}
	}
	return false
}

// TestListeningIsTrueOnlyAfterListen pins waitForListener's question: a bound
// socket that has not called listen() is the state the activation flake hit
// (the node exists, connect is refused). RED if listening() goes back to
// "the node exists".
func TestListeningIsTrueOnlyAfterListen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.sock")
	if listening(t, path) {
		t.Fatal("absent socket: listening = true, want false")
	}
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("control: bind made no node: %v", err)
	}
	if listening(t, path) {
		t.Fatal("bound, not listening: listening = true, want false")
	}
	if err := syscall.Listen(fd, 1); err != nil {
		t.Fatal(err)
	}
	if !listening(t, path) {
		t.Fatal("listening socket: listening = false, want true")
	}
}
