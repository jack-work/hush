//go:build linux

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// waitForListener waits for the activator to bind, which is not the same
// question as "is an agent running" — connecting is what starts one.
func waitForListener(t *testing.T, sockPath string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("activator never bound %s", sockPath)
}
