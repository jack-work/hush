package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// fakeKey is what a leaked API key looks like in this test. It is checked
// for by exact string, so it must be distinctive.
const fakeKey = "sk-test-DO-NOT-LEAK-2f9c41ab"

// TestSecretRoundTrip exercises the reason hush exists: a secret goes in
// encrypted, is never written back as plaintext, and reaches exactly one
// place — the argv of the command that needs it.
//
// It also covers the `secret` command group end to end after the verbs
// were regrouped (encrypt-value → secret encrypt, decrypt-value → secret
// decrypt, encrypt/lock → secret seal).
func TestSecretRoundTrip(t *testing.T) {
	w := newWorld(t)
	hushDir := filepath.Join(w.base, "config", "hush")

	// `secret encrypt` needs only the public half, and no agent.
	key, err := age.ParseX25519Identity(strings.TrimSpace(string(w.id)))
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	if err := os.MkdirAll(hushDir, 0700); err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(hushDir, "identity.age.pub")
	if err := os.WriteFile(pubFile, []byte(key.Recipient().String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out, err := w.command("secret", "encrypt", fakeKey).Output()
	if err != nil {
		t.Fatalf("secret encrypt: %v", err)
	}
	wrapped := strings.TrimSpace(string(out))
	if !strings.HasPrefix(wrapped, "AGE-ENC[") {
		t.Fatalf("secret encrypt produced %q, want an AGE-ENC[...] wrapper", wrapped)
	}
	if strings.Contains(wrapped, fakeKey) {
		t.Fatal("the ciphertext contains the plaintext")
	}

	// A command that does nothing but hand the secret to a child process.
	cmdDir := filepath.Join(hushDir, "commands", "echoer")
	if err := os.MkdirAll(cmdDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(cmdDir, "command.sh"), `printf '%s' "{{.token}}"`)
	writeFile(t, filepath.Join(cmdDir, "secrets.toml"), "token = \""+wrapped+"\"\n")

	agent := w.startAgent(t)
	defer func() {
		_ = w.client().Shutdown()
		_ = agent.Wait()
	}()

	got, err := w.command("echoer").Output()
	if err != nil {
		t.Fatalf("run command: %v", err)
	}
	if string(got) != fakeKey {
		t.Fatalf("command received %q, want the decrypted key", got)
	}

	// The whole point: what is at rest stays encrypted.
	assertNoPlaintextAtRest(t, w.base)

	// `secret decrypt` is the inverse, and needs the agent.
	plain, err := w.command("secret", "decrypt", wrapped).Output()
	if err != nil {
		t.Fatalf("secret decrypt: %v", err)
	}
	if strings.TrimSpace(string(plain)) != fakeKey {
		t.Fatalf("secret decrypt returned %q", plain)
	}
}

// TestSecretSeal covers the sweep: a value typed in by hand as plaintext
// is encrypted in place, both when the command is named and when it is
// not (the old `encrypt <name>` and `lock`, now one verb).
func TestSecretSeal(t *testing.T) {
	w := newWorld(t)
	hushDir := filepath.Join(w.base, "config", "hush")

	key, err := age.ParseX25519Identity(strings.TrimSpace(string(w.id)))
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	if err := os.MkdirAll(hushDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hushDir, "identity.age.pub"), key.Recipient().String()+"\n")

	for _, name := range []string{"one", "two"} {
		dir := filepath.Join(hushDir, "commands", name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "command.sh"), `echo {{.token}}`)
		writeFile(t, filepath.Join(dir, "secrets.toml"), "token = \""+fakeKey+"\"\n")
	}

	// Named: seals just that one.
	if out, err := w.command("secret", "seal", "one").CombinedOutput(); err != nil {
		t.Fatalf("secret seal one: %v\n%s", err, out)
	}
	if readFile(t, filepath.Join(hushDir, "commands", "one", "secrets.toml")) == "" {
		t.Fatal("sealing emptied the file")
	}
	if !strings.Contains(readFile(t, filepath.Join(hushDir, "commands", "two", "secrets.toml")), fakeKey) {
		t.Fatal("naming one command sealed another")
	}

	// Bare: sweeps everything that is left.
	if out, err := w.command("secret", "seal").CombinedOutput(); err != nil {
		t.Fatalf("secret seal: %v\n%s", err, out)
	}
	assertNoPlaintextAtRest(t, w.base)
}

// assertNoPlaintextAtRest walks every file under root and fails if the
// secret appears in any of them.
func assertNoPlaintextAtRest(t *testing.T, root string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil //nolint:nilerr // unreadable sockets and the like are not our business
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil //nolint:nilerr
		}
		if strings.Contains(string(data), fakeKey) {
			t.Errorf("plaintext secret found at rest in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
