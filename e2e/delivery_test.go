//go:build !windows

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These exercise the credential-delivery boundary through the real binary:
// a real agent, real encrypted secrets, real child processes.
//
// The properties under test are the ones that motivated the work — a secret
// must not appear in world-readable process metadata, and caller arguments
// must never become program text.

// writeCommand installs a hush command into a world, encrypting the given
// secrets through the running agent exactly as `hush secret new` would.
func (w *world) writeCommand(t *testing.T, name string, files map[string]string, secrets map[string]string) string {
	t.Helper()
	dir := filepath.Join(w.base, "config", "hush", "commands", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if len(secrets) > 0 {
		enc, err := w.client().Encrypt(secrets)
		if err != nil {
			t.Fatalf("encrypt secrets: %v", err)
		}
		var b strings.Builder
		for k, v := range enc {
			b.WriteString(k + " = \"" + v + "\"\n")
		}
		if err := os.WriteFile(filepath.Join(dir, "secrets.toml"), []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const canary = "canary-4a9f2b-do-not-leak"

// A legacy command — no command.toml at all — must keep working exactly as
// it did, and its secret must not be visible in the child's argv.
func TestLegacyCommandStillWorksAndDoesNotLeakToCmdline(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "legacy", map[string]string{
		"command.sh": "echo secret-is={{.token}}\n" +
			"cat /proc/$$/cmdline | tr '\\0' ' '\necho\n",
	}, map[string]string{"token": canary})

	out, err := w.command("legacy").CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	s := string(out)

	if !strings.Contains(s, "secret-is="+canary) {
		t.Errorf("legacy template delivery broke:\n%s", s)
	}
	// The cmdline line must not carry the secret.
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "/dev/fd/") && strings.Contains(line, canary) {
			t.Errorf("secret is visible in world-readable /proc/<pid>/cmdline:\n%s", line)
		}
	}
}

// The real proof for Phase 0: scan every process's cmdline on the machine
// while the command runs. Nothing anywhere may contain the secret.
func TestSecretNeverAppearsInAnyProcessCmdline(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "scan", map[string]string{
		"command.sh": "echo \"{{.token}}\" >/dev/null\n" +
			"for p in /proc/[0-9]*; do tr '\\0' ' ' <$p/cmdline 2>/dev/null; echo; done\n",
	}, map[string]string{"token": canary})

	out, err := w.command("scan").CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if strings.Contains(string(out), canary) {
		t.Error("the secret appeared in some process's cmdline — argv exposure is back")
	}
}

func TestEnvDeliveryEndToEnd(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "envcmd", map[string]string{
		"command.toml": "delivery = \"env\"\n\n[secrets]\ntoken = \"MY_TOKEN\"\n",
		"command.sh":   "echo got=$MY_TOKEN\n",
	}, map[string]string{"token": canary})

	out, err := w.command("envcmd").CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "got="+canary) {
		t.Errorf("secret did not reach the child environment:\n%s", out)
	}
}

// Scriptless commands: no interpreter anywhere, credential in the
// environment, caller args passed straight through as argv.
func TestScriptlessExecEndToEnd(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	// A tiny "binary" that reports its environment and arguments.
	bin := filepath.Join(w.base, "fakebin.sh")
	script := "#!/bin/sh\necho token=$FAKE_TOKEN\nfor a in \"$@\"; do echo \"arg=[$a]\"; done\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	w.writeCommand(t, "fake", map[string]string{
		"command.toml": "exec = \"" + bin + "\"\nargs = [\"--fixed\"]\n\n" +
			"[secrets]\ntoken = \"FAKE_TOKEN\"\n",
	}, map[string]string{"token": canary})

	payload := "'; echo PWNED; '"
	out, err := w.command("fake", payload).CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	s := string(out)

	if !strings.Contains(s, "token="+canary) {
		t.Errorf("credential did not reach the binary:\n%s", s)
	}
	if !strings.Contains(s, "arg=[--fixed]") || !strings.Contains(s, "arg=["+payload+"]") {
		t.Errorf("arguments did not arrive intact:\n%s", s)
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "PWNED" {
			t.Errorf("caller argument was executed:\n%s", s)
		}
	}
}

// Invoked through a symlink named after a command, hush runs that command
// and passes arguments through untouched.
func TestShimDispatchByArgv0(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "greet", map[string]string{
		"command.toml": "delivery = \"env\"\n\n[secrets]\ntoken = \"GREET_TOKEN\"\n",
		"command.sh":   "echo \"hello $1 (token=$GREET_TOKEN)\"\n",
	}, map[string]string{"token": canary})

	if out, err := w.command("shim", "install", "greet").CombinedOutput(); err != nil {
		t.Fatalf("shim install: %v\n%s", err, out)
	}
	link := filepath.Join(w.base, "state", "hush", "bin", "greet")
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("shim not created at %s: %v", link, err)
	}

	cmd := w.command()
	cmd.Path = link
	cmd.Args = []string{link, "world"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run through shim: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "hello world (token="+canary+")") {
		t.Errorf("shim dispatch failed:\n%s", out)
	}
}

// A shim must not catch the real binary that the brokered command itself
// invokes: the shims directory is stripped from the child's PATH.
func TestShimDirIsStrippedFromChildPath(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "loop", map[string]string{
		"command.sh": "echo PATH=$PATH\n",
	}, nil)

	if out, err := w.command("shim", "install", "loop").CombinedOutput(); err != nil {
		t.Fatalf("shim install: %v\n%s", err, out)
	}
	shims := filepath.Join(w.base, "state", "hush", "bin")

	cmd := w.command("loop")
	cmd.Env = append(cmd.Env, "PATH="+shims+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "PATH=") {
			continue
		}
		for _, p := range strings.Split(strings.TrimPrefix(line, "PATH="), ":") {
			if p == shims {
				t.Fatalf("shims dir survived into the child PATH: recursion is possible\n%s", line)
			}
		}
	}
}

func TestDoctorClassifiesCommands(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "risky", map[string]string{
		"command.sh": "q='{{index .Args 0}}'\ncurl -H \"tok: {{.token}}\" x\n",
	}, map[string]string{"token": canary})
	w.writeCommand(t, "clean", map[string]string{
		"command.toml": "delivery = \"env\"\n\n[secrets]\ntoken = \"T\"\n",
		"command.sh":   "echo $T\n",
	}, map[string]string{"token": canary})

	out, _ := w.command("doctor").CombinedOutput()
	s := string(out)

	if strings.Contains(s, canary) {
		t.Error("doctor decrypted secrets — it must only read key names")
	}
	if !strings.Contains(s, "WARN") || !strings.Contains(s, "risky") {
		t.Errorf("doctor did not flag the risky command:\n%s", s)
	}
	if !strings.Contains(s, "caller arguments into script text") {
		t.Errorf("doctor did not name the injection finding:\n%s", s)
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "clean") && strings.Contains(line, "WARN") {
			t.Errorf("doctor flagged an already-migrated command:\n%s", line)
		}
	}
}
