//go:build !windows

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The [env] table through the real binary: plain environment a command
// carries with it, next to a credential it does not. docs/command-env.md.

// The motivating case, in miniature: a scriptless command whose
// compatibility flags live in the spec rather than in a per-machine config,
// with its credential still arriving from the vault.
func TestPlainEnvReachesTheChildBesideACredential(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	bin := filepath.Join(w.base, "reportenv.sh")
	script := "#!/bin/sh\n" +
		"echo calc=$AWS_REQUEST_CHECKSUM_CALCULATION\n" +
		"echo key=$AWS_ACCESS_KEY_ID\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	w.writeCommand(t, "files", map[string]string{
		"command.toml": "exec = \"" + bin + "\"\n\n" +
			"[env]\nAWS_REQUEST_CHECKSUM_CALCULATION = \"WHEN_REQUIRED\"\n\n" +
			"[secrets]\naccess_key_id = \"AWS_ACCESS_KEY_ID\"\n",
	}, map[string]string{"access_key_id": canary})

	out, err := w.command("files").CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "calc=WHEN_REQUIRED") {
		t.Errorf("plain env did not reach the child:\n%s", s)
	}
	if !strings.Contains(s, "key="+canary) {
		t.Errorf("credential did not reach the child:\n%s", s)
	}
}

// What the caller exported must not defeat a compatibility flag the command
// declares about itself.
func TestPlainEnvBeatsTheInheritedEnvironment(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "mode", map[string]string{
		"command.toml": "[env]\nCHECKSUM_MODE = \"WHEN_REQUIRED\"\n",
		"command.sh":   "echo mode=$CHECKSUM_MODE\n",
	}, nil)

	cmd := w.command("mode")
	cmd.Env = append(cmd.Env, "CHECKSUM_MODE=WHEN_SUPPORTED")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "mode=WHEN_REQUIRED") {
		t.Errorf("the inherited value won:\n%s", out)
	}
}

// A spec that puts plain text where a credential goes must not run at all.
func TestEnvCollidingWithASecretRefusesToRun(t *testing.T) {
	w := newWorld(t)
	defer w.command("down").Run()
	w.startAgent(t)

	w.writeCommand(t, "clash", map[string]string{
		"command.toml": "delivery = \"env\"\n\n[env]\nBRAVE_AUTH = \"plaintext\"\n\n" +
			"[secrets]\ntoken = \"BRAVE_AUTH\"\n",
		"command.sh": "echo got=$BRAVE_AUTH\n",
	}, map[string]string{"token": canary})

	out, err := w.command("clash").CombinedOutput()
	if err == nil {
		t.Fatalf("the command ran despite a credential collision:\n%s", out)
	}
	if !strings.Contains(string(out), "both map to") {
		t.Errorf("refusal does not name the collision:\n%s", out)
	}
	if strings.Contains(string(out), canary) {
		t.Errorf("the refusal leaked the secret:\n%s", out)
	}
}
