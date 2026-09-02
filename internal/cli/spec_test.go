package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCmdDir(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadSpecMissingFileIsLegacyDefault(t *testing.T) {
	dir := writeCmdDir(t, "legacy", map[string]string{"command.sh": "echo hi"})
	spec, err := LoadSpec(dir)
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	if spec.Delivery != DeliveryScript {
		t.Errorf("delivery = %q, want %q", spec.Delivery, DeliveryScript)
	}
	if spec.EnvDelivery() || spec.Scriptless() {
		t.Error("a command with no command.toml must behave exactly as before")
	}
}

func TestLoadSpecExecImpliesEnvDelivery(t *testing.T) {
	dir := writeCmdDir(t, "gh", map[string]string{
		"command.toml": "exec = \"/usr/bin/gh\"\n\n[secrets]\ntoken = \"GH_TOKEN\"\n",
	})
	spec, err := LoadSpec(dir)
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	if !spec.Scriptless() {
		t.Error("exec should make the command scriptless")
	}
	if !spec.EnvDelivery() {
		t.Error("exec should imply env delivery: there is no script to render into")
	}
	if spec.Secrets["token"] != "GH_TOKEN" {
		t.Errorf("secrets = %v", spec.Secrets)
	}
}

func TestLoadSpecTimeout(t *testing.T) {
	dir := writeCmdDir(t, "slow", map[string]string{
		"command.toml": "delivery = \"env\"\ntimeout = \"1500ms\"\n",
	})
	spec, err := LoadSpec(dir)
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	if spec.Timeout.Duration != 1500*time.Millisecond {
		t.Errorf("timeout = %v, want 1.5s", spec.Timeout.Duration)
	}
}

func TestSpecValidateRejections(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want string
	}{
		{"relative exec", "exec = \"gh\"\n", "absolute path"},
		{"exec with script delivery", "exec = \"/usr/bin/gh\"\ndelivery = \"script\"\n", "no script"},
		{"unknown delivery", "delivery = \"telepathy\"\n", "want"},
		{"args without exec", "args = [\"-x\"]\n", "without exec"},
		{"empty env name", "delivery = \"env\"\n[secrets]\ntoken = \"\"\n", "empty environment"},
		{"bad env name", "delivery = \"env\"\n[secrets]\ntoken = \"A B\"\n", "not a valid environment"},
		{"bad duration", "timeout = \"soon\"\n", "not a duration"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeCmdDir(t, "x", map[string]string{"command.toml": c.toml})
			_, err := LoadSpec(dir)
			if err == nil {
				t.Fatalf("expected rejection, got none")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestSpecValidateRejectsDuplicateEnvNames(t *testing.T) {
	dir := writeCmdDir(t, "dup", map[string]string{
		"command.toml": "delivery = \"env\"\n[secrets]\na = \"TOKEN\"\nb = \"TOKEN\"\n",
	})
	if _, err := LoadSpec(dir); err == nil || !strings.Contains(err.Error(), "both map to") {
		t.Fatalf("expected duplicate-name rejection, got %v", err)
	}
}

func TestSecretEnvSortedAndComplete(t *testing.T) {
	spec := &Spec{Secrets: map[string]string{"b": "BEE", "a": "AY"}}
	env, err := spec.SecretEnv(map[string]string{"a": "1", "b": "2"})
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by secrets.toml key, so the child environment is deterministic.
	if len(env) != 2 || env[0] != "AY=1" || env[1] != "BEE=2" {
		t.Errorf("env = %v", env)
	}
}

func TestSecretEnvMissingSecretIsAnError(t *testing.T) {
	spec := &Spec{Secrets: map[string]string{"token": "TOKEN"}}
	_, err := spec.SecretEnv(map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "not present in secrets.toml") {
		t.Fatalf("a declared-but-absent secret must fail loudly, got %v", err)
	}
}
