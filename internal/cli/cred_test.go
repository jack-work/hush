//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func writeCredConfig(t *testing.T) string {
	t.Helper()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	body := `recipient = "` + key.Recipient().String() + `"
allow_user = "0"
[instances.anthropic-work]
kind = "anthropic"
authorize_url = "https://claude.example/oauth/authorize"
token_url = "https://console.example/v1/oauth/token"
redirect_uri = "https://console.example/oauth/code/callback"
client_id = "c"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCred(t *testing.T, args ...string) error {
	t.Helper()
	rootCmd.SetArgs(args)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	return rootCmd.Execute()
}

// Row (v): the code is read from a terminal or not at all.
func TestCredLoginRefusesAPipedStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString("code#state\n")
	w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; r.Close() })

	err = runCred(t, "cred", "login", "anthropic-work", "--config", writeCredConfig(t), "--state-dir", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("a piped code was accepted: %v", err)
	}
}

// Row (v): there is no way to hand the code over in argv.
func TestCredLoginTakesNoCodeInArgv(t *testing.T) {
	cfg := writeCredConfig(t)
	for _, args := range [][]string{
		{"cred", "login", "anthropic-work", "abc#def", "--config", cfg},
		{"cred", "login", "anthropic-work", "--code", "abc#def", "--config", cfg},
	} {
		if err := runCred(t, args...); err == nil {
			t.Fatalf("login accepted a code in argv: %v", args)
		}
	}
}
