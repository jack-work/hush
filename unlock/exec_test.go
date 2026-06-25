package unlock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jack-work/hush/config"
)

// writeShim drops a tiny POSIX shell script at base/<name> that prints
// the given string on stdout (no trailing newline added by us — the
// caller picks). Returns the absolute path. Marked executable.
func writeShim(t *testing.T, base, name, out string) string {
	t.Helper()
	path := filepath.Join(base, name)
	body := "#!/bin/sh\nprintf '%s' " + shellQuote(out) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write shim: %v", err)
	}
	return path
}

// shellQuote wraps s in single quotes, escaping any embedded single
// quote with the standard '\'' dance. Good enough for our test inputs.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func TestExecUnlocker_StripsSingleTrailingLF(t *testing.T) {
	dir := t.TempDir()
	shim := writeShim(t, dir, "pp.sh", "hunter2\n")

	u, err := New(execCfg(shim))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pp, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != "hunter2" {
		t.Fatalf("got %q, want %q", pp, "hunter2")
	}
}

func TestExecUnlocker_StripsSingleTrailingCRLF(t *testing.T) {
	dir := t.TempDir()
	shim := writeShim(t, dir, "pp.sh", "hunter2\r\n")

	u, _ := New(execCfg(shim))
	pp, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != "hunter2" {
		t.Fatalf("got %q, want %q", pp, "hunter2")
	}
}

func TestExecUnlocker_PreservesInternalAndLeadingWhitespace(t *testing.T) {
	dir := t.TempDir()
	shim := writeShim(t, dir, "pp.sh", " tab\there\n")

	u, _ := New(execCfg(shim))
	pp, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != " tab\there" {
		t.Fatalf("got %q, want %q", pp, " tab\there")
	}
}

func TestExecUnlocker_EmptyOutputIsError(t *testing.T) {
	dir := t.TempDir()
	shim := writeShim(t, dir, "pp.sh", "")

	u, _ := New(execCfg(shim))
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty stdout, got nil")
	}
}

func TestExecUnlocker_NonzeroExitIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fail.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	u, _ := New(execCfg(path))
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for nonzero exit, got nil")
	}
}

func TestExecUnlocker_EmptyArgvIsError(t *testing.T) {
	u, err := New(execCfg())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty argv, got nil")
	}
}

// execCfg builds a UnlockConfig with method=exec and the given argv.
func execCfg(argv ...string) config.UnlockConfig {
	return config.UnlockConfig{Method: "exec", Exec: argv}
}
