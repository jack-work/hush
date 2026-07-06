package unlock

import (
	"context"
	"encoding/base64"
	"os"
	"strconv"
	"testing"

	"github.com/jack-work/hush/config"
)

// The exec backend runs a user-supplied command. To test it without a
// POSIX shell (Windows has none), the "command" is this very test binary
// re-invoked to run TestExecHelperProcess, which emits an exact,
// base64-encoded byte string on stdout and exits with a chosen code.
// This is the standard os/exec testing pattern and is fully portable.

// helperArgv builds an argv that re-execs the test binary as the exec
// helper. The payload (base64 output, exit code) rides after "--" so the
// testing flag parser leaves it alone.
func helperArgv(out string, exit int) []string {
	return []string{
		os.Args[0], "-test.run=TestExecHelperProcess", "--",
		base64.StdEncoding.EncodeToString([]byte(out)), strconv.Itoa(exit),
	}
}

func execCfg(argv ...string) config.UnlockConfig {
	return config.UnlockConfig{Method: "exec", Exec: argv}
}

// TestExecHelperProcess is not a real test: it is the child process the
// exec-unlocker tests invoke. It no-ops unless it sees the payload after
// "--", so it is inert during a normal suite run.
func TestExecHelperProcess(t *testing.T) {
	payload := argsAfterDoubleDash()
	if len(payload) < 2 {
		return
	}
	out, err := base64.StdEncoding.DecodeString(payload[0])
	if err != nil {
		os.Exit(2)
	}
	os.Stdout.Write(out)
	code, _ := strconv.Atoi(payload[1])
	os.Exit(code)
}

func argsAfterDoubleDash() []string {
	for i, a := range os.Args {
		if a == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

func TestExecUnlocker_StripsSingleTrailingLF(t *testing.T) {
	u, err := New(execCfg(helperArgv("hunter2\n", 0)...))
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
	u, _ := New(execCfg(helperArgv("hunter2\r\n", 0)...))
	pp, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != "hunter2" {
		t.Fatalf("got %q, want %q", pp, "hunter2")
	}
}

func TestExecUnlocker_PreservesInternalAndLeadingWhitespace(t *testing.T) {
	u, _ := New(execCfg(helperArgv(" tab\there\n", 0)...))
	pp, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != " tab\there" {
		t.Fatalf("got %q, want %q", pp, " tab\there")
	}
}

func TestExecUnlocker_EmptyOutputIsError(t *testing.T) {
	u, _ := New(execCfg(helperArgv("", 0)...))
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty stdout, got nil")
	}
}

func TestExecUnlocker_NonzeroExitIsError(t *testing.T) {
	u, _ := New(execCfg(helperArgv("whatever", 7)...))
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
