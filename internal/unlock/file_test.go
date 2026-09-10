package unlock

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jack-work/hush/config"
)

func fileCfg(path string) config.UnlockConfig {
	return config.UnlockConfig{Method: "file", File: path}
}

// writePassphraseFile drops content at <tmp>/passphrase with the given
// mode and returns the path. Mode is applied with Chmod rather than
// left to WriteFile so the umask cannot quietly tighten a deliberately
// loose fixture.
func writePassphraseFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func readPassphrase(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	u, err := New(fileCfg(path), Hooks{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u.Passphrase(context.Background())
}

func TestFileUnlocker_StripsSingleTrailingLF(t *testing.T) {
	pp, err := readPassphrase(t, writePassphraseFile(t, "hunter2\n", 0o600))
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != "hunter2" {
		t.Fatalf("got %q, want %q", pp, "hunter2")
	}
}

func TestFileUnlocker_StripsSingleTrailingCRLF(t *testing.T) {
	pp, err := readPassphrase(t, writePassphraseFile(t, "hunter2\r\n", 0o600))
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != "hunter2" {
		t.Fatalf("got %q, want %q", pp, "hunter2")
	}
}

func TestFileUnlocker_StripsOnlyOneNewline(t *testing.T) {
	pp, err := readPassphrase(t, writePassphraseFile(t, "hunter2\n\n", 0o600))
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != "hunter2\n" {
		t.Fatalf("got %q, want %q", pp, "hunter2\n")
	}
}

func TestFileUnlocker_PreservesInternalAndLeadingWhitespace(t *testing.T) {
	pp, err := readPassphrase(t, writePassphraseFile(t, " tab\there\n", 0o600))
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(pp) != " tab\there" {
		t.Fatalf("got %q, want %q", pp, " tab\there")
	}
}

func TestFileUnlocker_ReadOnlyModeIsFine(t *testing.T) {
	if _, err := readPassphrase(t, writePassphraseFile(t, "hunter2\n", 0o400)); err != nil {
		t.Fatalf("0400 should be acceptable: %v", err)
	}
}

func TestFileUnlocker_GroupReadableIsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX mode bits on Windows")
	}
	path := writePassphraseFile(t, "hunter2\n", 0o640)
	_, err := readPassphrase(t, path)
	if err == nil {
		t.Fatal("expected an error for a group-readable file, got nil")
	}
	// The message has one job: tell the user which file, and what is
	// wrong with it. A test that only checks err != nil would pass on
	// "invalid argument".
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "640") {
		t.Fatalf("error should name the path and the mode, got: %v", err)
	}
}

func TestFileUnlocker_WorldReadableIsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX mode bits on Windows")
	}
	if _, err := readPassphrase(t, writePassphraseFile(t, "hunter2\n", 0o644)); err == nil {
		t.Fatal("expected an error for a world-readable file, got nil")
	}
}

func TestFileUnlocker_MissingFileIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope")
	_, err := readPassphrase(t, path)
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should name the path, got: %v", err)
	}
}

func TestFileUnlocker_EmptyFileIsError(t *testing.T) {
	if _, err := readPassphrase(t, writePassphraseFile(t, "\n", 0o600)); err == nil {
		t.Fatal("expected an error for an empty passphrase, got nil")
	}
}

func TestFileUnlocker_DirectoryIsError(t *testing.T) {
	if _, err := readPassphrase(t, t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory, got nil")
	}
}

func TestFileUnlocker_EmptyPathIsError(t *testing.T) {
	u, err := New(fileCfg(""), Hooks{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected an error for an unset path, got nil")
	}
}
