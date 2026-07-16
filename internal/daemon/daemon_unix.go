//go:build !windows

package daemon

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// Spawn re-execs exe+args as a detached background agent. extraEnv is
// appended to the child's environment; ChildEnvVar is set automatically.
// The identity is written to the child over an inherited pipe (fd 3) and
// zeroed by WriteTo. Returns the child pid.
func Spawn(exe string, args, extraEnv []string, id io.WriterTo) (int, error) {
	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("create pipe: %w", err)
	}

	child := exec.Command(exe, args...)
	child.Env = append(os.Environ(), extraEnv...)
	child.Env = append(child.Env, ChildEnvVar+"=1")
	child.ExtraFiles = []*os.File{pr}
	child.Stdin = nil
	child.Stdout = nil
	child.Stderr = nil

	if err := child.Start(); err != nil {
		pw.Close()
		pr.Close()
		return 0, fmt.Errorf("start daemon: %w", err)
	}

	pr.Close() // parent does not read
	if _, err := id.WriteTo(pw); err != nil {
		pw.Close()
		return 0, fmt.Errorf("hand off identity: %w", err)
	}
	pw.Close()

	return child.Process.Pid, nil
}

// CleanAgentLogs is a no-op on Unix. On Windows, it removes stale
// per-launch agent log files to prevent temp-dir bloat.
func CleanAgentLogs(_ time.Duration) {}

// ReadIdentity is the child side of the handoff: it reads the raw
// identity bytes the parent wrote to fd 3. Call once, early, in the
// re-exec'd child.
func ReadIdentity() ([]byte, error) {
	pipe := os.NewFile(3, "identity-pipe")
	if pipe == nil {
		return nil, fmt.Errorf("identity pipe (fd 3) not available")
	}
	defer pipe.Close()

	raw, err := io.ReadAll(pipe)
	if err != nil {
		return nil, fmt.Errorf("read identity from pipe: %w", err)
	}
	return raw, nil
}
