// spawn.go provides exported helpers for spawning and managing the hush agent
// from library code. These are the building blocks that allow an external
// application to embed hush agent management without requiring the hush CLI.

package agent

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jack-work/hush/identity"
)

// SpawnEnvVar is the environment variable set on re-exec'd child processes
// to signal they should enter agent mode. Exported so consuming applications
// can check it in their own main().
const SpawnEnvVar = "HUSH_AGENT_CHILD"

// SpawnDaemon re-execs the given executable as a detached child process,
// passing the decrypted identity over a pipe (fd 3). The identity's raw
// bytes are zeroed after writing.
//
// exe is the path to the binary to re-exec (typically os.Executable()).
// args are passed to the child process (e.g. your app's agent subcommand).
// env is appended to os.Environ() for the child.
//
// After return, the caller should use WaitForAgent to confirm the daemon
// is responsive.
func SpawnDaemon(exe string, args []string, env []string, id *identity.DecryptedIdentity) (pid int, err error) {
	defer id.Zero()

	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("create pipe: %w", err)
	}

	child := exec.Command(exe, args...)
	child.Env = append(os.Environ(), env...)
	child.Env = append(child.Env, SpawnEnvVar+"=1")
	// Pass the pipe read end as ExtraFiles[0] → fd 3 in the child.
	child.ExtraFiles = []*os.File{pr}
	// Detach from terminal.
	child.Stdin = nil
	child.Stdout = nil
	child.Stderr = nil

	if err := child.Start(); err != nil {
		pw.Close()
		pr.Close()
		return 0, fmt.Errorf("start daemon: %w", err)
	}

	pr.Close() // parent doesn't read
	if _, err := id.WriteTo(pw); err != nil {
		pw.Close()
		return 0, fmt.Errorf("write identity to pipe: %w", err)
	}
	pw.Close()

	return child.Process.Pid, nil
}

// RunChildFromPipe is the entry point for a re-exec'd daemon child.
// It reads the identity from fd 3 (passed via ExtraFiles by SpawnDaemon),
// creates an agent, and blocks until the agent exits.
//
// This is intended to be called from the consuming application's main()
// when it detects SpawnEnvVar is set.
func RunChildFromPipe(ttl time.Duration, runtimeDir string, logger *log.Logger) error {
	pipe := os.NewFile(3, "identity-pipe")
	if pipe == nil {
		return fmt.Errorf("identity pipe (fd 3) not available")
	}

	raw, err := io.ReadAll(pipe)
	pipe.Close()
	if err != nil {
		return fmt.Errorf("read identity from pipe: %w", err)
	}

	id, err := identity.ParseRaw(raw)
	if err != nil {
		return fmt.Errorf("parse identity from pipe: %w", err)
	}

	ag := New(id, ttl, runtimeDir, logger)
	return ag.Run()
}

// WaitForAgent polls the agent socket until it responds or timeout is reached.
func WaitForAgent(runtimeDir string, timeout time.Duration) error {
	sockPath := filepath.Join(runtimeDir, "agent.sock")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ping(sockPath); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for agent at %s", sockPath)
}

// IsAgentRunning checks whether an agent is responsive at the given
// runtime directory's socket.
func IsAgentRunning(runtimeDir string) bool {
	sockPath := filepath.Join(runtimeDir, "agent.sock")
	return ping(sockPath) == nil
}

func ping(sockPath string) error {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}
