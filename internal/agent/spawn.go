// spawn.go provides exported helpers for spawning and managing the hush agent
// from library code. These are the building blocks that allow an external
// application to embed hush agent management without requiring the hush CLI.

package agent

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	"github.com/jack-work/hush/internal/daemon"
	"github.com/jack-work/hush/internal/identity"
)

// SpawnEnvVar is the environment variable set on re-exec'd child processes
// to signal they should enter agent mode. Exported so consuming applications
// can check it in their own main().
const SpawnEnvVar = daemon.ChildEnvVar

// SpawnDaemon re-execs the given executable as a detached child process,
// handing the decrypted identity to it out-of-band (never through disk).
// The identity's raw bytes are zeroed after transfer.
//
// exe is the path to the binary to re-exec (typically os.Executable()).
// args are passed to the child process (e.g. your app's agent subcommand).
// env are extra KEY=VALUE vars for the child; the platform layer sets
// SpawnEnvVar itself.
//
// After return, the caller should use WaitForAgent to confirm the daemon
// is responsive.
func SpawnDaemon(exe string, args []string, env []string, id *identity.DecryptedIdentity) (pid int, err error) {
	defer id.Zero()
	return daemon.Spawn(exe, args, env, id)
}

// RunChildFromPipe is the entry point for a re-exec'd daemon child.
// It receives the identity from the parent (fd 3 on Unix, an AF_UNIX
// handoff socket on Windows), creates an agent, and blocks until it
// exits.
//
// This is intended to be called from the consuming application's main()
// when it detects SpawnEnvVar is set.
func RunChildFromPipe(ttl time.Duration, runtimeDir, stateDir string, logger *log.Logger) error {
	raw, err := daemon.ReadIdentity()
	if err != nil {
		return err
	}

	id, err := identity.ParseRaw(raw)
	if err != nil {
		return fmt.Errorf("parse identity from handoff: %w", err)
	}

	ag := New(id, ttl, runtimeDir, stateDir, logger)
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

func ping(sockPath string) error {
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

// SocketIsListening reports whether some process is listening on the
// AF_UNIX path, answered passively (no connect). Callers that clean up
// stale socket nodes need it: under socket activation the node belongs
// to the service manager even when no agent is running, and dialing it
// to find out would start the very agent they just stopped.
//
// Always false off Linux, where the question cannot be asked passively.
func SocketIsListening(path string) bool { return socketIsListening(path) }
