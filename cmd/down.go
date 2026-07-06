package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/internal/singleton"
)

func init() {
	rootCmd.AddCommand(downCmd)
}

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop the running hush agent",
	RunE:  runDown,
}

// runDown decides liveness by probing the agent's single-instance lock
// rather than pid heuristics: the shared lock can be taken iff no agent
// holds the exclusive one. The PID file is never removed (it is the lock
// inode; see agent.acquireLock).
//
// Shutdown is a socket RPC, not a signal: Windows cannot SIGTERM a
// detached daemon, and the RPC path works identically on every OS. If
// the agent holds the lock but will not answer, we force-terminate the
// pid as a last resort.
func runDown(cmd *cobra.Command, args []string) error {
	pidPath := filepath.Join(cfg.RuntimeDir, "agent.pid")
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")

	if free, _ := singleton.Free(pidPath); free {
		os.Remove(sockPath) // stale leftover, e.g. a hard-killed agent
		return fmt.Errorf("no agent running (lock at %s is free)", pidPath)
	}

	pid, perr := singleton.Holder(pidPath)

	if err := client.NewWithSocket(sockPath).Shutdown(); err != nil {
		// The agent holds the lock but did not answer the RPC. Force it.
		if perr == nil && pid > 0 {
			if proc, e := os.FindProcess(pid); e == nil {
				proc.Kill()
			}
		}
	}

	// The agent releases the lock as the last step of its shutdown.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if free, _ := singleton.Free(pidPath); free {
			fmt.Fprintf(os.Stderr, "agent (pid %d) stopped\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("agent (pid %d) did not stop within 5s", pid)
}
