package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(downCmd)
}

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop the running hush agent",
	RunE:  runDown,
}

// runDown decides liveness by probing the agent's single-instance flock
// rather than pid heuristics: a shared lock can be taken iff no agent
// holds the exclusive one. The PID file is never removed — it is the
// lock inode (see agent.acquireLock).
func runDown(cmd *cobra.Command, args []string) error {
	pidPath := filepath.Join(cfg.RuntimeDir, "agent.pid")
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")

	f, err := os.Open(pidPath)
	if err != nil {
		return fmt.Errorf("no agent running (no lock file at %s)", pidPath)
	}
	defer f.Close()

	if lockFree(f) {
		os.Remove(sockPath) // stale leftover, e.g. a SIGKILL'd agent
		return fmt.Errorf("no agent running (lock at %s is free)", pidPath)
	}

	data, _ := io.ReadAll(f)
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("agent holds the lock but pid file is unreadable: %q", strings.TrimSpace(string(data)))
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find agent process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to signal agent (pid %d): %w", pid, err)
	}

	// The agent releases the lock as the last step of its shutdown.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if lockFree(f) {
			fmt.Fprintf(os.Stderr, "agent (pid %d) stopped\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("agent (pid %d) did not stop within 5s", pid)
}

// lockFree reports whether the agent's exclusive flock is currently free.
// It momentarily takes (and releases) a shared lock to find out.
func lockFree(f *os.File) bool {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return false
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return true
}
