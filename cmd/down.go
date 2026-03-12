package cmd

import (
	"fmt"
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

func runDown(cmd *cobra.Command, args []string) error {
	pidPath := filepath.Join(cfg.RuntimeDir, "agent.pid")
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")

	data, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Errorf("no agent running (no pid file at %s)", pidPath)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		os.Remove(pidPath)
		return fmt.Errorf("corrupt pid file, removed")
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidPath)
		return fmt.Errorf("process %d not found, cleaned up pid file", pid)
	}

	// Check if alive.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		os.Remove(pidPath)
		os.Remove(sockPath)
		return fmt.Errorf("agent (pid %d) not running, cleaned up stale files", pid)
	}

	// Send SIGTERM.
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to signal agent (pid %d): %w", pid, err)
	}

	// Wait for cleanup.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "agent (pid %d) stopped\n", pid)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("agent (pid %d) did not stop within 5s", pid)
}
