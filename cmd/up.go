package cmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/agent"
	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/identity"
)

const agentChildEnv = "HUSH_AGENT_CHILD"

var (
	flagDaemon bool
	flagTTL    string
)

func init() {
	upCmd.Flags().BoolVarP(&flagDaemon, "daemon", "d", false, "run agent in background")
	upCmd.Flags().StringVar(&flagTTL, "ttl", "", "override TTL (e.g. 1h, 15m)")
	rootCmd.AddCommand(upCmd)
}

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "Start the hush agent",
	RunE:  runUp,
}

func runUp(cmd *cobra.Command, args []string) error {
	ttl := cfg.TTL
	if flagTTL != "" {
		d, err := time.ParseDuration(flagTTL)
		if err != nil {
			return fmt.Errorf("parse --ttl: %w", err)
		}
		ttl = d
	}

	// If we're the re-exec'd child, read identity from pipe and run.
	if os.Getenv(agentChildEnv) == "1" {
		return runChild(ttl)
	}

	// Prompt for passphrase and decrypt identity.
	id, err := promptAndUnlock(cfg.IdentityFile)
	if err != nil {
		return err
	}

	if flagDaemon {
		return spawnDaemon(id, ttl)
	}

	// Foreground mode: set up logging and run.
	logger, logFile, err := newLogger(cfg.StateDir)
	if err != nil {
		return err
	}
	defer logFile.Close()

	ag := agent.New(id, ttl, cfg.RuntimeDir, logger)
	return ag.Run()
}

func promptAndUnlock(identityFile string) (*identity.DecryptedIdentity, error) {
	fmt.Fprint(os.Stderr, "Enter passphrase for hush identity: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return identity.Unlock(identityFile, passphrase)
}

// spawnDaemon re-execs the binary as a detached child, passing the decrypted
// identity over a pipe. The identity's raw bytes are zeroed after writing.
func spawnDaemon(id *identity.DecryptedIdentity, ttl time.Duration) error {
	defer id.Zero()

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	childArgs := []string{"up"}
	if flagTTL != "" {
		childArgs = append(childArgs, "--ttl", flagTTL)
	}

	child := exec.Command(exe, childArgs...)
	child.Env = append(os.Environ(), agentChildEnv+"=1")
	// Pass the pipe read end as ExtraFiles[0] → fd 3 in the child.
	child.ExtraFiles = []*os.File{pr}
	// Detach from terminal.
	child.Stdin = nil
	child.Stdout = nil
	child.Stderr = nil

	if err := child.Start(); err != nil {
		pw.Close()
		pr.Close()
		return fmt.Errorf("start daemon: %w", err)
	}

	// Write raw identity bytes to pipe (zeros them), then close.
	pr.Close() // parent doesn't read
	if _, err := id.WriteTo(pw); err != nil {
		pw.Close()
		return fmt.Errorf("write identity to pipe: %w", err)
	}
	pw.Close()

	// Wait for child to start listening.
	if err := waitForAgent(cfg.RuntimeDir, 3*time.Second); err != nil {
		return fmt.Errorf("daemon started but not responding: %w", err)
	}

	fmt.Fprintf(os.Stderr, "agent started in background (pid %d, ttl %s)\n", child.Process.Pid, ttl)
	return nil
}

// runChild is the entry point for the re-exec'd daemon child.
// It reads the identity from fd 3 (passed via ExtraFiles).
func runChild(ttl time.Duration) error {
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

	logger, logFile, err := newLogger(cfg.StateDir)
	if err != nil {
		return err
	}
	defer logFile.Close()

	ag := agent.New(id, ttl, cfg.RuntimeDir, logger)
	return ag.Run()
}

// waitForAgent polls the agent socket until it responds or timeout is reached.
func waitForAgent(runtimeDir string, timeout time.Duration) error {
	sockPath := filepath.Join(runtimeDir, "agent.sock")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := pingAgent(sockPath); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for agent at %s", sockPath)
}

func pingAgent(sockPath string) error {
	return client.Ping(sockPath)
}

func newLogger(stateDir string) (*log.Logger, *os.File, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create state dir: %w", err)
	}

	logFile, err := os.OpenFile(
		filepath.Join(stateDir, "hush.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file: %w", err)
	}

	// In daemon mode, stdout is detached, so log file is the only output.
	// In foreground mode, write to both.
	var w io.Writer
	if os.Getenv(agentChildEnv) == "1" {
		w = logFile
	} else {
		w = io.MultiWriter(os.Stdout, logFile)
	}

	return log.New(w, "hush: ", log.LstdFlags), logFile, nil
}
