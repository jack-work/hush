package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/internal/agent"
	"github.com/jack-work/hush/internal/daemon"
	"github.com/jack-work/hush/internal/identity"
	"github.com/jack-work/hush/internal/singleton"
	"github.com/jack-work/hush/internal/unlock"
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

	ag := agent.New(id, ttl, cfg.RuntimeDir, cfg.StateDir, logger)
	return ag.Run()
}

func promptAndUnlock(identityFile string) (*identity.DecryptedIdentity, error) {
	// Build the resolver from the active config. Method defaults to
	// "passphrase" (TTY prompt) when nothing is set in hush.toml, so
	// behavior is identical to before this seam existed. Verify keeps
	// caching backends from trusting or persisting a passphrase that
	// doesn't decrypt the identity.
	u, err := unlock.New(cfg.Unlock, unlock.Hooks{
		Verify: func(pp []byte) error {
			id, err := identity.Unlock(identityFile, pp)
			if err == nil {
				id.Zero()
			}
			return err
		},
	})
	if err != nil {
		return nil, err
	}
	passphrase, err := u.Passphrase(context.Background())
	if err != nil {
		return nil, err
	}
	id, err := identity.Unlock(identityFile, passphrase)
	// Wipe the slice the moment the identity is decrypted, regardless
	// of where it came from.
	for i := range passphrase {
		passphrase[i] = 0
	}
	if err != nil {
		switch cfg.Unlock.Method {
		case "", "auto", "keyring":
			// A wrong passphrase cached in the keyring would fail silently
			// on every startup. Point the user at the recovery path.
			return nil, fmt.Errorf("%w\n\nif the passphrase saved in your OS keyring is wrong, clear it and retry:\n  hush keyring clear", err)
		}
	}
	return id, err
}

// spawnDaemon re-execs the binary as a detached child, handing the
// decrypted identity to it out-of-band (fd 3 on Unix, an AF_UNIX handoff
// socket on Windows). The identity's raw bytes are zeroed after transfer.
func spawnDaemon(id *identity.DecryptedIdentity, ttl time.Duration) error {
	defer id.Zero()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	childArgs := []string{"up"}
	if flagTTL != "" {
		childArgs = append(childArgs, "--ttl", flagTTL)
	}

	if _, err := daemon.Spawn(exe, childArgs, nil, id); err != nil {
		return err
	}

	// Wait for child to start listening.
	if err := waitForAgent(cfg.RuntimeDir, 10*time.Second); err != nil {
		return fmt.Errorf("daemon started but not responding: %w", err)
	}

	pid, _ := singleton.Holder(filepath.Join(cfg.RuntimeDir, "agent.pid"))
	fmt.Fprintf(os.Stderr, "agent started in background (pid %d, ttl %s)\n", pid, ttl)
	daemon.CleanAgentLogs(time.Hour)
	return nil
}

// runChild is the entry point for the re-exec'd daemon child.
// It receives the identity from the parent via the platform handoff.
func runChild(ttl time.Duration) error {
	raw, err := daemon.ReadIdentity()
	if err != nil {
		return err
	}

	id, err := identity.ParseRaw(raw)
	if err != nil {
		return fmt.Errorf("parse identity from handoff: %w", err)
	}

	logger, logFile, err := newLogger(cfg.StateDir)
	if err != nil {
		return err
	}
	defer logFile.Close()

	ag := agent.New(id, ttl, cfg.RuntimeDir, cfg.StateDir, logger)
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
	return client.NewWithSocket(sockPath).Ping()
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
