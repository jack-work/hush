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
	// Capture this before anything can consume the claim: the agent
	// clears LISTEN_PID once it adopts the descriptor, so asking later
	// gives the wrong answer.
	activated := agent.SocketActivated()
	started := time.Now()

	err := runUpBody(cmd, args, activated)

	// An activated start that fails must not fail INSTANTLY. systemd
	// re-triggers on the connection still pending in the socket's
	// backlog, so a process that dies in microseconds becomes an
	// activation storm, and a storm trips one of two rate limits —
	// TriggerLimitBurst on the socket, StartLimitBurst on the service.
	// Either one stops the socket unit, and on-demand starting is then
	// dead until a human re-arms it by hand. Silence, from a fault that
	// would have cleared on its own.
	//
	// A floor on how fast we may fail caps the activation rate at well
	// under one per second, whatever the cause — a held lock, a locked
	// keyring, a bad passphrase. The client waiting on the other end has
	// its own deadline and is unaffected by a pause we take on the way
	// out.
	if err != nil && activated {
		if remaining := activationFailureFloor - time.Since(started); remaining > 0 {
			time.Sleep(remaining)
		}
	}
	return err
}

// activationFailureFloor is the minimum lifetime of a failing activated
// agent. See runUp.
const activationFailureFloor = 2 * time.Second

// lockWaitOnActivation is how long an activated agent waits for a
// predecessor to release the single-instance lock before giving up. See
// runUpBody.
const lockWaitOnActivation = 60 * time.Second

func runUpBody(cmd *cobra.Command, args []string, activated bool) error {
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

	// Nothing to start if the socket is already listening — and on a box
	// with the socket unit installed it always is, whether or not an
	// agent is behind it. Touching it is what starts one, so a ping is
	// both the question and the answer. Checking here, before the
	// unlock, means no passphrase prompt for an agent that already
	// exists, and no spawned child that can only lose the race for the
	// lock and die where nobody reads its stderr.
	//
	// Except when we are the activated agent. Then the socket is
	// listening because systemd is holding it for *us*, the ping would
	// be answered by nobody but ourselves, and asking would deadlock
	// until the client's deadline. Whoever was waiting in the backlog
	// gets a timeout and the familiar "agent is not running" — the exact
	// failure this release exists to end.
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
	if !agent.SocketActivated() && agent.SocketIsListening(sockPath) {
		if err := waitForAgent(cfg.RuntimeDir, 10*time.Second); err == nil {
			pid, _ := singleton.Holder(filepath.Join(cfg.RuntimeDir, "agent.pid"))
			fmt.Fprintf(os.Stderr, "agent already reachable at %s (pid %d) — nothing to start\n", sockPath, pid)
			return nil
		}
	}

	// Another agent may already hold the single-instance lock. Run()
	// would discover that too, but only after promptAndUnlock has run
	// scrypt over the identity — ~840ms and a ~520MB peak to learn
	// something knowable in microseconds.
	//
	// What to do about it depends on who asked.
	//
	// Activated: a client is queued in our socket's backlog and systemd
	// has made us responsible for it. Wait. A predecessor holding the
	// lock is almost always one whose TTL is about to lapse, and while
	// we wait the service counts as running, so systemd does not
	// re-trigger — the activation rate stays at one per client instead
	// of hundreds per second. If it frees in time we go on to serve the
	// very connection that started us.
	//
	// Interactive: answer now. Nobody typing `hush up` wants a minute of
	// silence, and the message names the holder.
	pidPath := filepath.Join(cfg.RuntimeDir, "agent.pid")
	if activated {
		if err := waitForLockFree(pidPath, lockWaitOnActivation); err != nil {
			return err
		}
	} else if free, ferr := singleton.Free(pidPath); ferr == nil && !free {
		return fmt.Errorf("another agent is already running (%s holds %s)",
			lockHolder(pidPath), pidPath)
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

// waitForLockFree blocks until no agent holds the single-instance lock,
// or the timeout expires. Used only on the activated path, where holding
// systemd's service slot is precisely what keeps activation from being
// re-triggered into a storm.
func waitForLockFree(pidPath string, timeout time.Duration) error {
	if free, err := singleton.Free(pidPath); err != nil || free {
		return nil
	}

	// Say so once, on stderr, which journald captures for the unit. A
	// silent minute is indistinguishable from a hang.
	fmt.Fprintf(os.Stderr,
		"another agent (%s) still holds %s; waiting up to %s for it to exit\n",
		lockHolder(pidPath), pidPath, timeout)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		if free, err := singleton.Free(pidPath); err != nil || free {
			fmt.Fprintln(os.Stderr, "predecessor exited; taking over")
			return nil
		}
	}
	return fmt.Errorf(
		"another agent (%s) has held %s for %s; it is not socket-activated, "+
			"so this one cannot take over. Stop it and let the socket unit start the next: hush down",
		lockHolder(pidPath), pidPath, timeout)
}

func lockHolder(pidPath string) string {
	if h, err := singleton.Holder(pidPath); err == nil {
		return fmt.Sprintf("pid %d", h)
	}
	return "unknown pid"
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
