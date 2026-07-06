package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/identity"
	"github.com/jack-work/hush/internal/daemon"
	"github.com/jack-work/hush/internal/singleton"
)

func runCmd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	name := args[0]
	extra := args[1:]

	cmdDir := filepath.Join(cfg.CommandsDir, name)
	if _, err := os.Stat(cmdDir); err != nil {
		return fmt.Errorf("command %q not found (looked in %s)", name, cmdDir)
	}

	// Read command.sh.
	cmdFile := filepath.Join(cmdDir, "command.sh")
	cmdBytes, err := os.ReadFile(cmdFile)
	if err != nil {
		// Check if this is a config-only command (has secrets.toml but no command.sh).
		secretsFile := filepath.Join(cmdDir, "secrets.toml")
		if _, secErr := os.Stat(secretsFile); secErr == nil {
			return fmt.Errorf("hey — %q is config-only, pal. no command.sh in there.\n\n"+
				"this one's meant to be read by another program through the hush client library.\n"+
				"it holds secrets, sure, but it don't run nothin'. that's someone else's job.\n\n"+
				"if you meant to make it runnable, drop a command.sh in:\n  %s", name, cmdDir)
		}
		return fmt.Errorf("command %q missing command.sh (expected at %s)", name, cmdFile)
	}

	// Decrypt secrets if secrets.toml exists.
	values := make(map[string]string)
	secretsFile := filepath.Join(cmdDir, "secrets.toml")
	if _, err := os.Stat(secretsFile); err == nil {
		var decErr error
		values, decErr = decryptViaAgent(secretsFile)
		if decErr != nil {
			return decErr
		}
	}

	// Build template context: secrets at top level + Args + Cmd.
	ctx := make(map[string]interface{}, len(values)+2)
	for k, v := range values {
		ctx[k] = v
	}
	ctx["Args"] = extra
	ctx["Cmd"] = name

	// Render template.
	tmpl, err := template.New("command.sh").Parse(string(cmdBytes))
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, ctx); err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	// Execute via sh -c.
	sh := exec.Command("sh", "-c", rendered.String())
	sh.Stdin = os.Stdin
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr

	if err := sh.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

// decryptViaAgent reads the secrets TOML file and sends it to the agent for
// decryption. If no agent is running, it starts one implicitly.
func decryptViaAgent(secretsFile string) (map[string]string, error) {
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		return nil, fmt.Errorf("read secrets: %w", err)
	}

	var rawValues map[string]string
	if err := toml.Unmarshal(data, &rawValues); err != nil {
		return nil, fmt.Errorf("parse secrets toml: %w", err)
	}

	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")

	// Ensure agent is running.
	if err := ensureAgent(sockPath); err != nil {
		return nil, err
	}

	c := client.NewWithSocket(sockPath)
	return c.Decrypt(rawValues)
}

// ensureAgent checks if an agent is running and, if not, starts one
// implicitly. With unlock.method = auto or keyring and a seeded OS
// keyring, this is silent and needs no terminal: the "just works"
// autostart path. Only the passphrase (TTY) backend needs an interactive
// terminal; when it needs one and none exists, the unlock returns a clear
// error, which we augment with recovery guidance.
func ensureAgent(sockPath string) error {
	if err := pingAgent(sockPath); err == nil {
		return nil // agent is alive
	}

	// No agent — clean up stale socket if present.
	os.Remove(sockPath)

	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	if interactive {
		fmt.Fprintln(os.Stderr, "No running agent. Starting one...")
	}

	id, err := promptAndUnlock(cfg.IdentityFile)
	if err != nil {
		if !interactive {
			return fmt.Errorf("hush agent is not running and could not start it non-interactively: %w\n\n"+
				"Seed the passphrase into your OS keyring so autostart is silent:\n\n  hush keyring set\n\n"+
				"or start the agent manually from an interactive shell:\n\n  hush up -d", err)
		}
		return err
	}

	ttl := cfg.TTL
	if err := spawnDaemonWithID(id, ttl); err != nil {
		return err
	}

	return nil
}

// spawnDaemonWithID is the same as spawnDaemon but takes an explicit TTL
// and doesn't rely on flag state.
func spawnDaemonWithID(id *identity.DecryptedIdentity, ttl time.Duration) error {
	defer id.Zero()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	if _, err := daemon.Spawn(exe, []string{"up", "--ttl", ttl.String()}, nil, id); err != nil {
		return err
	}

	if err := waitForAgent(cfg.RuntimeDir, 10*time.Second); err != nil {
		return fmt.Errorf("agent started but not responding: %w", err)
	}

	pid, _ := singleton.Holder(filepath.Join(cfg.RuntimeDir, "agent.pid"))
	fmt.Fprintf(os.Stderr, "Agent started (pid %d, ttl %s)\n", pid, ttl)
	return nil
}
