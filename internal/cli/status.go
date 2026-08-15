package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/config"
	"github.com/jack-work/hush/internal/version"
)

var flagCheck bool

func init() {
	statusCmd.Flags().BoolVar(&flagCheck, "check", false, "exit 0 if agent is running, 1 if not (no output)")
	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show hush agent and configuration status",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
	c := client.NewWithSocket(sockPath)

	// --check mode: silent exit code only.
	if flagCheck {
		if c.Ping() == nil {
			return nil
		}
		os.Exit(1)
		return nil // unreachable
	}

	fmt.Printf("Version: %s\n\n", version.Version)
	fmt.Println("Config:")
	fmt.Printf("  config dir:   %s\n", cfg.ConfigDir)
	fmt.Printf("  commands dir: %s\n", cfg.CommandsDir)
	fmt.Printf("  identity:     %s\n", cfg.IdentityFile)
	fmt.Printf("  runtime dir:  %s\n", cfg.RuntimeDir)
	fmt.Printf("  state dir:    %s\n", cfg.StateDir)
	fmt.Printf("  default ttl:  %s\n", cfg.TTL)
	fmt.Printf("  unlock:       %s\n", describeUnlock(cfg.Unlock))

	// Identity.
	if _, err := os.Stat(cfg.IdentityFile); err == nil {
		fmt.Println("\nIdentity: ✓ present")
	} else {
		fmt.Println("\nIdentity: ✗ not found (run 'hush init')")
	}
	if pubData, err := os.ReadFile(cfg.IdentityFile + ".pub"); err == nil {
		fmt.Printf("  public key: %s\n", strings.TrimSpace(string(pubData)))
	}

	// Commands.
	commands := listCommands()
	fmt.Printf("\nCommands: %d\n", len(commands))
	for _, c := range commands {
		detail := "has secrets"
		switch {
		case !c.runnable():
			detail = "empty — no script, no secrets"
		case c.hasScript && !c.hasSecrets:
			detail = "no secrets"
		case c.hasSecrets && !c.hasScript:
			detail = "config-only"
		}
		fmt.Printf("  %s (%s)\n", c.name, detail)
	}

	// Agent.
	fmt.Println()
	ttl, err := c.Status()
	if err == nil {
		pidData, _ := os.ReadFile(filepath.Join(cfg.RuntimeDir, "agent.pid"))
		agentVer := "unknown"
		if v, verr := c.Version(); verr == nil {
			agentVer = v
		}
		fmt.Printf("Agent: ✓ running (pid %s, version %s, ttl remaining %s)\n",
			strings.TrimSpace(string(pidData)), agentVer, ttl)
	} else {
		fmt.Println("Agent: ✗ not running")
	}

	return nil
}

// commandEntry is one directory under commands/, and what it actually
// holds. A directory alone means nothing: `hush <name>` needs a script,
// and a library consumer needs secrets.toml. A directory with neither is
// leftover litter, and used to be counted and advertised as a command
// that would then fail to run.
type commandEntry struct {
	name       string
	hasScript  bool
	hasSecrets bool
}

// runnable reports whether the entry is worth telling a user about.
func (e commandEntry) runnable() bool { return e.hasScript || e.hasSecrets }

func listCommands() []commandEntry {
	entries, err := os.ReadDir(cfg.CommandsDir)
	if err != nil {
		return nil
	}
	var out []commandEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(cfg.CommandsDir, e.Name())
		c := commandEntry{name: e.Name()}
		// Ask the platform which script names count, rather than
		// assuming command.sh — on Windows that is command.ps1 or
		// command.cmd, and hard-coding .sh reported those as scriptless.
		for _, n := range commandScriptNames() {
			if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
				c.hasScript = true
				break
			}
		}
		if _, err := os.Stat(filepath.Join(dir, "secrets.toml")); err == nil {
			c.hasSecrets = true
		}
		out = append(out, c)
	}
	return out
}

// describeUnlock renders the active unlock method as a one-liner for
// the status output. We deliberately avoid printing anything that could
// double as a secret — keyring service/account are fine (they're
// identifiers, not values); exec argv is fine (it's argv, not stdout).
func describeUnlock(u config.UnlockConfig) string {
	method := u.Method
	if method == "" {
		method = "passphrase"
	}
	switch method {
	case "passphrase":
		return "passphrase (TTY prompt)"
	case "keyring":
		return fmt.Sprintf("keyring (service=%q account=%q)",
			u.Keyring.Service, u.Keyring.Account)
	case "exec":
		if len(u.Exec) == 0 {
			return "exec (argv not set — misconfigured)"
		}
		return fmt.Sprintf("exec %v", u.Exec)
	default:
		return fmt.Sprintf("%s (unknown method)", method)
	}
}
