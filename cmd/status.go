package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/version"
)

func init() {
	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show hush agent and configuration status",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	fmt.Printf("Version: %s\n\n", version.Version)
	fmt.Println("Config:")
	fmt.Printf("  config dir:   %s\n", cfg.ConfigDir)
	fmt.Printf("  commands dir: %s\n", cfg.CommandsDir)
	fmt.Printf("  identity:     %s\n", cfg.IdentityFile)
	fmt.Printf("  runtime dir:  %s\n", cfg.RuntimeDir)
	fmt.Printf("  state dir:    %s\n", cfg.StateDir)
	fmt.Printf("  default ttl:  %s\n", cfg.TTL)

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
	for _, name := range commands {
		cmdDir := filepath.Join(cfg.CommandsDir, name)
		hasSecrets := false
		if _, err := os.Stat(filepath.Join(cmdDir, "secrets.toml")); err == nil {
			hasSecrets = true
		}
		hasCommand := false
		if _, err := os.Stat(filepath.Join(cmdDir, "command.sh")); err == nil {
			hasCommand = true
		}
		detail := "no secrets"
		if hasSecrets && hasCommand {
			detail = "has secrets"
		} else if hasSecrets && !hasCommand {
			detail = "config-only"
		}
		fmt.Printf("  %s (%s)\n", name, detail)
	}

	// Agent.
	fmt.Println()
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
	c := client.NewWithSocket(sockPath)
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

func listCommands() []string {
	entries, err := os.ReadDir(cfg.CommandsDir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}
