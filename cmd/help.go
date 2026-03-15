package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(helpCmd)
}

var helpCmd = &cobra.Command{
	Use:   "help",
	Short: "Show help and available commands",
	RunE:  runHelp,
}

func runHelp(cmd *cobra.Command, args []string) error {
	fmt.Println(`hush — secret-injecting command runner

Usage:
  hush <command> [args...]    Run a hush command (decrypts secrets, templates, executes)
  hush <builtin> [flags]      Run a built-in command

Built-in commands:
  init            Generate and encrypt an age identity
  up [-d] [--ttl] Start the agent (foreground or daemon)
  down            Stop the running agent
  status          Show agent, identity, and command status
  hush <name>     Bootstrap a new command with one secret
  encrypt <name>  Encrypt plaintext values in a command's secrets.toml
  encrypt-value   Encrypt a single string, print AGE-ENC[...] to stdout
  lock            Encrypt all plaintext values across all commands
  edit <name>     Decrypt secrets to $EDITOR, re-encrypt on save
  help            Show this help`)

	commands := listCommands()
	if len(commands) > 0 {
		fmt.Printf("\nYour commands (%s):\n", cfg.CommandsDir)
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
			if hasCommand {
				detail := ""
				if hasSecrets {
					detail = " (has secrets)"
				}
				fmt.Printf("  %-16s hush %s [args...]%s\n", name, name, detail)
			} else if hasSecrets {
				fmt.Printf("  %-16s config-only — secrets for library use\n", name)
			}
		}
	} else {
		fmt.Println("\nNo commands yet. Run 'hush hush <name>' to create one.")
	}

	return nil
}
