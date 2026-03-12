package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/secrets"
)

func init() {
	rootCmd.AddCommand(hushCmd)
}

var hushCmd = &cobra.Command{
	Use:   "hush <name>",
	Short: "Bootstrap a new command with a single secret",
	Long: `Create a new command directory with a secrets.toml containing one encrypted
secret and a stub command.sh that demonstrates the templating pattern.

Prompts for a single secret value (input is hidden). The secret is stored
as "secret" in secrets.toml. The directory path is printed to stdout.`,
	Args: cobra.ExactArgs(1),
	RunE: runHush,
}

func runHush(cmd *cobra.Command, args []string) error {
	name := args[0]
	cmdDir := filepath.Join(cfg.CommandsDir, name)

	if _, err := os.Stat(cmdDir); err == nil {
		return fmt.Errorf("command %q already exists at %s", name, cmdDir)
	}

	// Read public key.
	pubPath := cfg.IdentityFile + ".pub"
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read public key: %w (run 'hush init' first)", err)
	}
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(pubData)))
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	// Prompt for secret.
	fmt.Fprint(os.Stderr, "Enter secret value: ")
	secretBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}
	defer func() {
		for i := range secretBytes {
			secretBytes[i] = 0
		}
	}()

	if len(secretBytes) == 0 {
		return fmt.Errorf("secret cannot be empty")
	}

	// Encrypt.
	encValue, err := secrets.EncryptValue(string(secretBytes), recipient)
	if err != nil {
		return err
	}

	// Create directory.
	if err := os.MkdirAll(cmdDir, 0700); err != nil {
		return fmt.Errorf("create command dir: %w", err)
	}

	// Write secrets.toml.
	secretsContent := fmt.Sprintf("secret = %q\n", encValue)
	if err := os.WriteFile(filepath.Join(cmdDir, "secrets.toml"), []byte(secretsContent), 0600); err != nil {
		return err
	}

	// Write stub command.sh.
	stub := fmt.Sprintf(`# hush command: %s
# Edit this template. Secrets from secrets.toml are available as {{.secret}}.
# Extra CLI args are available as {{.Args}}, command name as {{.Cmd}}.
echo "secret={{.secret}}"
`, name)
	if err := os.WriteFile(filepath.Join(cmdDir, "command.sh"), []byte(stub), 0600); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "Command created. Edit command.sh to build your template.")
	fmt.Println(cmdDir)
	return nil
}
