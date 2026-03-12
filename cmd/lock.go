package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/gluck/hush/secrets"
)

func init() {
	rootCmd.AddCommand(lockCmd)
}

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Encrypt all plaintext values across all commands",
	Long:  `Walk all command directories and encrypt any non-AGE-ENC values in secrets.toml files.`,
	RunE:  runLock,
}

func runLock(cmd *cobra.Command, args []string) error {
	recipient, err := loadRecipient()
	if err != nil {
		return err
	}

	commands := listCommands()
	if len(commands) == 0 {
		fmt.Fprintln(os.Stderr, "no commands found")
		return nil
	}

	totalEncrypted := 0
	for _, name := range commands {
		secretsPath := filepath.Join(cfg.CommandsDir, name, "secrets.toml")
		data, err := os.ReadFile(secretsPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		var values map[string]string
		if err := toml.Unmarshal(data, &values); err != nil {
			return fmt.Errorf("%s: parse: %w", name, err)
		}

		count := 0
		for k, v := range values {
			if strings.HasPrefix(v, secrets.EncPrefix) && strings.HasSuffix(v, secrets.EncSuffix) {
				continue
			}
			enc, err := secrets.EncryptValue(v, recipient)
			if err != nil {
				return fmt.Errorf("%s: encrypt %q: %w", name, k, err)
			}
			values[k] = enc
			count++
		}

		if count == 0 {
			continue
		}

		out, err := secrets.MarshalTOML(values)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := os.WriteFile(secretsPath, out, 0600); err != nil {
			return fmt.Errorf("%s: write: %w", name, err)
		}

		fmt.Fprintf(os.Stderr, "  %s: encrypted %d value(s)\n", name, count)
		totalEncrypted += count
	}

	if totalEncrypted == 0 {
		fmt.Fprintln(os.Stderr, "all values already encrypted")
	} else {
		fmt.Fprintf(os.Stderr, "encrypted %d value(s) total\n", totalEncrypted)
	}
	return nil
}
