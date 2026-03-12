package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/gluck/hush/secrets"
)

var encryptKeys []string

func init() {
	encryptCmd.Flags().StringSliceVar(&encryptKeys, "key", nil, "encrypt only these keys (default: all plaintext)")
	rootCmd.AddCommand(encryptCmd)
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt <name>",
	Short: "Encrypt plaintext values in a command's secrets.toml",
	Long: `Read secrets.toml for the named command and encrypt any plaintext (non-AGE-ENC)
values in place. Use --key to encrypt only specific keys.`,
	Args: cobra.ExactArgs(1),
	RunE: runEncrypt,
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	name := args[0]
	secretsPath := filepath.Join(cfg.CommandsDir, name, "secrets.toml")

	data, err := os.ReadFile(secretsPath)
	if err != nil {
		return fmt.Errorf("read secrets: %w", err)
	}

	var values map[string]string
	if err := toml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("parse secrets: %w", err)
	}

	recipient, err := loadRecipient()
	if err != nil {
		return err
	}

	// Determine which keys to encrypt.
	targets := make(map[string]bool)
	if len(encryptKeys) > 0 {
		for _, k := range encryptKeys {
			targets[k] = true
		}
	} else {
		// All plaintext values.
		for k, v := range values {
			if !isEncrypted(v) {
				targets[k] = true
			}
		}
	}

	count := 0
	for k := range targets {
		v, ok := values[k]
		if !ok {
			return fmt.Errorf("key %q not found in %s", k, secretsPath)
		}
		if isEncrypted(v) {
			fmt.Fprintf(os.Stderr, "  %s: already encrypted, skipping\n", k)
			continue
		}
		enc, err := secrets.EncryptValue(v, recipient)
		if err != nil {
			return fmt.Errorf("encrypt %q: %w", k, err)
		}
		values[k] = enc
		count++
		fmt.Fprintf(os.Stderr, "  %s: encrypted\n", k)
	}

	if count == 0 {
		fmt.Fprintln(os.Stderr, "nothing to encrypt")
		return nil
	}

	// Write back.
	out, err := secrets.MarshalTOML(values)
	if err != nil {
		return err
	}
	if err := os.WriteFile(secretsPath, out, 0600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "encrypted %d value(s) in %s\n", count, secretsPath)
	return nil
}

func loadRecipient() (age.Recipient, error) {
	pubPath := cfg.IdentityFile + ".pub"
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w (run 'hush init' first)", err)
	}
	return age.ParseX25519Recipient(strings.TrimSpace(string(pubData)))
}

func isEncrypted(v string) bool {
	return strings.HasPrefix(v, secrets.EncPrefix) && strings.HasSuffix(v, secrets.EncSuffix)
}
