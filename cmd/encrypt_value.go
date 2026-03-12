package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/jack-work/hush/secrets"
)

func init() {
	rootCmd.AddCommand(encryptValueCmd)
}

var encryptValueCmd = &cobra.Command{
	Use:   "encrypt-value <plaintext | ->",
	Short: "Encrypt a single value and print the AGE-ENC[...] string",
	Long: `Encrypt a plaintext string using the public key from your hush identity.
The result is an AGE-ENC[...] wrapped string suitable for secrets.toml.

Pass "-" to read from stdin (trailing newline is trimmed).`,
	Args: cobra.ExactArgs(1),
	RunE: runEncryptValue,
}

func runEncryptValue(cmd *cobra.Command, args []string) error {
	plaintext := args[0]

	if plaintext == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		plaintext = strings.TrimRight(string(data), "\n")
	}

	pubPath := cfg.IdentityFile + ".pub"
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read public key: %w (expected at %s)", err, pubPath)
	}

	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(string(pubData)))
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	enc, err := secrets.EncryptValue(plaintext, recipient)
	if err != nil {
		return err
	}

	fmt.Println(enc)
	return nil
}
