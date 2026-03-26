package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/secrets"
)

func init() {
	rootCmd.AddCommand(decryptValueCmd)
}

var decryptValueCmd = &cobra.Command{
	Use:   "decrypt-value <AGE-ENC[...] | ->",
	Short: "Decrypt a single AGE-ENC[...] value and print the plaintext",
	Long: `Decrypt an AGE-ENC[...] wrapped string using the running hush agent.
The result is printed to stdout.

Pass "-" to read from stdin (trailing newline is trimmed).

Requires a running agent (hush up -d).`,
	Args: cobra.ExactArgs(1),
	RunE: runDecryptValue,
}

func runDecryptValue(cmd *cobra.Command, args []string) error {
	ciphertext := args[0]

	if ciphertext == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		ciphertext = strings.TrimRight(string(data), "\n")
	}

	if !secrets.IsEncrypted(ciphertext) {
		return fmt.Errorf("value is not AGE-ENC[...] wrapped")
	}

	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")

	if err := ensureAgent(sockPath); err != nil {
		return err
	}

	c := client.NewWithSocket(sockPath)
	result, err := c.Decrypt(map[string]string{"_": ciphertext})
	if err != nil {
		return err
	}

	fmt.Println(result["_"])
	return nil
}
