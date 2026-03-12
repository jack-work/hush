package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/jack-work/hush/agent"
	"github.com/jack-work/hush/secrets"
)

func init() {
	rootCmd.AddCommand(editCmd)
}

var editCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit a command's secrets in $EDITOR",
	Long: `Decrypt secrets.toml to a temp file, open it in $EDITOR, and re-encrypt
any changed or new plaintext values on save. Requires a running agent or
will start one implicitly.`,
	Args: cobra.ExactArgs(1),
	RunE: runEdit,
}

func runEdit(cmd *cobra.Command, args []string) error {
	name := args[0]
	secretsPath := filepath.Join(cfg.CommandsDir, name, "secrets.toml")

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	// Read and decrypt current secrets via agent.
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
	if err := ensureAgent(sockPath); err != nil {
		return err
	}

	var currentValues map[string]string
	data, err := os.ReadFile(secretsPath)
	if os.IsNotExist(err) {
		// New file — start empty.
		currentValues = make(map[string]string)
	} else if err != nil {
		return fmt.Errorf("read secrets: %w", err)
	} else {
		// Parse raw TOML.
		var raw map[string]string
		if err := toml.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("parse secrets: %w", err)
		}
		// Decrypt via agent to get plaintext for editing.
		currentValues, err = decryptMap(sockPath, raw)
		if err != nil {
			return err
		}
	}

	// Write plaintext to temp file.
	tmp, err := os.CreateTemp("", "hush-edit-*.toml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	plainTOML, err := secrets.MarshalTOML(currentValues)
	if err != nil {
		return err
	}
	if _, err := tmp.Write(plainTOML); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	// Open editor.
	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}

	// Read back edited values.
	editedData, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}

	var editedValues map[string]string
	if err := toml.Unmarshal(editedData, &editedValues); err != nil {
		return fmt.Errorf("parse edited file: %w", err)
	}

	// Encrypt all values.
	recipient, err := loadRecipient()
	if err != nil {
		return err
	}

	encrypted := make(map[string]string, len(editedValues))
	for k, v := range editedValues {
		// If value is already AGE-ENC wrapped (user pasted one in), keep it.
		if strings.HasPrefix(v, secrets.EncPrefix) && strings.HasSuffix(v, secrets.EncSuffix) {
			encrypted[k] = v
			continue
		}
		enc, err := secrets.EncryptValue(v, recipient)
		if err != nil {
			return fmt.Errorf("encrypt %q: %w", k, err)
		}
		encrypted[k] = enc
	}

	out, err := secrets.MarshalTOML(encrypted)
	if err != nil {
		return err
	}

	// Ensure command directory exists (for new files).
	if err := os.MkdirAll(filepath.Dir(secretsPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(secretsPath, out, 0600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "saved %d secret(s) to %s\n", len(encrypted), secretsPath)
	return nil
}

func decryptMap(sockPath string, raw map[string]string) (map[string]string, error) {
	resp, err := rpc(sockPath, agent.Request{Op: "decrypt", Values: raw})
	if err != nil {
		return nil, fmt.Errorf("agent decrypt: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("agent: %s", resp.Error)
	}
	return resp.Values, nil
}
