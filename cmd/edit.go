package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/secrets"
)

var editFile string

func init() {
	editCmd.Flags().StringVarP(&editFile, "file", "f", "", "path to secrets file (default: <commands-dir>/<name>/secrets.toml)")
	rootCmd.AddCommand(editCmd)
}

var editCmd = &cobra.Command{
	Use:   "edit [name]",
	Short: "Edit a command's secrets in $EDITOR",
	Long: `Decrypt secrets.toml to a temp file, open it in $EDITOR, and re-encrypt
any changed or new plaintext values on save. Requires a running agent or
will start one implicitly.

Use -f to edit an arbitrary secrets file instead of a named command:
  hush edit -f path/to/secrets.toml`,
	Args: func(cmd *cobra.Command, args []string) error {
		if editFile != "" {
			return cobra.MaximumNArgs(0)(cmd, args)
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
	RunE: runEdit,
}

func runEdit(cmd *cobra.Command, args []string) error {
	var secretsPath string
	if editFile != "" {
		secretsPath = editFile
	} else {
		secretsPath = filepath.Join(cfg.CommandsDir, args[0], "secrets.toml")
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	// Read and decrypt current secrets via agent.
	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
	if err := ensureAgent(sockPath); err != nil {
		return err
	}
	c := client.NewWithSocket(sockPath)

	data, err := os.ReadFile(secretsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read secrets: %w", err)
	}

	// Detect whether the file is a single AGE-ENC[...] blob or TOML key-value pairs.
	content := strings.TrimSpace(string(data))
	wholeFile := len(data) > 0 && secrets.IsEncrypted(content)

	if wholeFile {
		return editWholeFile(c, editor, secretsPath, content)
	}
	return editTOML(c, editor, secretsPath, data)
}

// editWholeFile handles files that are a single AGE-ENC[...] blob.
// Decrypts the whole content, opens in editor, re-encrypts on save.
func editWholeFile(c *client.Client, editor, secretsPath, encrypted string) error {
	result, err := c.Decrypt(map[string]string{"_": encrypted})
	if err != nil {
		return err
	}
	plaintext := result["_"]

	tmp, err := os.CreateTemp("", "hush-edit-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(plaintext); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}

	editedData, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}

	result, err = c.Encrypt(map[string]string{"_": string(editedData)})
	if err != nil {
		return err
	}

	if err := os.WriteFile(secretsPath, []byte(result["_"]+"\n"), 0600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "saved encrypted file %s\n", secretsPath)
	return nil
}

// editTOML handles TOML files with per-value AGE-ENC[...] encryption.
func editTOML(c *client.Client, editor, secretsPath string, data []byte) error {
	var currentValues map[string]string
	if len(data) == 0 {
		currentValues = make(map[string]string)
	} else {
		var raw map[string]string
		if err := toml.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("parse secrets: %w", err)
		}
		var err error
		currentValues, err = c.Decrypt(raw)
		if err != nil {
			return err
		}
	}

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

	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr
	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}

	editedData, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}

	var editedValues map[string]string
	if err := toml.Unmarshal(editedData, &editedValues); err != nil {
		return fmt.Errorf("parse edited file: %w", err)
	}

	encrypted, err := c.Encrypt(editedValues)
	if err != nil {
		return err
	}

	out, err := secrets.MarshalTOML(encrypted)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(secretsPath), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(secretsPath, out, 0600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "saved %d secret(s) to %s\n", len(encrypted), secretsPath)
	return nil
}

