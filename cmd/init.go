package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/identity"
)

func init() {
	rootCmd.AddCommand(initCmd)
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize hush: generate and encrypt an age identity",
	RunE:  runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	identityPath := cfg.IdentityFile
	pubPath := identityPath + ".pub"

	// Guard against overwriting an existing identity.
	if _, err := os.Stat(identityPath); err == nil {
		return fmt.Errorf("identity already exists at %s", identityPath)
	}

	// Generate keypair.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}
	pubkey := id.Recipient().String()

	// Prompt for passphrase (twice).
	passphrase, err := promptPassphraseTwice()
	if err != nil {
		return err
	}
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	// Create config directory.
	if err := os.MkdirAll(filepath.Dir(identityPath), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Write passphrase-encrypted identity.
	keyData := []byte(id.String() + "\n")
	if err := identity.EncryptToFile(keyData, identityPath, string(passphrase)); err != nil {
		return err
	}

	// Write public key.
	if err := os.WriteFile(pubPath, []byte(pubkey+"\n"), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	// Create commands directory.
	os.MkdirAll(cfg.CommandsDir, 0700)

	fmt.Fprintf(os.Stderr, "Identity created:\n")
	fmt.Fprintf(os.Stderr, "  Private key: %s\n", identityPath)
	fmt.Fprintf(os.Stderr, "  Public key:  %s\n", pubPath)
	fmt.Fprintf(os.Stderr, "  Recipient:   %s\n", pubkey)
	return nil
}

func promptPassphraseTwice() ([]byte, error) {
	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(p1) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		for i := range p1 {
			p1[i] = 0
		}
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	if string(p1) != string(p2) {
		for i := range p1 {
			p1[i] = 0
		}
		for i := range p2 {
			p2[i] = 0
		}
		return nil, fmt.Errorf("passphrases do not match")
	}

	for i := range p2 {
		p2[i] = 0
	}
	return p1, nil
}
