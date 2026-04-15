package managed

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/jack-work/hush/identity"
	"github.com/jack-work/hush/config"
)

// initIdentity generates a new age keypair and encrypts it with the given
// passphrase. Returns the public key string.
func initIdentity(cfg *config.Config, passphrase []byte) (string, error) {
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	identityPath := cfg.IdentityFile
	pubPath := identityPath + ".pub"

	if _, err := os.Stat(identityPath); err == nil {
		return "", fmt.Errorf("identity already exists at %s", identityPath)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generate identity: %w", err)
	}
	pubkey := id.Recipient().String()

	// Create config directory.
	if err := os.MkdirAll(filepath.Dir(identityPath), 0700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	// Write passphrase-encrypted identity.
	keyData := []byte(id.String() + "\n")
	if err := identity.EncryptToFile(keyData, identityPath, string(passphrase)); err != nil {
		return "", err
	}

	// Write public key.
	if err := os.WriteFile(pubPath, []byte(pubkey+"\n"), 0644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	// Create commands directory.
	os.MkdirAll(cfg.CommandsDir, 0700)

	return pubkey, nil
}

// promptPassphrase reads a passphrase from the terminal with the given prompt.
// Returns an error if stdin is not a terminal.
func promptPassphrase(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("no interactive terminal available for passphrase input")
	}
	fmt.Fprint(os.Stderr, prompt)
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return p, nil
}
