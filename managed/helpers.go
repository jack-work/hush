package managed

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/jack-work/hush/identity"
	"github.com/jack-work/hush/config"
)

// initIdentity generates a new age keypair and encrypts it with the given
// passphrase. Returns the public key string. The caller owns the
// passphrase buffer — we do NOT wipe it here, because the same bytes
// often need to be handed to a keyring write in the bootstrap flow.
// Callers should defer their own wipe.
func initIdentity(cfg *config.Config, passphrase []byte) (string, error) {
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

