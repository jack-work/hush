package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/gluck/hush/config"
	"github.com/gluck/hush/identity"
	"github.com/gluck/hush/secrets"
)

// Phase 1 test harness — exercises config, identity, and secrets encryption/decryption.
// This will be replaced by cobra commands in later phases.
func main() {
	fmt.Println("=== Phase 1: Config ===")
	cfg, err := config.Load()
	if err != nil {
		fatal("config load", err)
	}
	fmt.Printf("  TTL:          %s\n", cfg.TTL)
	fmt.Printf("  Identity:     %s\n", cfg.IdentityFile)
	fmt.Printf("  ConfigDir:    %s\n", cfg.ConfigDir)
	fmt.Printf("  CommandsDir:  %s\n", cfg.CommandsDir)
	fmt.Printf("  StateDir:     %s\n", cfg.StateDir)
	fmt.Printf("  RuntimeDir:   %s\n", cfg.RuntimeDir)

	fmt.Println("\n=== Phase 1: Identity ===")
	dir, err := os.MkdirTemp("", "hush-phase1-*")
	if err != nil {
		fatal("mkdtemp", err)
	}
	defer os.RemoveAll(dir)

	// Generate an age key pair using the library.
	ageIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		fatal("generate age identity", err)
	}
	pubkey := ageIdentity.Recipient().String()
	fmt.Printf("  Generated pubkey: %s\n", pubkey)

	// Write the plaintext identity to disk.
	keyFile := filepath.Join(dir, "identity.txt")
	keyData := []byte(ageIdentity.String() + "\n")
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		fatal("write key", err)
	}

	// Load it back via our identity package.
	id, err := identity.UnlockPlaintext(keyFile)
	if err != nil {
		fatal("unlock plaintext identity", err)
	}
	defer id.Zero()
	fmt.Printf("  Loaded %d identity(ies) from plaintext file\n", len(id.Identities))

	// Create a passphrase-encrypted copy and load it.
	encKeyFile := filepath.Join(dir, "identity.age")
	encryptIdentityWithPassphrase(keyData, encKeyFile, "testpass")

	passID, err := identity.Unlock(encKeyFile, []byte("testpass"))
	if err != nil {
		fatal("unlock encrypted identity", err)
	}
	defer passID.Zero()
	fmt.Printf("  Loaded %d identity(ies) from encrypted file\n", len(passID.Identities))

	fmt.Println("\n=== Phase 1: Secrets (encrypt → disk → decrypt) ===")

	// Original plaintext values.
	original := map[string]string{
		"token":     "super-secret-token-123",
		"api_key":   "sk-abc-456",
		"client_id": "not-secret-plaintext",
	}
	// Only encrypt token and api_key; leave client_id plaintext.
	keysToEncrypt := []string{"token", "api_key"}

	recipient := ageIdentity.Recipient()
	tomlBytes, err := secrets.EncryptFile(original, recipient, keysToEncrypt)
	if err != nil {
		fatal("encrypt file", err)
	}

	// Write to disk so we can see the format and read it back.
	secretsPath := filepath.Join(dir, "secrets.toml")
	if err := os.WriteFile(secretsPath, tomlBytes, 0600); err != nil {
		fatal("write secrets.toml", err)
	}

	fmt.Println("  On-disk secrets.toml:")
	for _, line := range strings.Split(string(tomlBytes), "\n") {
		if line != "" {
			fmt.Printf("    %s\n", line)
		}
	}

	// Read it back and decrypt.
	decrypted, err := secrets.DecryptFile(secretsPath, id.Identities)
	if err != nil {
		fatal("decrypt file", err)
	}

	fmt.Println("\n  Decrypted values:")
	allMatch := true
	for k, orig := range original {
		got := decrypted[k]
		match := "✓"
		if got != orig {
			match = "✗"
			allMatch = false
		}
		fmt.Printf("    %s %s = %q\n", match, k, got)
	}

	if !allMatch {
		fatal("verify", fmt.Errorf("decrypted values do not match originals"))
	}

	// Also verify via the encrypted identity.
	decrypted2, err := secrets.DecryptFile(secretsPath, passID.Identities)
	if err != nil {
		fatal("decrypt via encrypted identity", err)
	}
	for k, orig := range original {
		if decrypted2[k] != orig {
			fatal("verify encrypted id", fmt.Errorf("key %q: got %q, want %q", k, decrypted2[k], orig))
		}
	}
	fmt.Println("  ✓ Encrypted identity also decrypts correctly")

	fmt.Println("\n✓ Phase 1 complete")
}

func encryptIdentityWithPassphrase(keyData []byte, outPath, passphrase string) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		fatal("scrypt recipient", err)
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fatal("create encrypted key file", err)
	}
	defer f.Close()

	aw := armor.NewWriter(f)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		fatal("age encrypt", err)
	}
	if _, err := w.Write(keyData); err != nil {
		fatal("write encrypted key", err)
	}
	if err := w.Close(); err != nil {
		fatal("close age writer", err)
	}
	if err := aw.Close(); err != nil {
		fatal("close armor writer", err)
	}
}

func fatal(ctx string, err error) {
	fmt.Fprintf(os.Stderr, "FAIL [%s]: %v\n", ctx, err)
	os.Exit(1)
}
