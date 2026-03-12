package identity

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// DecryptedIdentity holds the raw bytes of the decrypted key.
// Call Zero() to wipe it from memory.
type DecryptedIdentity struct {
	raw        []byte
	Identities []age.Identity
}

// Zero overwrites the raw key material.
func (d *DecryptedIdentity) Zero() {
	for i := range d.raw {
		d.raw[i] = 0
	}
}

// Unlock reads a passphrase-encrypted age identity file and decrypts it.
// The passphrase slice is zeroed before this function returns.
func Unlock(path string, passphrase []byte) (*DecryptedIdentity, error) {
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity: %w", err)
	}
	defer f.Close()

	armorReader := armor.NewReader(f)

	// NOTE: string(passphrase) creates an immutable copy in memory that Go's
	// garbage collector will eventually reclaim but cannot be explicitly zeroed.
	// This is a known Go limitation. We still zero the []byte passphrase in the
	// defer above, which is the best we can do.
	scryptID, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("scrypt identity: %w", err)
	}

	reader, err := age.Decrypt(armorReader, scryptID)
	if err != nil {
		return nil, fmt.Errorf("decrypt identity file: %w", err)
	}

	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read decrypted identity: %w", err)
	}

	identities, err := age.ParseIdentities(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}

	return &DecryptedIdentity{raw: raw, Identities: identities}, nil
}

// UnlockPlaintext reads an unencrypted age identity file (for testing / convenience).
func UnlockPlaintext(path string) (*DecryptedIdentity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	identities, err := age.ParseIdentities(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}

	return &DecryptedIdentity{raw: raw, Identities: identities}, nil
}
