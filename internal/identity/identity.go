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

// WriteTo writes the raw key bytes to w and then zeros them. After calling
// WriteTo, the identity can no longer be transferred — only the in-memory
// parsed Identities remain usable.
func (d *DecryptedIdentity) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(d.raw)
	for i := range d.raw {
		d.raw[i] = 0
	}
	return int64(n), err
}

// Zero overwrites the raw key material.
func (d *DecryptedIdentity) Zero() {
	for i := range d.raw {
		d.raw[i] = 0
	}
}

// ParseRaw creates a DecryptedIdentity from raw age identity bytes (as read
// from a pipe in daemon mode). The caller is responsible for zeroing the
// input slice if needed.
func ParseRaw(raw []byte) (*DecryptedIdentity, error) {
	identities, err := age.ParseIdentities(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}
	return &DecryptedIdentity{raw: raw, Identities: identities}, nil
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

// EncryptToFile writes keyData to outPath, encrypted with a passphrase via
// age's scrypt recipient. The file is created with 0600 permissions and
// O_EXCL to prevent overwriting.
func EncryptToFile(keyData []byte, outPath, passphrase string) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("scrypt recipient: %w", err)
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create identity file: %w", err)
	}
	defer f.Close()

	aw := armor.NewWriter(f)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(keyData); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return aw.Close()
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
