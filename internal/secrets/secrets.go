// Package secrets handles per-value age encryption inside flat TOML files.
//
// All TOML values must be quoted strings — no bare integers, booleans, or
// nested tables. The file format is strictly key = "value" pairs so that
// unmarshal into map[string]string works without ambiguity.
package secrets

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
)

const (
	EncPrefix = "AGE-ENC["
	EncSuffix = "]"
)

// EncryptValue encrypts a single plaintext string and returns the AGE-ENC[...] wrapped string.
func EncryptValue(plaintext string, recipient age.Recipient) (string, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return "", fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return EncPrefix + encoded + EncSuffix, nil
}

// DecryptValue takes an AGE-ENC[...] wrapped string, unwraps, base64 decodes,
// age decrypts, and returns the plaintext.
func DecryptValue(wrapped string, identities []age.Identity) (string, error) {
	if !IsEncrypted(wrapped) {
		return "", fmt.Errorf("value is not AGE-ENC wrapped")
	}

	inner := wrapped[len(EncPrefix) : len(wrapped)-len(EncSuffix)]
	ciphertext, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return "", fmt.Errorf("age decrypt: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// MarshalTOML encodes a flat string map to TOML bytes.
func MarshalTOML(values map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(values); err != nil {
		return nil, fmt.Errorf("encode toml: %w", err)
	}
	return buf.Bytes(), nil
}

// IsEncrypted reports whether a value is wrapped in AGE-ENC[...].
func IsEncrypted(v string) bool {
	return strings.HasPrefix(v, EncPrefix) && strings.HasSuffix(v, EncSuffix)
}
