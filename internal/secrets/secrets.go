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
	"os"
	"strings"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
)

const (
	EncPrefix = "AGE-ENC["
	EncSuffix = "]"
)

// DecryptFile reads a TOML file from disk, decrypts any AGE-ENC[] wrapped
// values using the provided identities, and passes through plaintext values
// as-is. Returns a flat map of all key-value pairs fully decrypted.
func DecryptFile(path string, identities []age.Identity) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]string
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse toml: %w", err)
	}

	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if IsEncrypted(v) {
			dec, err := DecryptValue(v, identities)
			if err != nil {
				return nil, fmt.Errorf("decrypt key %q: %w", k, err)
			}
			out[k] = dec
		} else {
			out[k] = v
		}
	}
	return out, nil
}

// EncryptFile takes a flat map of plaintext key-value pairs and a list of
// which keys should be encrypted. For keys in keysToEncrypt, age-encrypt
// the value to the recipient, base64 encode, wrap in AGE-ENC[...]. Leave
// all other keys as plaintext. Marshal to TOML and return the bytes.
// TODO: use a structured value in the map to indicate which should be encrypted
// rather than string with adjacent list.
func EncryptFile(values map[string]string, recipient age.Recipient, keysToEncrypt []string) ([]byte, error) {
	encrypt := make(map[string]bool, len(keysToEncrypt))
	for _, k := range keysToEncrypt {
		if _, ok := values[k]; !ok {
			return nil, fmt.Errorf("key %q listed in keysToEncrypt but not found in values", k)
		}
		encrypt[k] = true
	}

	out := make(map[string]string, len(values))
	for k, v := range values {
		if encrypt[k] {
			enc, err := EncryptValue(v, recipient)
			if err != nil {
				return nil, fmt.Errorf("encrypt key %q: %w", k, err)
			}
			out[k] = enc
		} else {
			out[k] = v
		}
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(out); err != nil {
		return nil, fmt.Errorf("encode toml: %w", err)
	}
	return buf.Bytes(), nil
}

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
