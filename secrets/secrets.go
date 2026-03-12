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
	encPrefix = "AGE-ENC["
	encSuffix = "]"
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
		if isEncrypted(v) {
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
func EncryptFile(values map[string]string, recipient age.Recipient, keysToEncrypt []string) ([]byte, error) {
	encrypt := make(map[string]bool, len(keysToEncrypt))
	for _, k := range keysToEncrypt {
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
	return encPrefix + encoded + encSuffix, nil
}

// DecryptValue takes an AGE-ENC[...] wrapped string, unwraps, base64 decodes,
// age decrypts, and returns the plaintext.
func DecryptValue(wrapped string, identities []age.Identity) (string, error) {
	if !isEncrypted(wrapped) {
		return "", fmt.Errorf("value is not AGE-ENC wrapped")
	}

	inner := wrapped[len(encPrefix) : len(wrapped)-len(encSuffix)]
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

func isEncrypted(v string) bool {
	return strings.HasPrefix(v, encPrefix) && strings.HasSuffix(v, encSuffix)
}
