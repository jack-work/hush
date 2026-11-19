package ca_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type sshConn struct {
	ssh.ConnMetadata
	user string
}

func (c sshConn) User() string { return c.user }

func sshUser(u string) ssh.ConnMetadata { return sshConn{user: u} }

type urlT = url.URL

func big1() *big.Int { return big.NewInt(1) }

func resign(t *testing.T, key *ecdsa.PrivateKey, tok, header string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(header))
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

func tamper(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(raw), "figaro/abc", "figaro/xyz", 1)))
	return strings.Join(parts, ".")
}
