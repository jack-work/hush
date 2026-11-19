package ca

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jack-work/hush/spiffeid"
)

const (
	SSHTTL    = 10 * time.Minute
	MaxSSHTTL = 24 * time.Hour
)

func IssueSSHUser(signer ssh.Signer, pub ssh.PublicKey, id spiffeid.ID, principals []string, now time.Time, ttl time.Duration) (*ssh.Certificate, error) {
	if id.IsZero() {
		return nil, errors.New("ssh certificate: no identity")
	}
	if len(principals) == 0 {
		return nil, errors.New("ssh certificate: at least one principal")
	}
	for _, p := range principals {
		if p == "" {
			return nil, errors.New("ssh certificate: an empty principal")
		}
	}
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        ssh.UserCert,
		KeyId:           id.String(),
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-ClockSkew).Unix()),
		ValidBefore:     uint64(now.Add(ClampTTL(ttl, SSHTTL, time.Minute, MaxSSHTTL)).Unix()),
		Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return cert, nil
}
