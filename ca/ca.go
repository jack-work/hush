package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/jack-work/hush/spiffeid"
)

const (
	IntermediateTTL = 365 * 24 * time.Hour
	NodeTTL         = 7 * 24 * time.Hour
	MinNodeTTL      = 24 * time.Hour
	MaxNodeTTL      = 30 * 24 * time.Hour
	SVIDTTL         = time.Hour
	MinSVIDTTL      = 5 * time.Minute
	MaxSVIDTTL      = 24 * time.Hour
	ClockSkew       = 5 * time.Minute
)

var (
	rootNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rootNotAfter  = time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
)

var (
	ErrIssuerExpired = errors.New("the issuing certificate has expired")
	ErrOutsideNode   = errors.New("the identity is outside the issuing node")
)

func ParseRoot(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("root key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("root key: %w", err)
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("root key: want Ed25519, got %T", k)
	}
	return ed, nil
}

func RootCert(td string, key ed25519.PrivateKey) (*x509.Certificate, error) {
	if err := spiffeid.ValidTrustDomain(td); err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(append([]byte(td+"\x00"), pub...))
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(sum[:16]),
		Subject:               pkix.Name{CommonName: "figaro troupe " + td},
		NotBefore:             rootNotBefore,
		NotAfter:              rootNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          sum[16:],
	}
	return create(tmpl, tmpl, pub, key)
}

func IssueIntermediate(root crypto.Signer, rootCert *x509.Certificate, td, node string, pub crypto.PublicKey, now time.Time, ttl time.Duration) (*x509.Certificate, error) {
	if _, err := spiffeid.Node(td, node); err != nil {
		return nil, err
	}
	if !now.Before(rootCert.NotAfter) {
		return nil, fmt.Errorf("%w at %s", ErrIssuerExpired, rootCert.NotAfter.Format(time.RFC3339))
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "figaro troupe " + td + " node " + node, SerialNumber: node},
		NotBefore:             now.Add(-ClockSkew),
		NotAfter:              earlier(now.Add(ttl), rootCert.NotAfter),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedURIDomains:   []string{td},
	}
	return create(tmpl, rootCert, pub, root)
}

func IntermediateNode(c *x509.Certificate) string {
	return c.Subject.SerialNumber
}

func ClampTTL(asked, def, least, most time.Duration) time.Duration {
	if asked <= 0 {
		asked = def
	}
	return min(max(asked, least), most)
}

func IssueNode(inter crypto.Signer, interCert *x509.Certificate, td, node string, pub crypto.PublicKey, now time.Time, ttl time.Duration) (*x509.Certificate, error) {
	id, err := spiffeid.Node(td, node)
	if err != nil {
		return nil, err
	}
	return issueLeaf(inter, interCert, id, pub, now, ttl)
}

func IssueX509SVID(inter crypto.Signer, interCert *x509.Certificate, id spiffeid.ID, pub crypto.PublicKey, now time.Time, ttl time.Duration) (*x509.Certificate, error) {
	if id.IsNode() {
		return nil, fmt.Errorf("%s is a node identity: issue it with IssueNode", id)
	}
	return issueLeaf(inter, interCert, id, pub, now, ClampTTL(ttl, SVIDTTL, MinSVIDTTL, MaxSVIDTTL))
}

func issueLeaf(inter crypto.Signer, interCert *x509.Certificate, id spiffeid.ID, pub crypto.PublicKey, now time.Time, ttl time.Duration) (*x509.Certificate, error) {
	if !interCert.IsCA {
		return nil, errors.New("the issuer is not a CA")
	}
	if !now.Before(interCert.NotAfter) {
		return nil, fmt.Errorf("%w at %s", ErrIssuerExpired, interCert.NotAfter.Format(time.RFC3339))
	}
	if !id.Under(IntermediateNode(interCert)) {
		return nil, fmt.Errorf("%w: %s from node %q", ErrOutsideNode, id, IntermediateNode(interCert))
	}
	if err := leafKey(pub); err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      leafSubject(id),
		NotBefore:    now.Add(-ClockSkew),
		NotAfter:     earlier(now.Add(ttl), interCert.NotAfter),
		URIs:         []*url.URL{id.URL()},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	return create(tmpl, interCert, pub, inter)
}

func leafSubject(id spiffeid.ID) pkix.Name {
	if id.IsNode() {
		node, _ := id.Node()
		return pkix.Name{CommonName: node}
	}
	return pkix.Name{}
}

func leafKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return errors.New("leaf key: a malformed Ed25519 key")
		}
		return nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return errors.New("leaf key: want ECDSA on P-256")
		}
		return nil
	}
	return fmt.Errorf("leaf key: want Ed25519 or ECDSA P-256, got %T", pub)
}

func create(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
