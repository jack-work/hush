package svid

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/spiffeid"
)

const JWTLeeway = 30 * time.Second

var (
	ErrUntrusted = errors.New("svid: not trusted")
	ErrExpired   = errors.New("svid: expired")
)

func VerifyX509(chain []*x509.Certificate, b *bundle.Bundle, now time.Time) (spiffeid.ID, error) {
	if len(chain) == 0 {
		return spiffeid.ID{}, fmt.Errorf("%w: no certificate", ErrUntrusted)
	}
	leaf := chain[0]
	if leaf.IsCA {
		return spiffeid.ID{}, fmt.Errorf("%w: the leaf is a CA", ErrUntrusted)
	}
	if leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return spiffeid.ID{}, fmt.Errorf("%w: the leaf may sign certificates", ErrUntrusted)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return spiffeid.ID{}, fmt.Errorf("%w: the leaf may not sign", ErrUntrusted)
	}
	if len(leaf.URIs) != 1 {
		return spiffeid.ID{}, fmt.Errorf("%w: want one URI SAN, got %d", ErrUntrusted, len(leaf.URIs))
	}
	id, err := spiffeid.FromURL(leaf.URIs[0])
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	if id.TrustDomain() != b.TrustDomain {
		return spiffeid.ID{}, fmt.Errorf("%w: %s is not in trust domain %s", ErrUntrusted, id, b.TrustDomain)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	paths, err := leaf.Verify(x509.VerifyOptions{
		Roots:         b.Pool(),
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var inv x509.CertificateInvalidError
		if errors.As(err, &inv) && inv.Reason == x509.Expired && now.After(inv.Cert.NotAfter) {
			return spiffeid.ID{}, fmt.Errorf("%w: %v", ErrExpired, err)
		}
		return spiffeid.ID{}, fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	for _, p := range paths {
		if scoped(id, p) {
			return id, nil
		}
	}
	return spiffeid.ID{}, fmt.Errorf("%w: %s is outside the node that issued it", ErrUntrusted, id)
}

func scoped(id spiffeid.ID, path []*x509.Certificate) bool {
	if len(path) != 3 {
		return false
	}
	issuer := path[1]
	node := issuer.Subject.SerialNumber
	return node != "" && id.Under(node)
}

type JWT struct {
	ID       spiffeid.ID
	Audience []string
	Expiry   time.Time
}

func VerifyJWT(token string, b *bundle.Bundle, audience string, now time.Time) (JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWT{}, fmt.Errorf("%w: not a compact JWS", ErrUntrusted)
	}
	enc := base64.RawURLEncoding
	var h struct {
		Alg  string `json:"alg"`
		Kid  string `json:"kid"`
		Typ  string `json:"typ"`
		Crit any    `json:"crit"`
	}
	if err := decode(parts[0], &h); err != nil {
		return JWT{}, err
	}
	if h.Alg != "ES256" {
		return JWT{}, fmt.Errorf("%w: alg %q", ErrUntrusted, h.Alg)
	}
	if h.Typ != "" && h.Typ != "JWT" && h.Typ != "JOSE" {
		return JWT{}, fmt.Errorf("%w: typ %q", ErrUntrusted, h.Typ)
	}
	if h.Crit != nil {
		return JWT{}, fmt.Errorf("%w: critical header", ErrUntrusted)
	}
	if h.Kid == "" {
		return JWT{}, fmt.Errorf("%w: no kid", ErrUntrusted)
	}
	key, ok := b.JWTAuthorities[h.Kid].(*ecdsa.PublicKey)
	if !ok {
		return JWT{}, fmt.Errorf("%w: kid %q is not a P-256 authority of %s", ErrUntrusted, h.Kid, b.TrustDomain)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return JWT{}, fmt.Errorf("%w: a malformed signature", ErrUntrusted)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, sum[:], r, s) {
		return JWT{}, fmt.Errorf("%w: bad signature", ErrUntrusted)
	}
	var c struct {
		Sub string          `json:"sub"`
		Aud json.RawMessage `json:"aud"`
		Exp *int64          `json:"exp"`
	}
	if err := decode(parts[1], &c); err != nil {
		return JWT{}, err
	}
	id, err := spiffeid.Parse(c.Sub)
	if err != nil {
		return JWT{}, fmt.Errorf("%w: sub: %v", ErrUntrusted, err)
	}
	if id.TrustDomain() != b.TrustDomain {
		return JWT{}, fmt.Errorf("%w: %s is not in trust domain %s", ErrUntrusted, id, b.TrustDomain)
	}
	aud, err := audiences(c.Aud)
	if err != nil {
		return JWT{}, err
	}
	if audience == "" || !slices.Contains(aud, audience) {
		return JWT{}, fmt.Errorf("%w: not for audience %q", ErrUntrusted, audience)
	}
	if c.Exp == nil {
		return JWT{}, fmt.Errorf("%w: no exp", ErrUntrusted)
	}
	exp := time.Unix(*c.Exp, 0)
	if !now.Before(exp.Add(JWTLeeway)) {
		return JWT{}, fmt.Errorf("%w: at %s", ErrExpired, exp.Format(time.RFC3339))
	}
	return JWT{ID: id, Audience: aud, Expiry: exp}, nil
}

func audiences(raw json.RawMessage) ([]string, error) {
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 {
		return many, nil
	}
	return nil, fmt.Errorf("%w: no audience", ErrUntrusted)
}

func decode(part string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: %v", ErrUntrusted, err)
	}
	return nil
}
