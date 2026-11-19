package bundle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jack-work/hush/spiffeid"
)

const (
	UseX509 = "x509-svid"
	UseJWT  = "jwt-svid"
)

type Bundle struct {
	TrustDomain     string
	Sequence        uint64
	RefreshHint     time.Duration
	X509Authorities []*x509.Certificate
	JWTAuthorities  map[string]crypto.PublicKey
}

type jwk struct {
	Use string   `json:"use"`
	Kid string   `json:"kid,omitempty"`
	Kty string   `json:"kty"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

type document struct {
	Sequence    uint64 `json:"spiffe_sequence"`
	RefreshHint int64  `json:"spiffe_refresh_hint,omitempty"`
	Keys        []jwk  `json:"keys"`
}

var b64 = base64.RawURLEncoding

func (b *Bundle) Marshal() ([]byte, error) {
	doc := document{Sequence: b.Sequence, RefreshHint: int64(b.RefreshHint / time.Second), Keys: []jwk{}}
	for _, c := range b.X509Authorities {
		if !c.IsCA {
			return nil, fmt.Errorf("x509 authority %q is not a CA", c.Subject.CommonName)
		}
		k, err := keyJWK(c.PublicKey)
		if err != nil {
			return nil, err
		}
		k.Use = UseX509
		k.X5c = []string{base64.StdEncoding.EncodeToString(c.Raw)}
		doc.Keys = append(doc.Keys, k)
	}
	kids := make([]string, 0, len(b.JWTAuthorities))
	for kid := range b.JWTAuthorities {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		if kid == "" {
			return nil, errors.New("a jwt authority needs a kid")
		}
		k, err := keyJWK(b.JWTAuthorities[kid])
		if err != nil {
			return nil, err
		}
		k.Use, k.Kid = UseJWT, kid
		doc.Keys = append(doc.Keys, k)
	}
	return json.MarshalIndent(doc, "", "  ")
}

func Parse(td string, raw []byte) (*Bundle, error) {
	if err := spiffeid.ValidTrustDomain(td); err != nil {
		return nil, err
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	b := &Bundle{TrustDomain: td, Sequence: doc.Sequence, RefreshHint: time.Duration(doc.RefreshHint) * time.Second, JWTAuthorities: map[string]crypto.PublicKey{}}
	for i, k := range doc.Keys {
		switch k.Use {
		case UseX509:
			c, err := x509Authority(k)
			if err != nil {
				return nil, fmt.Errorf("bundle key %d: %w", i, err)
			}
			b.X509Authorities = append(b.X509Authorities, c)
		case UseJWT:
			if k.Kid == "" {
				return nil, fmt.Errorf("bundle key %d: a jwt-svid key needs a kid", i)
			}
			if _, dup := b.JWTAuthorities[k.Kid]; dup {
				return nil, fmt.Errorf("bundle key %d: kid %q twice", i, k.Kid)
			}
			pub, err := jwkKey(k)
			if err != nil {
				return nil, fmt.Errorf("bundle key %d: %w", i, err)
			}
			b.JWTAuthorities[k.Kid] = pub
		}
	}
	return b, nil
}

func (b *Bundle) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range b.X509Authorities {
		p.AddCert(c)
	}
	return p
}

func x509Authority(k jwk) (*x509.Certificate, error) {
	if len(k.X5c) != 1 {
		return nil, fmt.Errorf("an x509-svid key carries exactly one certificate, got %d", len(k.X5c))
	}
	der, err := base64.StdEncoding.DecodeString(k.X5c[0])
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if !c.IsCA {
		return nil, errors.New("an x509-svid authority must be a CA")
	}
	pub, err := jwkKey(k)
	if err != nil {
		return nil, err
	}
	if !samePublic(pub, c.PublicKey) {
		return nil, errors.New("the key does not match its certificate")
	}
	return c, nil
}

func keyJWK(pub crypto.PublicKey) (jwk, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(k)}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return jwk{}, errors.New("want ECDSA on P-256")
		}
		raw, err := k.Bytes()
		if err != nil {
			return jwk{}, err
		}
		return jwk{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(raw[1:33]), Y: b64.EncodeToString(raw[33:])}, nil
	}
	return jwk{}, fmt.Errorf("unsupported key %T", pub)
}

func jwkKey(k jwk) (crypto.PublicKey, error) {
	x, err := b64.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("x: %w", err)
	}
	switch {
	case k.Kty == "OKP" && k.Crv == "Ed25519":
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("a malformed Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	case k.Kty == "EC" && k.Crv == "P-256":
		y, err := b64.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("y: %w", err)
		}
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("a malformed P-256 key")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, err
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported key type %s/%s", k.Kty, k.Crv)
}

func samePublic(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}
