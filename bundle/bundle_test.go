package bundle_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/ca"
)

func root(t *testing.T) *x509.Certificate {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	c, err := ca.RootCert("kelliher", k)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestABundleRoundTrips(t *testing.T) {
	jwt, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid, _ := ca.JWTKeyID(&jwt.PublicKey)
	in := &bundle.Bundle{TrustDomain: "kelliher", Sequence: 7, RefreshHint: 5 * time.Minute,
		X509Authorities: []*x509.Certificate{root(t)}, JWTAuthorities: map[string]crypto.PublicKey{kid: &jwt.PublicKey}}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := bundle.Parse("kelliher", raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Sequence != 7 || out.RefreshHint != 5*time.Minute || len(out.X509Authorities) != 1 || !out.X509Authorities[0].Equal(in.X509Authorities[0]) {
		t.Fatalf("%+v", out)
	}
	if !jwt.PublicKey.Equal(out.JWTAuthorities[kid]) {
		t.Fatal("jwt authority changed")
	}
}

func TestParseSkipsUnknownUses(t *testing.T) {
	b, err := bundle.Parse("kelliher", []byte(`{"spiffe_sequence":1,"keys":[{"use":"future","kty":"x","crv":"y","x":""}]}`))
	if err != nil || len(b.X509Authorities)+len(b.JWTAuthorities) != 0 {
		t.Fatalf("%v %+v", err, b)
	}
}

func TestParseRefuses(t *testing.T) {
	r := root(t)
	good, _ := (&bundle.Bundle{TrustDomain: "kelliher", X509Authorities: []*x509.Certificate{r}}).Marshal()
	var doc map[string]any
	_ = json.Unmarshal(good, &doc)
	k := doc["keys"].([]any)[0].(map[string]any)
	x5c := k["x5c"].([]any)[0].(string)
	otherKey := ed25519.PublicKey(make([]byte, 32))
	other, _ := (&bundle.Bundle{TrustDomain: "kelliher", JWTAuthorities: map[string]crypto.PublicKey{"k": otherKey}}).Marshal()
	otherX := strings.Split(strings.Split(string(other), `"x": "`)[1], `"`)[0]
	for name, raw := range map[string]string{
		"not json":            `nope`,
		"two certs":           `{"keys":[{"use":"x509-svid","kty":"OKP","crv":"Ed25519","x":"` + k["x"].(string) + `","x5c":["` + x5c + `","` + x5c + `"]}]}`,
		"no cert":             `{"keys":[{"use":"x509-svid","kty":"OKP","crv":"Ed25519","x":"` + k["x"].(string) + `"}]}`,
		"key not the cert's":  `{"keys":[{"use":"x509-svid","kty":"OKP","crv":"Ed25519","x":"` + otherX + `","x5c":["` + x5c + `"]}]}`,
		"jwt key without kid": `{"keys":[{"use":"jwt-svid","kty":"OKP","crv":"Ed25519","x":"` + otherX + `"}]}`,
		"duplicate kid":       `{"keys":[{"use":"jwt-svid","kid":"a","kty":"OKP","crv":"Ed25519","x":"` + otherX + `"},{"use":"jwt-svid","kid":"a","kty":"OKP","crv":"Ed25519","x":"` + otherX + `"}]}`,
		"short ed25519":       `{"keys":[{"use":"jwt-svid","kid":"a","kty":"OKP","crv":"Ed25519","x":"AAAA"}]}`,
		"rsa":                 `{"keys":[{"use":"jwt-svid","kid":"a","kty":"RSA","crv":"","x":"AAAA"}]}`,
		"p256 off curve":      `{"keys":[{"use":"jwt-svid","kid":"a","kty":"EC","crv":"P-256","x":"` + strings.Repeat("A", 43) + `","y":"` + strings.Repeat("A", 43) + `"}]}`,
	} {
		if _, err := bundle.Parse("kelliher", []byte(raw)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := bundle.Parse("Kelliher", good); err == nil {
		t.Error("bad trust domain: parsed")
	}
}

func TestMarshalRefusesALeafAsAnAuthority(t *testing.T) {
	r := root(t)
	leaf := *r
	leaf.IsCA = false
	if _, err := (&bundle.Bundle{TrustDomain: "kelliher", X509Authorities: []*x509.Certificate{&leaf}}).Marshal(); err == nil {
		t.Fatal("marshalled a leaf")
	}
}
