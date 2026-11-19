package interop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	gobundle "github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/ca"
	hushid "github.com/jack-work/hush/spiffeid"
)

func TestGoSpiffeAcceptsWhatHushIssues(t *testing.T) {
	now := time.Now()
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	rc, err := ca.RootCert("kelliher", root)
	if err != nil {
		t.Fatal(err)
	}
	_, inter, _ := ed25519.GenerateKey(rand.Reader)
	ic, err := ca.IssueIntermediate(root, rc, "kelliher", "spain", inter.Public(), now, ca.IntermediateTTL)
	if err != nil {
		t.Fatal(err)
	}
	jwtKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid, _ := ca.JWTKeyID("spain", &jwtKey.PublicKey)
	raw, err := (&bundle.Bundle{TrustDomain: "kelliher", Sequence: 1, X509Authorities: []*x509.Certificate{rc},
		JWTAuthorities: map[string]crypto.PublicKey{kid: &jwtKey.PublicKey}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	td := spiffeid.RequireTrustDomainFromString("kelliher")
	gb, err := gobundle.Parse(td, raw)
	if err != nil {
		t.Fatalf("go-spiffe refuses hush's bundle: %v", err)
	}

	id, _ := hushid.Parse("spiffe://kelliher/node/spain/figaro/abc")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	leaf, err := ca.IssueX509SVID(inter, ic, id, pub, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := x509svid.Verify([]*x509.Certificate{leaf, ic}, gb)
	if err != nil {
		t.Fatalf("go-spiffe refuses hush's X.509-SVID: %v", err)
	}
	if got.String() != id.String() {
		t.Fatalf("go-spiffe reads %s", got)
	}

	tok, _, err := ca.IssueJWTSVID(jwtKey, kid, id, []string{"spain"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	js, err := jwtsvid.ParseAndValidate(tok, gb, []string{"spain"})
	if err != nil {
		t.Fatalf("go-spiffe refuses hush's JWT-SVID: %v", err)
	}
	if js.ID.String() != id.String() {
		t.Fatalf("go-spiffe reads %s", js.ID)
	}
}
