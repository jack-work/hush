package ca_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/ca"
	"github.com/jack-work/hush/spiffeid"
	"github.com/jack-work/hush/svid"
)

var now = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

type troupe struct {
	td        string
	root      ed25519.PrivateKey
	rootCert  *x509.Certificate
	inter     ed25519.PrivateKey
	interCert *x509.Certificate
	bundle    *bundle.Bundle
}

func newTroupe(t *testing.T, td, node string) troupe {
	t.Helper()
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	rc, err := ca.RootCert(td, root)
	if err != nil {
		t.Fatal(err)
	}
	_, inter, _ := ed25519.GenerateKey(rand.Reader)
	ic, err := ca.IssueIntermediate(root, rc, td, node, inter.Public(), now, ca.IntermediateTTL)
	if err != nil {
		t.Fatal(err)
	}
	return troupe{td, root, rc, inter, ic, &bundle.Bundle{TrustDomain: td, X509Authorities: []*x509.Certificate{rc}}}
}

func id(t *testing.T, s string) spiffeid.ID {
	t.Helper()
	v, err := spiffeid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func edKey() ed25519.PublicKey {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return pub
}

func TestTheRootMatchesFigarosTroupeRootByteForByte(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	c, err := ca.RootCert("kelliher", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(c.Raw)
	if got := hex.EncodeToString(sum[:]); got != "e7bf0b78f6b3fdff05fe7bb41f18e962a5eefa749b89eda0eb857cdd8da74e0d" {
		t.Fatalf("root certificate changed: %s; figaro's troupe.RootCert gives e7bf0b78...", got)
	}
}

func TestParseRootRefusesAnythingButAnEd25519PKCS8Key(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := x509.MarshalPKCS8PrivateKey(ed)
	if _, err := ca.ParseRoot(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: good})); err != nil {
		t.Fatal(err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKCS8PrivateKey(ec)
	for name, raw := range map[string][]byte{
		"empty":   nil,
		"not pem": []byte("hello"),
		"ecdsa":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}),
		"garbage": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := ca.ParseRoot(raw); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestAnSVIDVerifiesAgainstTheBundleWithItsIdentity(t *testing.T) {
	tr := newTroupe(t, "kelliher", "spain")
	for _, s := range []string{"spiffe://kelliher/node/spain/unit/figaro.service", "spiffe://kelliher/node/spain/figaro/abc"} {
		leaf, err := ca.IssueX509SVID(tr.inter, tr.interCert, id(t, s), edKey(), now, 0)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.NotAfter.Sub(now) != ca.SVIDTTL {
			t.Errorf("%s lives %s", s, leaf.NotAfter.Sub(now))
		}
		got, err := svid.VerifyX509([]*x509.Certificate{leaf, tr.interCert}, tr.bundle, now)
		if err != nil || got.String() != s {
			t.Fatalf("%s: %v %v", s, got, err)
		}
	}
	node, err := ca.IssueNode(tr.inter, tr.interCert, "kelliher", "spain", edKey(), now, ca.NodeTTL)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svid.VerifyX509([]*x509.Certificate{node, tr.interCert}, tr.bundle, now); err != nil || !got.IsNode() {
		t.Fatalf("node leaf: %v %v", got, err)
	}
}

func TestIssuanceRefuses(t *testing.T) {
	tr := newTroupe(t, "kelliher", "spain")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	other, _ := spiffeid.New("kelliher", "node", "merlin", "unit", "x.service")
	nodeID, _ := spiffeid.Node("kelliher", "spain")
	expired := *tr.interCert
	expired.NotAfter = now.Add(-time.Second)
	notCA := *tr.interCert
	notCA.IsCA = false
	cases := map[string]struct {
		issuer *x509.Certificate
		id     spiffeid.ID
		pub    crypto.PublicKey
		want   error
	}{
		"another node's subtree": {tr.interCert, other, edKey(), ca.ErrOutsideNode},
		"a node identity":        {tr.interCert, nodeID, edKey(), nil},
		"expired issuer":         {&expired, id(t, "spiffe://kelliher/node/spain/uid/1"), edKey(), ca.ErrIssuerExpired},
		"issuer not a CA":        {&notCA, id(t, "spiffe://kelliher/node/spain/uid/1"), edKey(), nil},
		"rsa key":                {tr.interCert, id(t, "spiffe://kelliher/node/spain/uid/1"), &rsaKey.PublicKey, nil},
		"p384 key":               {tr.interCert, id(t, "spiffe://kelliher/node/spain/uid/1"), &p384.PublicKey, nil},
	}
	for name, c := range cases {
		_, err := ca.IssueX509SVID(tr.inter, c.issuer, c.id, c.pub, now, 0)
		if err == nil {
			t.Errorf("%s: issued", name)
			continue
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestSVIDLifetimeIsClampedAndNeverOutlivesItsIssuer(t *testing.T) {
	tr := newTroupe(t, "kelliher", "spain")
	sid := id(t, "spiffe://kelliher/node/spain/uid/1000")
	for asked, want := range map[time.Duration]time.Duration{
		time.Second:    ca.MinSVIDTTL,
		90 * time.Hour: ca.MaxSVIDTTL,
		2 * time.Hour:  2 * time.Hour,
		-1 * time.Hour: ca.SVIDTTL,
	} {
		leaf, err := ca.IssueX509SVID(tr.inter, tr.interCert, sid, edKey(), now, asked)
		if err != nil {
			t.Fatal(err)
		}
		if got := leaf.NotAfter.Sub(now); got != want {
			t.Errorf("asked %s: lives %s, want %s", asked, got, want)
		}
	}
	late := tr.interCert.NotAfter.Add(-time.Minute)
	leaf, err := ca.IssueX509SVID(tr.inter, tr.interCert, sid, edKey(), late, 0)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(tr.interCert.NotAfter) {
		t.Fatalf("leaf outlives its issuer: %s > %s", leaf.NotAfter, tr.interCert.NotAfter)
	}
}

func TestVerifyX509Refuses(t *testing.T) {
	tr := newTroupe(t, "kelliher", "spain")
	sid := id(t, "spiffe://kelliher/node/spain/uid/1000")
	leaf, err := ca.IssueX509SVID(tr.inter, tr.interCert, sid, edKey(), now, 0)
	if err != nil {
		t.Fatal(err)
	}
	stranger := newTroupe(t, "kelliher", "spain")
	otherTD := newTroupe(t, "estate", "spain")
	otherLeaf, _ := ca.IssueX509SVID(otherTD.inter, otherTD.interCert, id(t, "spiffe://estate/node/spain/uid/1"), edKey(), now, 0)

	merlinPub, merlinKey, _ := ed25519.GenerateKey(rand.Reader)
	_ = merlinPub
	merlinInter, _ := ca.IssueIntermediate(tr.root, tr.rootCert, "kelliher", "merlin", merlinKey.Public(), now, ca.IntermediateTTL)
	forged := forgeLeaf(t, merlinKey, merlinInter, id(t, "spiffe://kelliher/node/spain/uid/0"))

	cases := map[string]struct {
		chain []*x509.Certificate
		b     *bundle.Bundle
		at    time.Time
		want  error
	}{
		"no chain":                     {nil, tr.bundle, now, svid.ErrUntrusted},
		"no intermediate":              {[]*x509.Certificate{leaf}, tr.bundle, now, svid.ErrUntrusted},
		"another root":                 {[]*x509.Certificate{leaf, tr.interCert}, stranger.bundle, now, svid.ErrUntrusted},
		"another trust domain":         {[]*x509.Certificate{otherLeaf, otherTD.interCert}, &bundle.Bundle{TrustDomain: "kelliher", X509Authorities: otherTD.bundle.X509Authorities}, now, svid.ErrUntrusted},
		"expired":                      {[]*x509.Certificate{leaf, tr.interCert}, tr.bundle, now.Add(2 * time.Hour), svid.ErrExpired},
		"not yet valid":                {[]*x509.Certificate{leaf, tr.interCert}, tr.bundle, now.Add(-time.Hour), svid.ErrUntrusted},
		"intermediate as leaf":         {[]*x509.Certificate{tr.interCert}, tr.bundle, now, svid.ErrUntrusted},
		"merlin signs spain's subtree": {[]*x509.Certificate{forged, merlinInter}, tr.bundle, now, svid.ErrUntrusted},
	}
	for name, c := range cases {
		if _, err := svid.VerifyX509(c.chain, c.b, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func forgeLeaf(t *testing.T, key ed25519.PrivateKey, issuer *x509.Certificate, sid spiffeid.ID) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big1(),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		URIs:         []*urlT{sid.URL()},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, edKey(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestJWTSVIDRoundTripsAndVerifyRefuses(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid, _ := ca.JWTKeyID("spain", &key.PublicKey)
	b := &bundle.Bundle{TrustDomain: "kelliher", JWTAuthorities: map[string]crypto.PublicKey{kid: &key.PublicKey}}
	sid := id(t, "spiffe://kelliher/node/spain/figaro/abc")
	tok, exp, err := ca.IssueJWTSVID(key, kid, sid, []string{"figaro-door", "spain"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Sub(now) != ca.JWTTTL {
		t.Fatalf("lives %s", exp.Sub(now))
	}
	got, err := svid.VerifyJWT(tok, b, "spain", now)
	if err != nil || got.ID != sid {
		t.Fatalf("%v %v", got, err)
	}

	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	strangerTok, _, _ := ca.IssueJWTSVID(stranger, kid, sid, []string{"spain"}, now, 0)
	otherTD, _, _ := ca.IssueJWTSVID(key, kid, id(t, "spiffe://estate/node/spain/uid/1"), []string{"spain"}, now, 0)
	cases := map[string]struct {
		tok  string
		aud  string
		at   time.Time
		want error
	}{
		"wrong audience":         {tok, "merlin", now, svid.ErrUntrusted},
		"empty audience":         {tok, "", now, svid.ErrUntrusted},
		"expired":                {tok, "spain", now.Add(ca.JWTTTL + svid.JWTLeeway), svid.ErrExpired},
		"another key":            {strangerTok, "spain", now, svid.ErrUntrusted},
		"another domain":         {otherTD, "spain", now, svid.ErrUntrusted},
		"alg none":               {resign(t, key, tok, `{"alg":"none","kid":"`+kid+`"}`), "spain", now, svid.ErrUntrusted},
		"alg HS256":              {resign(t, key, tok, `{"alg":"HS256","kid":"`+kid+`"}`), "spain", now, svid.ErrUntrusted},
		"no kid":                 {resign(t, key, tok, `{"alg":"ES256"}`), "spain", now, svid.ErrUntrusted},
		"unknown kid":            {resign(t, key, tok, `{"alg":"ES256","kid":"nope"}`), "spain", now, svid.ErrUntrusted},
		"critical header":        {resign(t, key, tok, `{"alg":"ES256","kid":"`+kid+`","crit":["x"]}`), "spain", now, svid.ErrUntrusted},
		"tampered claims":        {tamper(t, tok), "spain", now, svid.ErrUntrusted},
		"another node's subject": {forgeJWT(t, key, kid, `{"sub":"spiffe://kelliher/node/merlin/unit/sshd.service","aud":["spain"],"exp":`+fmt.Sprint(now.Add(time.Minute).Unix())+`}`), "spain", now, svid.ErrUntrusted},
		"high-s twin":            {highS(t, key, tok), "spain", now, svid.ErrUntrusted},
		"lives past an hour":     {forgeJWT(t, key, kid, `{"sub":"spiffe://kelliher/node/spain/figaro/abc","aud":["spain"],"exp":`+fmt.Sprint(now.Add(2*time.Hour).Unix())+`}`), "spain", now, svid.ErrUntrusted},
		"issued in the future":   {forgeJWT(t, key, kid, `{"sub":"spiffe://kelliher/node/spain/figaro/abc","aud":["spain"],"exp":`+fmt.Sprint(now.Add(time.Minute).Unix())+`,"iat":`+fmt.Sprint(now.Add(10*time.Minute).Unix())+`}`), "spain", now, svid.ErrUntrusted},
		"two parts":              {"a.b", "spain", now, svid.ErrUntrusted},
		"empty":                  {"", "spain", now, svid.ErrUntrusted},
	}
	for name, c := range cases {
		if _, err := svid.VerifyJWT(c.tok, b, c.aud, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestJWTIssuanceRefuses(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	sid := id(t, "spiffe://kelliher/node/spain/uid/1")
	for name, f := range map[string]func() error{
		"p384":           func() error { _, _, e := ca.IssueJWTSVID(p384, "spain:k", sid, []string{"a"}, now, 0); return e },
		"nil key":        func() error { _, _, e := ca.IssueJWTSVID(nil, "spain:k", sid, []string{"a"}, now, 0); return e },
		"no kid":         func() error { _, _, e := ca.IssueJWTSVID(key, "", sid, []string{"a"}, now, 0); return e },
		"no audience":    func() error { _, _, e := ca.IssueJWTSVID(key, "spain:k", sid, nil, now, 0); return e },
		"empty audience": func() error { _, _, e := ca.IssueJWTSVID(key, "spain:k", sid, []string{""}, now, 0); return e },
		"no subject": func() error {
			_, _, e := ca.IssueJWTSVID(key, "spain:k", spiffeid.ID{}, []string{"a"}, now, 0)
			return e
		},
		"unscoped kid": func() error { _, _, e := ca.IssueJWTSVID(key, "k", sid, []string{"a"}, now, 0); return e },
		"another node": func() error { _, _, e := ca.IssueJWTSVID(key, "merlin:k", sid, []string{"a"}, now, 0); return e },
	} {
		if f() == nil {
			t.Errorf("%s: issued", name)
		}
	}
}

func TestSSHUserCertificateCarriesTheIdentityAndChecksAgainstTheCA(t *testing.T) {
	_, caKey, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(caKey)
	userPub, _ := ssh.NewPublicKey(edKey())
	sid := id(t, "spiffe://kelliher/node/spain/figaro/abc")
	cert, err := ca.IssueSSHUser(signer, userPub, sid, []string{"git"}, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyId != sid.String() {
		t.Fatalf("key id %q", cert.KeyId)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(signer.PublicKey().Marshal()) },
		Clock:           func() time.Time { return now },
	}
	if err := checker.CheckCert("git", cert); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		principal string
		at        time.Time
	}{
		"principal not granted": {"root", now},
		"expired":               {"git", now.Add(ca.SSHTTL + time.Second)},
	} {
		checker.Clock = func() time.Time { return c.at }
		if err := checker.CheckCert(c.principal, cert); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	stranger, _ := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, 32)))
	checker.Clock = func() time.Time { return now }
	if _, err := checker.Authenticate(sshUser("git"), cert); err != nil {
		t.Fatalf("the issuing CA: %v", err)
	}
	checker.IsUserAuthority = func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(stranger.PublicKey().Marshal()) }
	if _, err := checker.Authenticate(sshUser("git"), cert); err == nil {
		t.Error("another CA: accepted")
	}
	if _, err := ca.IssueSSHUser(signer, userPub, sid, nil, now, 0); err == nil {
		t.Error("no principals: issued")
	}
}
