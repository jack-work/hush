package workload_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/ca"
	"github.com/jack-work/hush/spiffeid"
	"github.com/jack-work/hush/svid"
	"github.com/jack-work/hush/workload"
)

type fixture struct {
	socket string
	srv    *workload.Server
	auth   workload.Authority
	client *workload.Client
}

func authority(t *testing.T, node string, now time.Time) workload.Authority {
	t.Helper()
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	rc, err := ca.RootCert("kelliher", root)
	if err != nil {
		t.Fatal(err)
	}
	_, inter, _ := ed25519.GenerateKey(rand.Reader)
	ic, err := ca.IssueIntermediate(root, rc, "kelliher", node, inter.Public(), now, ca.IntermediateTTL)
	if err != nil {
		t.Fatal(err)
	}
	jk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid, _ := ca.JWTKeyID(&jk.PublicKey)
	return workload.Authority{
		Intermediate: inter, IntermediateCert: ic, JWTKey: jk, JWTKeyID: kid,
		Bundle: &bundle.Bundle{TrustDomain: "kelliher", Sequence: 1, X509Authorities: []*x509.Certificate{rc},
			JWTAuthorities: map[string]crypto.PublicKey{kid: &jk.PublicKey}},
	}
}

func serve(t *testing.T, attest workload.Attestor, policy workload.Policy, auth workload.Authority) fixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "hw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "w.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := workload.NewServer(attest, policy, auth)
	srv.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return fixture{sock, srv, auth, workload.NewClient("kelliher", sock)}
}

func fixed(p workload.Peer) workload.Attestor {
	return func(net.Conn) (workload.Peer, error) { return p, nil }
}

var unitPeer = workload.Peer{PID: 42, UID: 0, Cgroup: "/system.slice/figaro.service"}

func TestAWorkloadGetsAnSVIDForItsUnitAndAJWTThatVerifies(t *testing.T) {
	f := serve(t, fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), authority(t, "spain", time.Now()))
	ctx := context.Background()
	b, err := f.client.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	s, err := f.client.X509(ctx, key, b)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID.String() != "spiffe://kelliher/node/spain/unit/figaro.service" {
		t.Fatalf("id %s", s.ID)
	}
	if !s.RenewAfter.Before(s.Chain[0].NotAfter) {
		t.Fatal("renew_after is not before expiry")
	}
	j, err := f.client.JWT(ctx, "spain")
	if err != nil {
		t.Fatal(err)
	}
	got, err := svid.VerifyJWT(j.Token, b, "spain", time.Now())
	if err != nil || got.ID != s.ID {
		t.Fatalf("%v %v", got, err)
	}
}

func TestTheRealAttestorNamesThisProcess(t *testing.T) {
	var seen workload.Peer
	f := serve(t, func(c net.Conn) (workload.Peer, error) {
		p, err := workload.PeerAttestor(c)
		seen = p
		return p, err
	}, workload.NodePolicy("kelliher", "spain"), authority(t, "spain", time.Now()))
	if _, err := f.client.Bundle(context.Background()); err != nil {
		var we *workload.Error
		if errors.As(err, &we) && strings.Contains(we.Reason, "pidfd") {
			t.Skipf("kernel without SO_PEERPIDFD: %v", err)
		}
		t.Fatal(err)
	}
	if seen.PID != os.Getpid() || seen.UID != uint32(os.Getuid()) || seen.Cgroup == "" {
		t.Fatalf("attested %+v, want pid %d uid %d", seen, os.Getpid(), os.Getuid())
	}
}

func TestThePolicyMapsCgroupsToIdentities(t *testing.T) {
	p := workload.NodePolicy("kelliher", "spain")
	for cg, want := range map[string]string{
		"/system.slice/figaro.service":                                      "spiffe://kelliher/node/spain/unit/figaro.service",
		"/system.slice/systemd-nspawn@shell0.service/payload":               "spiffe://kelliher/node/spain/unit/systemd-nspawn.service/shell0",
		"/system.slice/figaro-valet@gluck.service":                          "spiffe://kelliher/node/spain/unit/figaro-valet.service/gluck",
		"/system.slice/getty@tty\\x2d1.service":                             "spiffe://kelliher/node/spain/uid/1000",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/x.service": "spiffe://kelliher/node/spain/uid/1000",
		"/system.slice/foo.mount":                                           "spiffe://kelliher/node/spain/uid/1000",
	} {
		id, err := p(workload.Peer{PID: 1, UID: 1000, Cgroup: cg})
		if err != nil || id.String() != want {
			t.Errorf("%s: %s %v, want %s", cg, id, err, want)
		}
	}
	id, err := p(workload.Peer{PID: 1, UID: 1000, Cgroup: "/system.slice/figaro.service", Mixed: true})
	if err != nil || id.String() != "spiffe://kelliher/node/spain/uid/1000" {
		t.Errorf("a uid sharing its unit with another uid got %s %v, want its uid identity", id, err)
	}
}

func post(t *testing.T, sock, path, body string) (int, map[string]string) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	resp, err := c.Post("http://hush"+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestTheSocketRefuses(t *testing.T) {
	now := time.Now()
	good := authority(t, "spain", now)
	expired := good
	ic := *good.IntermediateCert
	ic.NotAfter = now.Add(-time.Minute)
	expired.IntermediateCert = &ic
	merlin := workload.NodePolicy("kelliher", "merlin")
	refuse := func(workload.Peer) (spiffeid.ID, error) { return spiffeid.ID{}, workload.ErrUnattested }
	unattested := func(net.Conn) (workload.Peer, error) { return workload.Peer{}, workload.ErrUnattested }
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csrPEM := string(pemCSR(csr))
	broken := []byte(csrPEM)
	broken[len(broken)/2] ^= 1
	brokenJSON, _ := json.Marshal(map[string]string{"csr": string(broken)})
	goodJSON, _ := json.Marshal(map[string]string{"csr": csrPEM})

	cases := map[string]struct {
		attest workload.Attestor
		policy workload.Policy
		auth   workload.Authority
		path   string
		body   string
		status int
		code   string
	}{
		"unattested peer":        {unattested, workload.NodePolicy("kelliher", "spain"), good, "/v1/x509-svid", string(goodJSON), 403, "unattested"},
		"policy refuses":         {fixed(unitPeer), refuse, good, "/v1/x509-svid", string(goodJSON), 403, "unattested"},
		"another node's subtree": {fixed(unitPeer), merlin, good, "/v1/x509-svid", string(goodJSON), 403, "not_granted"},
		"no csr":                 {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), good, "/v1/x509-svid", `{}`, 400, "bad_request"},
		"csr not signed by key":  {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), good, "/v1/x509-svid", string(brokenJSON), 400, "bad_request"},
		"not json":               {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), good, "/v1/x509-svid", `nope`, 400, "bad_request"},
		"expired intermediate":   {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), expired, "/v1/x509-svid", string(goodJSON), 503, "unavailable"},
		"no intermediate":        {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), workload.Authority{}, "/v1/x509-svid", string(goodJSON), 503, "unavailable"},
		"jwt without audience":   {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), good, "/v1/jwt-svid", `{"audience":[]}`, 400, "bad_request"},
		"jwt unattested":         {unattested, workload.NodePolicy("kelliher", "spain"), good, "/v1/jwt-svid", `{"audience":["a"]}`, 403, "unattested"},
		"jwt without a key":      {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), workload.Authority{}, "/v1/jwt-svid", `{"audience":["a"]}`, 503, "unavailable"},
		"oversized body":         {fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), good, "/v1/jwt-svid", `{"audience":["` + strings.Repeat("a", 20<<10) + `"]}`, 400, "bad_request"},
	}
	for name, c := range cases {
		f := serve(t, c.attest, c.policy, c.auth)
		status, out := post(t, f.socket, c.path, c.body)
		if status != c.status || out["error"] != c.code {
			t.Errorf("%s: %d %v, want %d %s", name, status, out, c.status, c.code)
		}
	}
}

func TestTheClientRefusesAnAnswerItCannotVerify(t *testing.T) {
	now := time.Now()
	f := serve(t, fixed(unitPeer), workload.NodePolicy("kelliher", "spain"), authority(t, "spain", now))
	other := authority(t, "spain", now)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := f.client.X509(context.Background(), key, other.Bundle); !errors.Is(err, svid.ErrUntrusted) {
		t.Fatalf("another root: %v", err)
	}
}

func pemCSR(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
