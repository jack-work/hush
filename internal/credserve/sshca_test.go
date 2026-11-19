//go:build linux

package credserve

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

type carig struct {
	t      *testing.T
	srv    *Server
	grants string
	state  string
	logs   *syncBuffer
	owner  *http.Client
	box    *http.Client // principal "onboardd", granted "fleet"
	other  *http.Client // principal "seat", not granted "fleet"
}

func newCARig(t *testing.T) *carig {
	t.Helper()
	dir := t.TempDir()
	key, _ := age.GenerateX25519Identity()
	me := fmt.Sprint(os.Getuid())
	cfg, err := ParseConfig([]byte(fmt.Sprintf(`
recipient = %q
allow_user = %q

[instances.fleet]
kind = "ssh-ca"
grants_file = %q

[instances.other-ca]
kind = "ssh-ca"
grants_file = %q

[principals.onboardd]
users = [%q]
credentials = ["fleet"]

[principals.seat]
users = [%q]
credentials = ["other-ca"]
`, key.Recipient().String(), me, filepath.Join(dir, "grants.json"), filepath.Join(dir, "grants.json"), me, me)))
	if err != nil {
		t.Fatal(err)
	}
	c := &carig{t: t, grants: filepath.Join(dir, "grants.json"), state: filepath.Join(dir, "state"), logs: &syncBuffer{}}
	c.srv = NewServer(cfg, nil, uint32(os.Getuid()), log.New(c.logs, "", 0))
	ps, err := ResolvePrincipals(cfg, func(u string) (uint32, error) { return uint32(os.Getuid()), nil })
	if err != nil {
		t.Fatal(err)
	}
	c.srv.SetPrincipals(ps, true)
	c.srv.SetSSHCA(c.state, []age.Identity{key})
	sockDir, err := os.MkdirTemp("", "casock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	hs := c.srv.HTTPServer()
	t.Cleanup(func() { hs.Close() })
	listen := func(name, principal string) *http.Client {
		sock := filepath.Join(sockDir, name+".sock")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		if principal != "" {
			ln = PrincipalListener(ln, principal)
		}
		go hs.Serve(ln)
		return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}
	}
	c.owner = listen("owner", "")
	c.box = listen("onboardd", "onboardd")
	c.other = listen("seat", "seat")
	return c
}

func (c *carig) grant(principal, cred string, until time.Time) {
	c.t.Helper()
	doc := map[string]any{"grants": []map[string]any{{"principal": principal, "credential": cred, "expires_at": float64(until.Unix())}}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(c.grants, b, 0o644); err != nil {
		c.t.Fatal(err)
	}
}

type caAnswer struct {
	status int
	Error  string `json:"error"`
	Cur    string `json:"current"`
	Next   string `json:"next"`
	Cert   string `json:"certificate"`
}

func (c *carig) do(cl *http.Client, method, path string, body any) caAnswer {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://hush"+path, rd)
	res, err := cl.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	a := caAnswer{status: res.StatusCode}
	_ = json.Unmarshal(raw, &a)
	return a
}

func hostKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ssh.NewPublicKey(pub)
	return k, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func parseCert(t *testing.T, line string) *ssh.Certificate {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := k.(*ssh.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %s", line)
	}
	return cert
}

// checker trusts exactly the given CA public lines, the way an
// @cert-authority known_hosts line does.
func checker(t *testing.T, now time.Time, cas ...string) *ssh.CertChecker {
	t.Helper()
	var trusted []ssh.PublicKey
	for _, l := range cas {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err != nil {
			t.Fatal(err)
		}
		trusted = append(trusted, k)
	}
	return &ssh.CertChecker{
		Clock: func() time.Time { return now },
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			for _, k := range trusted {
				if bytes.Equal(k.Marshal(), auth.Marshal()) {
					return true
				}
			}
			return false
		},
	}
}

var addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2231}

func TestSSHCARotateNeedsLiveGrant(t *testing.T) {
	c := newCARig(t)
	if a := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil); a.status != 403 || a.Error != "no_grant" {
		t.Fatalf("rotate without a grant: %d %s", a.status, a.Error)
	}
	c.grant("owner", "ssh-ca-rotate:fleet", time.Now().Add(-time.Minute))
	if a := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil); a.status != 403 {
		t.Fatalf("rotate with an expired grant: %d", a.status)
	}
	c.grant("seat", "ssh-ca-rotate:fleet", time.Now().Add(time.Hour))
	if a := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil); a.status != 403 {
		t.Fatalf("rotate with another principal's grant: %d", a.status)
	}
	c.grant("owner", "ssh-ca-rotate:other-ca", time.Now().Add(time.Hour))
	if a := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil); a.status != 403 {
		t.Fatalf("rotate with a grant for another CA: %d", a.status)
	}
	if a := c.do(c.box, "GET", "/ssh-ca/fleet/pub", nil); a.status != 409 || a.Error != "no_ca" {
		t.Fatalf("pub before init: %d %s", a.status, a.Error)
	}
	c.grant("owner", "ssh-ca-rotate:fleet", time.Now().Add(time.Hour))
	a := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil)
	if a.status != 200 || a.Cur == "" || a.Next == "" || a.Cur == a.Next {
		t.Fatalf("init rotate: %d %+v", a.status, a)
	}
	raw, _ := os.ReadFile(filepath.Join(c.state, "ssh-ca", "fleet.toml"))
	if bytes.Contains(raw, []byte("PRIVATE KEY")) || !bytes.Contains(raw, []byte("age-encryption")) && !bytes.Contains(raw, []byte("AGE")) {
		t.Fatalf("state holds a clear private key or no sealed one:\n%s", raw)
	}
}

func TestSSHCASignHostPositiveAndNegative(t *testing.T) {
	c := newCARig(t)
	c.grant("owner", "ssh-ca-rotate:fleet", time.Now().Add(time.Hour))
	ca := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil)
	_, beetPub := hostKey(t)
	a := c.do(c.box, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": "beet", "public_key": beetPub})
	if a.status != 200 {
		t.Fatalf("sign-host: %d %s", a.status, a.Error)
	}
	cert := parseCert(t, a.Cert)
	if cert.CertType != ssh.HostCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "beet" {
		t.Fatalf("cert: type %d principals %v", cert.CertType, cert.ValidPrincipals)
	}
	now := time.Now()
	chk := checker(t, now, ca.Cur, ca.Next)
	// P1: beet's cert, reached as HostKeyAlias beet, under the trusted CA.
	if err := chk.CheckHostKey("beet:22", addr, cert); err != nil {
		t.Fatalf("P1 beet: %v", err)
	}
	// N4: beet's cert presented as leob (a tunnel port shift, 11-18 beet :2231).
	if err := chk.CheckHostKey("leob:22", addr, cert); err == nil {
		t.Fatal("N4: beet's cert accepted as leob")
	}
	// The address alone is never a principal.
	if err := chk.CheckHostKey("127.0.0.1:2231", addr, cert); err == nil {
		t.Fatal("N4b: a node cert accepted for a bare 127.0.0.1 address")
	}
	// N2: expired.
	if err := checker(t, now.Add(36*24*time.Hour), ca.Cur).CheckHostKey("beet:22", addr, cert); err == nil {
		t.Fatal("N2: expired cert accepted")
	}
	// N3: a cert from a CA nobody trusts.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	rs, _ := ssh.NewSignerFromKey(rogue)
	k, _ := hostKey(t)
	bad := &ssh.Certificate{Key: k, CertType: ssh.HostCert, ValidPrincipals: []string{"beet"},
		ValidAfter: uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix())}
	_ = bad.SignCert(rand.Reader, rs)
	if err := chk.CheckHostKey("beet:22", addr, bad); err == nil {
		t.Fatal("N3: cert from an untrusted CA accepted")
	}
	// N1: a self-signed cert (the host key signs itself).
	_, selfPriv, _ := ed25519.GenerateKey(rand.Reader)
	selfSigner, _ := ssh.NewSignerFromKey(selfPriv)
	self := &ssh.Certificate{Key: selfSigner.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{"beet"},
		ValidAfter: uint64(now.Add(-time.Hour).Unix()), ValidBefore: uint64(now.Add(time.Hour).Unix())}
	_ = self.SignCert(rand.Reader, selfSigner)
	if err := chk.CheckHostKey("beet:22", addr, self); err == nil {
		t.Fatal("N1: self-signed cert accepted")
	}
	// A plain host key (no cert) is not vouched for by the CA.
	plain, _ := hostKey(t)
	if err := chk.CheckHostKey("beet:22", addr, plain); err == nil {
		t.Fatal("a bare host key accepted by a CA-only checker")
	}
}

func TestSSHCASignRefusals(t *testing.T) {
	c := newCARig(t)
	c.grant("owner", "ssh-ca-rotate:fleet", time.Now().Add(time.Hour))
	c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil)
	_, pub := hostKey(t)
	if a := c.do(c.other, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": "beet", "public_key": pub}); a.status != 403 || a.Error != "not_granted" {
		t.Fatalf("ungranted principal: %d %s", a.status, a.Error)
	}
	if a := c.do(c.other, "GET", "/ssh-ca/fleet/pub", nil); a.status != 403 {
		t.Fatalf("ungranted principal pub: %d", a.status)
	}
	if a := c.do(c.box, "POST", "/ssh-ca/fleet/rotate", nil); a.status != 403 || a.Error != "no_grant" {
		t.Fatalf("principal rotate on the owner's grant: %d %s", a.status, a.Error)
	}
	for _, node := range []string{"127.0.0.1", "Beet", "beet/x", "", "[127.0.0.1]:2231"} {
		if a := c.do(c.box, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": node, "public_key": pub}); a.status != 400 {
			t.Fatalf("node %q: %d", node, a.status)
		}
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rpub, _ := ssh.NewPublicKey(&rk.PublicKey)
	if a := c.do(c.box, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": "beet", "public_key": string(ssh.MarshalAuthorizedKey(rpub))}); a.status != 400 {
		t.Fatalf("rsa host key: %d", a.status)
	}
	signed := c.do(c.box, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": "beet", "public_key": pub})
	if a := c.do(c.box, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": "beet", "public_key": signed.Cert}); a.status != 400 {
		t.Fatalf("cert as host key: %d", a.status)
	}
	if a := c.do(c.box, "GET", "/cred/fleet", nil); a.status == 200 {
		t.Fatal("/cred/ served an ssh-ca instance")
	}
	if !strings.Contains(c.logs.String(), "ssh-ca: audit sign-host fleet node=beet") {
		t.Fatalf("no audit line:\n%s", c.logs.String())
	}
}

func TestSSHCARotationOverlap(t *testing.T) {
	c := newCARig(t)
	c.grant("owner", "ssh-ca-rotate:fleet", time.Now().Add(time.Hour))
	first := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil)
	_, pub := hostKey(t)
	old := parseCert(t, c.do(c.box, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": "verd", "public_key": pub}).Cert)
	second := c.do(c.owner, "POST", "/ssh-ca/fleet/rotate", nil)
	if second.Cur != first.Next || second.Next == first.Next || second.Next == first.Cur {
		t.Fatalf("rotate must promote next: first %+v second %+v", first, second)
	}
	renewed := parseCert(t, c.do(c.box, "POST", "/ssh-ca/fleet/sign-host", map[string]string{"node": "verd", "public_key": pub}).Cert)
	now := time.Now()
	overlap := checker(t, now, first.Cur, second.Cur, second.Next)
	for i, cert := range []*ssh.Certificate{old, renewed} {
		if err := overlap.CheckHostKey("verd:22", addr, cert); err != nil {
			t.Fatalf("R1 overlap accepts cert %d: %v", i, err)
		}
	}
	after := checker(t, now, second.Cur, second.Next)
	if err := after.CheckHostKey("verd:22", addr, renewed); err != nil {
		t.Fatalf("R1 re-signed cert under the new current: %v", err)
	}
	if err := after.CheckHostKey("verd:22", addr, old); err == nil {
		t.Fatal("R1 a cert from the dropped CA still accepted")
	}
}

func TestSSHCAConfigValidation(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	for _, extra := range []string{
		"kind = \"ssh-ca\"\nclient_id = \"x\"",
		"kind = \"ssh-ca\"\nvalidity = \"2400h\"",
		"kind = \"ssh-ca\"\nvalidity = \"10m\"",
		"kind = \"ssh-ca\"\ngrants_file = \"rel/grants.json\"",
		"kind = \"refresh_token\"\nclient_id = \"x\"\ntoken_url = \"https://t\"\nauthorize_url = \"https://a\"\nredirect_uri = \"https://r\"\nvalidity = \"24h\"",
	} {
		_, err := ParseConfig([]byte(fmt.Sprintf("recipient = %q\nallow_user = \"x\"\n[instances.ca]\n%s\n", key.Recipient().String(), extra)))
		if err == nil {
			t.Fatalf("accepted:\n%s", extra)
		}
	}
	if _, err := ParseConfig([]byte(fmt.Sprintf("recipient = %q\nallow_user = \"x\"\n[instances.ca]\nkind = \"ssh-ca\"\nvalidity = \"840h\"\n", key.Recipient().String()))); err != nil {
		t.Fatal(err)
	}
}
