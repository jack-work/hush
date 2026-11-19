//go:build linux

package credserve

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// srig serves one config's LoadCredential socket.
type srig struct {
	*prig
	sock string
}

func systemdConfig(managerUID uint32) string {
	return fmt.Sprintf(`
[principals.keel]
users = ["other"]
credentials = ["anthropic-work"]

[systemd]
socket = "/run/hush/systemd.sock"
manager_uid = %d

[systemd.units."keel-lieutenant.service"]
token = "anthropic-work"
copilot = "copilot-work"
`, managerUID)
}

func newSystemdRig(t *testing.T, managerUID uint32) *srig {
	t.Helper()
	p := newPrincipalRig(t, "", systemdConfig(managerUID))
	dir, err := os.MkdirTemp("", "sdsock-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "systemd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.srv.ServeSystemd(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("ServeSystemd: %v", err)
		}
	})
	return &srig{prig: p, sock: sock}
}

var abstractSeq int

// load connects as systemd does for LoadCredential=<id>:<socket> on behalf of
// unit (bound to "\0<random>/unit/<unit>/<id>"), or from an unbound address
// when unit is "", and returns every byte the server wrote.
func (s *srig) load(unit, id string) string {
	s.t.Helper()
	var laddr *net.UnixAddr
	if unit != "" {
		abstractSeq++
		laddr = &net.UnixAddr{Net: "unix", Name: fmt.Sprintf("@hushtest%d-%d/unit/%s/%s", os.Getpid(), abstractSeq, unit, id)}
	}
	c, err := net.DialUnix("unix", laddr, &net.UnixAddr{Net: "unix", Name: s.sock})
	if err != nil {
		s.t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil && !strings.Contains(err.Error(), "reset") {
		s.t.Fatal(err)
	}
	return string(got)
}

func me() uint32 { return uint32(os.Getuid()) }

func TestSystemdDeliversTheRawTokenToAGrantedUnit(t *testing.T) {
	s := newSystemdRig(t, me())
	if got := s.load("keel-lieutenant.service", "token"); got != "at-seed" {
		t.Fatalf("granted unit got %q, want the raw token", got)
	}
	logs := s.logs.String()
	if !strings.Contains(logs, `systemd: delivered anthropic-work to keel-lieutenant.service as "token"`) {
		t.Fatalf("no delivery line: %s", logs)
	}
	if !strings.Contains(logs, "cred: audit anthropic-work principal=systemd:keel-lieutenant.service") {
		t.Fatalf("no audit line: %s", logs)
	}
	if strings.Contains(logs, "at-seed") || strings.Contains(logs, "rt-canary") {
		t.Fatalf("a token reached the log: %s", logs)
	}
}

func TestSystemdWritesNothingOnRefusal(t *testing.T) {
	s := newSystemdRig(t, me())
	for name, c := range map[string]struct{ unit, id, log string }{
		"ungranted unit":      {"intruder.service", "token", `REFUSED intruder.service credential "token": no grant`},
		"ungranted id":        {"keel-lieutenant.service", "other", `REFUSED keel-lieutenant.service credential "other": no grant`},
		"not systemd":         {"", "", "address is not systemd's"},
		"unminted credential": {"keel-lieutenant.service", "copilot", "REFUSED copilot-work to keel-lieutenant.service"},
	} {
		if got := s.load(c.unit, c.id); got != "" {
			t.Fatalf("%s: got %q, want nothing", name, got)
		}
		if !strings.Contains(s.logs.String(), c.log) {
			t.Fatalf("%s: no %q in %s", name, c.log, s.logs.String())
		}
	}
	// Control: the same rig still serves the granted pair.
	if got := s.load("keel-lieutenant.service", "token"); got != "at-seed" {
		t.Fatalf("control: granted unit got %q", got)
	}
}

// Any process can bind an abstract address naming a granted unit; only the
// system manager's uid is believed.
func TestSystemdRefusesAForgedAddressFromAnotherUID(t *testing.T) {
	s := newSystemdRig(t, me()+1)
	if got := s.load("keel-lieutenant.service", "token"); got != "" {
		t.Fatalf("a forged address from uid %d got %q", me(), got)
	}
	if want := fmt.Sprintf("REFUSED uid %d (only the system manager, uid %d)", me(), me()+1); !strings.Contains(s.logs.String(), want) {
		t.Fatalf("no %q in %s", want, s.logs.String())
	}
}

func TestParseSystemdPeer(t *testing.T) {
	for name, c := range map[string]struct {
		addr     net.Addr
		unit, id string
		ok       bool
	}{
		"systemd":       {&net.UnixAddr{Name: "@a1b2/unit/x.service/tok"}, "x.service", "tok", true},
		"path address":  {&net.UnixAddr{Name: "/a1b2/unit/x.service/tok"}, "", "", false},
		"unbound":       {&net.UnixAddr{Name: ""}, "", "", false},
		"no unit":       {&net.UnixAddr{Name: "@a1b2/unit//tok"}, "", "", false},
		"extra segment": {&net.UnixAddr{Name: "@a1b2/unit/x.service/tok/more"}, "", "", false},
		"not unit":      {&net.UnixAddr{Name: "@a1b2/user/x.service/tok"}, "", "", false},
		"tcp":           {&net.TCPAddr{}, "", "", false},
	} {
		unit, id, ok := parseSystemdPeer(c.addr)
		if unit != c.unit || id != c.id || ok != c.ok {
			t.Fatalf("%s: got %q %q %v", name, unit, id, ok)
		}
	}
}

func TestSystemdConfigValidation(t *testing.T) {
	key, _ := age.GenerateX25519Identity()
	base := fmt.Sprintf("recipient = %q\nallow_user = \"me\"\n", key.Recipient().String()) + `
[instances.a]
kind = "copilot"
device_url = "https://github.example/login/device/code"
github_token_url = "https://github.example/login/oauth/access_token"
token_url = "https://api.github.example/copilot_internal/v2/token"
client_id = "Iv1.x"
`
	good := "[systemd]\nsocket = \"/run/hush/systemd.sock\"\n[systemd.units.\"k.service\"]\ntoken = \"a\"\n"
	if _, err := ParseConfig([]byte(base + good)); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, c := range map[string]struct{ body, want string }{
		"relative socket":    {"[systemd]\nsocket = \"s.sock\"\n[systemd.units.\"k.service\"]\ntoken = \"a\"\n", "not an absolute path"},
		"no units":           {"[systemd]\nsocket = \"/run/s.sock\"\n", "units is required"},
		"empty grants":       {"[systemd]\nsocket = \"/run/s.sock\"\n[systemd.units.\"k.service\"]\n", "grants nothing"},
		"not a unit":         {"[systemd]\nsocket = \"/run/s.sock\"\n[systemd.units.\"k/x\"]\ntoken = \"a\"\n", "is not a unit name"},
		"bad id":             {"[systemd]\nsocket = \"/run/s.sock\"\n[systemd.units.\"k.service\"]\n\"a/b\" = \"a\"\n", "is not a credential name"},
		"unknown instance":   {"[systemd]\nsocket = \"/run/s.sock\"\n[systemd.units.\"k.service\"]\ntoken = \"b\"\n", `"b" is not an instance`},
		"unknown key":        {"[systemd]\nsocket = \"/run/s.sock\"\nmanager = 0\n[systemd.units.\"k.service\"]\ntoken = \"a\"\n", "unknown keys"},
		"reserved principal": {good + "[principals.loadcredential]\nusers = [\"x\"]\ncredentials = [\"a\"]\n", "reserved for the systemd LoadCredential socket"},
	} {
		_, err := ParseConfig([]byte(base + c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want %q", name, err, c.want)
		}
	}
}
