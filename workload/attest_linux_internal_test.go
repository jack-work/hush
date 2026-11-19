//go:build linux

package workload

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// tree is a fixture of the two kernel views the attestor reads: /proc and /sys/fs/cgroup.
type tree struct {
	t *testing.T
	r roots
}

func newTree(t *testing.T) tree {
	d := t.TempDir()
	return tree{t, roots{proc: filepath.Join(d, "proc"), cgroup: filepath.Join(d, "cgroup")}}
}

func (x tree) write(path, body string) {
	x.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		x.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		x.t.Fatal(err)
	}
}

// proc adds a process with a host uid, in the shape of /proc/<pid>/status.
func (x tree) proc(pid int, uid uint32) {
	x.write(filepath.Join(x.r.proc, fmt.Sprint(pid), "status"), fmt.Sprintf("Name:\tx\nUid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid))
}

// cg puts pids in a cgroup directory (cgroup.procs), creating it.
func (x tree) cg(dir string, pids ...int) {
	var b strings.Builder
	for _, p := range pids {
		fmt.Fprintln(&b, p)
	}
	x.write(filepath.Join(x.r.cgroup, dir, "cgroup.procs"), b.String())
}

const (
	base   = 1895890944 // range k=1, as measured
	unitA  = "/machine.slice/band-svc@spool-a-g1.service"
	leader = 100
)

// sandboxA lays out sandbox A as measured on a node: supervisor (host root), payload/init.scope (the leader, root
// inside), dbus and nscd in payload/system.slice, the box runner (inside uid 1000), and a padded uid_map.
func sandboxA(t *testing.T) tree {
	x := newTree(t)
	x.proc(1, 0)
	x.cg(unitA+"/supervisor", 1)
	x.cg(unitA)
	x.cg(unitA + "/payload")
	x.cg(unitA + "/payload/system.slice")
	x.proc(leader, base)
	x.cg(unitA+"/payload/init.scope", leader)
	x.proc(101, base+4)
	x.proc(102, base+999)
	x.cg(unitA+"/payload/system.slice/dbus-broker.service", 101)
	x.cg(unitA+"/payload/system.slice/nscd.service", 102)
	x.proc(103, base+1000)
	x.cg(unitA+"/payload/system.slice/figaro-box.service", 103)
	x.cg(unitA + "/.control")
	x.write(filepath.Join(x.r.proc, fmt.Sprint(leader), "uid_map"), "         0 1895890944      65536\n")
	return x
}

func registry(entries map[string][2]any) Registry {
	return func(name string) (string, uint32, error) {
		e, ok := entries[name]
		if !ok {
			return "", 0, errors.New("no such machine")
		}
		return e[0].(string), uint32(e[1].(int)), nil
	}
}

var registered = registry(map[string][2]any{"spool-a-g1": {"band-svc@spool-a-g1.service", leader}})

// RED if readMachine stops reading any fact the policy decides on.
func TestReadMachineGathersTheFacts(t *testing.T) {
	payloadUIDs := []uint32{base, base + 4, base + 999, base + 1000}
	cases := []struct {
		desc string
		edit func(tree)
		reg  Registry
		rest string
		want Machine
	}{
		{"control: the box runner in A's payload", nil, registered, "payload/system.slice/figaro-box.service",
			Machine{Payload: true, Registered: true, UIDMap: "0 1895890944 65536", UIDs: payloadUIDs}},
		{"the supervisor is not payload", nil, registered, "supervisor",
			Machine{Payload: false, Registered: true, UIDMap: "0 1895890944 65536", UIDs: payloadUIDs}},
		{".control is not payload", nil, registered, ".control",
			Machine{Payload: false, Registered: true, UIDMap: "0 1895890944 65536", UIDs: payloadUIDs}},
		{"a sibling named payloadx is not payload", nil, registered, "payloadx/x.service",
			Machine{Payload: false, Registered: true, UIDMap: "0 1895890944 65536", UIDs: payloadUIDs}},
		{"machined does not know the machine: nothing else is read", nil, registry(nil), "payload/init.scope",
			Machine{Payload: true}},
		{"machined names another unit for the name", nil,
			registry(map[string][2]any{"spool-a-g1": {"band-svc@spool-a-g2.service", leader}}), "payload/init.scope",
			Machine{Payload: true}},
		{"machined reports no leader", nil,
			registry(map[string][2]any{"spool-a-g1": {"band-svc@spool-a-g1.service", 0}}), "payload/init.scope",
			Machine{Payload: true}},
		{"a host-uid process in the payload is read as such", func(x tree) {
			x.proc(104, 1000)
			x.cg(unitA+"/payload/system.slice/intruder.service", 104)
		}, registered, "payload/init.scope",
			Machine{Payload: true, Registered: true, UIDMap: "0 1895890944 65536", UIDs: append(slices.Clone(payloadUIDs), 1000)}},
		{"a pid that exited mid-walk is skipped", func(x tree) {
			x.cg(unitA+"/payload/system.slice/gone.service", 999)
		}, registered, "payload/init.scope",
			Machine{Payload: true, Registered: true, UIDMap: "0 1895890944 65536", UIDs: payloadUIDs}},
		{"an unreadable cgroup in the payload drops every uid (never a partial list)", func(x tree) {
			if err := os.MkdirAll(filepath.Join(x.r.cgroup, unitA, "payload/system.slice/broken.service"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, registered, "payload/init.scope",
			Machine{Payload: true, Registered: true, UIDMap: "0 1895890944 65536"}},
		{"a uid_map of two ranges is kept distinct", func(x tree) {
			x.write(filepath.Join(x.r.proc, fmt.Sprint(leader), "uid_map"), "0 1895890944 65536\n65536 1000 1\n")
		}, registered, "payload/init.scope",
			Machine{Payload: true, Registered: true, UIDMap: "0 1895890944 65536;65536 1000 1", UIDs: payloadUIDs}},
	}
	for _, c := range cases {
		x := sandboxA(t)
		if c.edit != nil {
			c.edit(x)
		}
		got := x.r.readMachine(c.reg, "band-svc", "spool-a-g1", c.rest)
		c.want.Template, c.want.Instance = "band-svc", "spool-a-g1"
		slices.Sort(got.UIDs)
		slices.Sort(c.want.UIDs)
		if got.Template != c.want.Template || got.Instance != c.want.Instance || got.Payload != c.want.Payload ||
			got.Registered != c.want.Registered || got.UIDMap != c.want.UIDMap || !slices.Equal(got.UIDs, c.want.UIDs) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.desc, *got, c.want)
		}
	}
}

// The facts as read, through the policy: the real tree of a node gives A's identity to its box runner and refuses
// the supervisor and a mixed payload. RED if either half of the attestor-to-policy chain drops a fact.
func TestFactsThroughThePolicy(t *testing.T) {
	s := Sandboxes{Template: "band-svc", Base: 0x71000000, Size: 65536, Machines: map[string]Slot{"spool-a": {ID: "a", K: 1}}}
	p := MachinePolicy("kelliher", "spain", s)
	peer := func(x tree, uid uint32, rest string) Peer {
		cg := unitA + "/" + rest
		tm, in, r, _ := MachineOf(cg)
		return Peer{PID: 103, UID: uid, Cgroup: cg, Machine: x.r.readMachine(registered, tm, in, r)}
	}
	x := sandboxA(t)
	if id, err := p(peer(x, base+1000, "payload/system.slice/figaro-box.service")); err != nil ||
		id.String() != "spiffe://kelliher/node/spain/unit/band-svc.service/spool-a" {
		t.Errorf("box runner: %s %v", id, err)
	}
	if _, err := p(peer(x, 0, "supervisor")); err == nil || err.Error() != "unattested: sandbox spool-a-g1: not in the payload" {
		t.Errorf("supervisor: %v", err)
	}
	x.proc(104, 1000)
	x.cg(unitA+"/payload/system.slice/intruder.service", 104)
	if _, err := p(peer(x, base+1000, "payload/system.slice/figaro-box.service")); err == nil ||
		err.Error() != "unattested: sandbox spool-a-g1: payload runs host uid 1000 (mixed)" {
		t.Errorf("mixed: %v", err)
	}
}

// RED if unitRunsAs (the host unit guard, now on uidsUnder) stops refusing a mixed unit.
func TestUnitRunsAsOnlyOneUID(t *testing.T) {
	x := newTree(t)
	x.proc(1, 0)
	x.proc(2, 0)
	x.cg("/system.slice/a.service", 1, 2)
	if !x.r.unitRunsAs("/system.slice/a.service", 0) {
		t.Error("control: a unit of one uid")
	}
	x.proc(3, 1000)
	x.cg("/system.slice/a.service/sub", 3)
	if x.r.unitRunsAs("/system.slice/a.service", 0) {
		t.Error("a unit with a second uid passed")
	}
	if x.r.unitRunsAs("/system.slice/missing.service", 0) {
		t.Error("an unreadable unit passed")
	}
}

// A peer that connects and exits before it is read is refused: its pidfd names no pid any more, so a reused pid can
// never be read in its place. RED if the attestor stops checking the pidfd.
func TestAnExitedPeerIsRefused(t *testing.T) {
	if os.Getenv("HUSH_TEST_DIAL") != "" {
		c, err := net.Dial("unix", os.Getenv("HUSH_TEST_DIAL"))
		if err != nil {
			os.Exit(3)
		}
		_ = c
		os.Exit(0) // exit holding the connection open in the kernel's queue
	}
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestAnExitedPeerIsRefused$")
	child.Env = append(os.Environ(), "HUSH_TEST_DIAL="+sock)
	if err := child.Run(); err != nil {
		t.Fatalf("child: %v", err)
	}
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = PeerAttestor(conn)
	if err != nil && strings.Contains(err.Error(), "no peer pidfd") {
		t.Skipf("SKIP kernel without SO_PEERPIDFD: %v", err)
	}
	if !errors.Is(err, ErrUnattested) || err.Error() != "unattested: the peer has exited" {
		t.Fatalf("an exited peer: %v, want %q", err, "unattested: the peer has exited")
	}
}
