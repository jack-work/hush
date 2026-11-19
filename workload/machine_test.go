package workload_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jack-work/hush/workload"
)

// The sandbox map of these tests: the fixed user-namespace ranges measured on a node running the sandbox pool
// (base 0x71000000, 65536 uids per k; k=1 starts at 1895890944).
var sandboxes = workload.Sandboxes{
	Template: "band-svc",
	Base:     0x71000000,
	Size:     65536,
	Machines: map[string]workload.Slot{
		"spool-captains-log-steward": {ID: "captains-log-steward", K: 1},
		"spool-b":                    {ID: "b", K: 2},
		"spool-c":                    {ID: "c", K: 3},
	},
}

const (
	kA        = 1895890944 // range k=1
	kB        = kA + 65536 // range k=2
	kC        = kB + 65536 // range k=3
	unitA     = "/machine.slice/band-svc@spool-captains-log-steward-g1.service"
	boxA      = unitA + "/payload/system.slice/figaro-box.service" // the real path measured on the node
	identityA = "spiffe://kelliher/node/spain/unit/band-svc.service/spool-captains-log-steward"
)

// machineA is sandbox A as the attestor reads it: registered, payload, its fixed range, the payload uids measured
// (root, dbus 4, oomd 998, nscd 999, the box user 1000, all mapped into the range).
func machineA(instance string) *workload.Machine {
	return &workload.Machine{
		Template: "band-svc", Instance: instance, Payload: true, Registered: true,
		UIDMap: "0 1895890944 65536",
		UIDs:   []uint32{kA, kA + 4, kA + 998, kA + 999, kA + 1000},
	}
}

func with(m *workload.Machine, edit func(*workload.Machine)) *workload.Machine {
	c := *m
	c.UIDs = append([]uint32(nil), m.UIDs...)
	edit(&c)
	return &c
}

// Contract H1 section 4, row by row. Each refusal sits next to the control it differs from in one fact.
// RED if any rule of MachinePolicy goes: each refusal row names the fact whose check it needs.
func TestSandboxIdentityRules(t *testing.T) {
	p := workload.MachinePolicy("kelliher", "spain", sandboxes)
	a := machineA("spool-captains-log-steward-g1")
	cases := []struct {
		desc   string
		peer   workload.Peer
		want   string // the SPIFFE id, or "" for a refusal
		reason string // the refusal's exact text after "unattested: sandbox <instance>: "
	}{
		{"control: the box runner in sandbox A gets A's identity",
			workload.Peer{PID: 7, UID: kA + 1000, Cgroup: boxA, Machine: a}, identityA, ""},
		{"control: root inside A (host uid = base) gets A's identity",
			workload.Peer{PID: 8, UID: kA, Cgroup: unitA + "/payload/init.scope", Machine: a}, identityA, ""},
		{"A after a rebuild (g2) gets the SAME identity: the generation is stripped",
			workload.Peer{PID: 9, UID: kA + 1000, Cgroup: "/machine.slice/band-svc@spool-captains-log-steward-g2.service/payload/system.slice/figaro-box.service",
				Machine: machineA("spool-captains-log-steward-g2")}, identityA, ""},
		{"A restarted (a new leader, same range) gets the SAME identity",
			workload.Peer{PID: 4242, UID: kA + 1000, Cgroup: boxA, Machine: a}, identityA, ""},
		{"sandbox B gets B's identity, never A's",
			workload.Peer{PID: 10, UID: kB + 1000, Cgroup: "/machine.slice/band-svc@spool-b-g1.service/payload/system.slice/figaro-box.service",
				Machine: &workload.Machine{Template: "band-svc", Instance: "spool-b-g1", Payload: true, Registered: true,
					UIDMap: "0 1895956480 65536", UIDs: []uint32{kB, kB + 1000}}},
			"spiffe://kelliher/node/spain/unit/band-svc.service/spool-b", ""},
		{"a new identity C in a k that a retired identity held gets C's identity",
			workload.Peer{PID: 11, UID: kC + 1000, Cgroup: "/machine.slice/band-svc@spool-c-g1.service/payload/system.slice/figaro-box.service",
				Machine: &workload.Machine{Template: "band-svc", Instance: "spool-c-g1", Payload: true, Registered: true,
					UIDMap: "0 1896022016 65536", UIDs: []uint32{kC, kC + 1000}}},
			"spiffe://kelliher/node/spain/unit/band-svc.service/spool-c", ""},
		{"the retired identity's machine (k reused by C, gone from the map) is refused",
			workload.Peer{PID: 12, UID: kC + 1000, Cgroup: "/machine.slice/band-svc@spool-retired-g1.service/payload",
				Machine: &workload.Machine{Template: "band-svc", Instance: "spool-retired-g1", Payload: true, Registered: true,
					UIDMap: "0 1896022016 65536", UIDs: []uint32{kC + 1000}}},
			"", "not in the sandbox map"},
		{"supervisor (systemd-nspawn, host root) in A's unit is refused",
			workload.Peer{PID: 13, UID: 0, Cgroup: unitA + "/supervisor",
				Machine: with(a, func(m *workload.Machine) { m.Payload = false })}, "", "not in the payload"},
		{".control in A's unit is refused",
			workload.Peer{PID: 14, UID: 0, Cgroup: unitA + "/.control",
				Machine: with(a, func(m *workload.Machine) { m.Payload = false })}, "", "not in the payload"},
		{"a machine not registered with machined (a bare cgroup dir) is refused",
			workload.Peer{PID: 15, UID: kA + 1000, Cgroup: boxA,
				Machine: with(a, func(m *workload.Machine) { m.Registered = false })}, "", "not registered with machined"},
		{"a userns picked at start (pre-fixed range) is refused",
			workload.Peer{PID: 16, UID: 1451361256, Cgroup: boxA,
				Machine: with(a, func(m *workload.Machine) { m.UIDMap = "0 1451360256 65536"; m.UIDs = []uint32{1451361256} })},
			"", `user namespace "0 1451360256 65536" is not range k=1`},
		{"a userns of the right base but another size is refused",
			workload.Peer{PID: 17, UID: kA + 1000, Cgroup: boxA,
				Machine: with(a, func(m *workload.Machine) { m.UIDMap = "0 1895890944 65537" })},
			"", `user namespace "0 1895890944 65537" is not range k=1`},
		{"a userns of two ranges is refused",
			workload.Peer{PID: 18, UID: kA + 1000, Cgroup: boxA,
				Machine: with(a, func(m *workload.Machine) { m.UIDMap = "0 1895890944 65536;65536 1000 1" })},
			"", `user namespace "0 1895890944 65536;65536 1000 1" is not range k=1`},
		{"a caller uid outside A's range is refused",
			workload.Peer{PID: 19, UID: 1000, Cgroup: boxA, Machine: a}, "", "uid 1000 outside the range"},
		{"a caller one past A's range is refused",
			workload.Peer{PID: 20, UID: kA + 65536, Cgroup: boxA, Machine: a}, "", "uid 1895956480 outside the range"},
		{"a host-uid process inside A's payload makes A mixed: refused, never a uid identity",
			workload.Peer{PID: 21, UID: kA + 1000, Cgroup: boxA,
				Machine: with(a, func(m *workload.Machine) { m.UIDs = append(m.UIDs, 1000) })}, "", "payload runs host uid 1000 (mixed)"},
		{"a payload whose uids could not be read is refused",
			workload.Peer{PID: 22, UID: kA + 1000, Cgroup: boxA,
				Machine: with(a, func(m *workload.Machine) { m.UIDs = nil })}, "", "no payload process read"},
		{"a sandbox-template unit without facts is refused",
			workload.Peer{PID: 23, UID: kA + 1000, Cgroup: boxA}, "", "no machine facts"},
		{"facts for another machine than the cgroup names are refused",
			workload.Peer{PID: 24, UID: kA + 1000, Cgroup: boxA, Machine: machineA("spool-b-g1")}, "", "no machine facts"},
		{"an instance without a generation is refused",
			workload.Peer{PID: 25, UID: kA + 1000, Cgroup: "/machine.slice/band-svc@spool-captains-log-steward.service/payload",
				Machine: machineA("spool-captains-log-steward")}, "", "instance has no -g<generation>"},
		{"the activation proxy (system.slice, root) gets its own unit identity, never A's",
			workload.Peer{PID: 27, UID: 0, Cgroup: "/system.slice/sandbox-pool-captains-log-steward.service"},
			"spiffe://kelliher/node/spain/unit/sandbox-pool-captains-log-steward.service", ""},
		{"a host process keeps its unit identity",
			workload.Peer{PID: 28, UID: 0, Cgroup: "/system.slice/figaro.service"},
			"spiffe://kelliher/node/spain/unit/figaro.service", ""},
		{"a user session keeps its uid identity",
			workload.Peer{PID: 29, UID: 1000, Cgroup: "/user.slice/user-1000.slice/session-3.scope"},
			"spiffe://kelliher/node/spain/uid/1000", ""},
		{"a machine of another template keeps NodePolicy's uid identity",
			workload.Peer{PID: 30, UID: 1000, Cgroup: "/machine.slice/systemd-nspawn@shell0.service/payload",
				Machine: &workload.Machine{Template: "systemd-nspawn", Instance: "shell0", Payload: true, Registered: true}},
			"spiffe://kelliher/node/spain/uid/1000", ""},
	}
	if len(cases) < 20 {
		t.Fatalf("the contract table lost rows: %d", len(cases))
	}
	for _, c := range cases {
		id, err := p(c.peer)
		if c.want != "" {
			if err != nil || id.String() != c.want {
				t.Errorf("%s: got %q %v, want %s", c.desc, id, err, c.want)
			}
			if strings.Contains(id.String(), "-g1") || strings.Contains(id.String(), "-g2") {
				t.Errorf("%s: generation in the SAN: %s", c.desc, id)
			}
			continue
		}
		_, instance, _, _ := workload.MachineOf(c.peer.Cgroup)
		want := "unattested: sandbox " + instance + ": " + c.reason
		if !errors.Is(err, workload.ErrUnattested) || err.Error() != want || !id.IsZero() {
			t.Errorf("%s: got %q %v, want refusal %q", c.desc, id, err, want)
		}
	}
}

func TestMachineOfReadsOnlyMachineUnits(t *testing.T) {
	cases := []struct {
		cgroup, template, instance, rest string
		ok                               bool
	}{
		{boxA, "band-svc", "spool-captains-log-steward-g1", "payload/system.slice/figaro-box.service", true},
		{unitA, "band-svc", "spool-captains-log-steward-g1", "", true},
		{unitA + "/supervisor", "band-svc", "spool-captains-log-steward-g1", "supervisor", true},
		{"/system.slice/band-svc@spool-a-g1.service/payload", "", "", "", false},
		{"/machine.slice/machine-x.scope/payload", "", "", "", false},
		{"/machine.slice/band-svc.service/payload", "", "", "", false},
		{"/machine.slice/@x.service", "", "", "", false},
		{"/machine.slice/band-svc@.service", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		tm, in, rest, ok := workload.MachineOf(c.cgroup)
		if tm != c.template || in != c.instance || rest != c.rest || ok != c.ok {
			t.Errorf("%q: got (%q %q %q %v), want (%q %q %q %v)", c.cgroup, tm, in, rest, ok, c.template, c.instance, c.rest, c.ok)
		}
	}
}

// RED if LoadSandboxes stops refusing any of these maps.
func TestLoadSandboxesRefusesMapsThatCannotAttest(t *testing.T) {
	good := `{"template":"band-svc","base":1895825408,"size":65536,"machines":{"spool-a":{"id":"a","k":1}}}`
	cases := []struct {
		desc, body, err string
	}{
		{"control: a valid map loads", good, ""},
		{"an unknown field", `{"template":"band-svc","base":0,"size":1,"machines":{},"extra":1}`, "unknown field"},
		{"no template", `{"template":"","base":0,"size":1,"machines":{}}`, `sandboxes: template ""`},
		{"a template with @", `{"template":"band@svc","base":0,"size":1,"machines":{}}`, `sandboxes: template "band@svc"`},
		{"size 0", `{"template":"t","base":0,"size":0,"machines":{}}`, "sandboxes: size 0"},
		{"a name that ends in a generation", `{"template":"t","base":0,"size":1,"machines":{"spool-a-g1":{"id":"a","k":0}}}`, `sandboxes: machine name "spool-a-g1"`},
		{"two machines in one k", `{"template":"t","base":0,"size":1,"machines":{"a":{"id":"a","k":2},"b":{"id":"b","k":2}}}`, "share k=2"},
		{"a range past 2^32", `{"template":"t","base":4294901760,"size":65536,"machines":{"a":{"id":"a","k":1}}}`, "sandboxes: a: range k=1 overflows"},
		{"not json", `nope`, "invalid character"},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "machines.json")
		if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := workload.LoadSandboxes(path)
		if c.err == "" {
			if err != nil || s.Machines["spool-a"].K != 1 || s.Size != 65536 || s.Base != 0x71000000 {
				t.Errorf("%s: %+v %v", c.desc, s, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: got %v, want an error containing %q", c.desc, err, c.err)
		}
	}
}
