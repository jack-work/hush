package workload

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/jack-work/hush/spiffeid"
)

// Machine is what the attestor read about a peer whose cgroup lies in a systemd-nspawn machine's unit
// (/machine.slice/<template>@<instance>.service/...). The policy decides; the attestor only reads.
type Machine struct {
	Template   string   // the unit template, e.g. pool-svc
	Instance   string   // the unit instance, e.g. spool-a-g1
	Payload    bool     // the peer's cgroup is under <unit>/payload/ (never supervisor or .control)
	Registered bool     // systemd-machined holds machine <instance> whose unit is <template>@<instance>.service
	UIDMap     string   // the machine leader's /proc/<leader>/uid_map, as read
	UIDs       []uint32 // the uid of every live process under <unit>/payload/
}

// MachineOf parses a cgroup path in a machine unit: /machine.slice/<template>@<instance>.service/<rest>.
func MachineOf(cgroup string) (template, instance, rest string, ok bool) {
	tail, ok := strings.CutPrefix(cgroup, "/machine.slice/")
	if !ok {
		return "", "", "", false
	}
	unit, rest, _ := strings.Cut(tail, "/")
	name, ok := strings.CutSuffix(unit, ".service")
	if !ok {
		return "", "", "", false
	}
	template, instance, ok = strings.Cut(name, "@")
	if !ok || template == "" || instance == "" {
		return "", "", "", false
	}
	return template, instance, rest, true
}

// Sandboxes is the machine policy's configuration: which machine units are sandboxes, and the fixed user-namespace
// range each must run in (range k = [Base + k*Size, Base + (k+1)*Size)).
type Sandboxes struct {
	Template string          `json:"template"`
	Base     uint32          `json:"base"`
	Size     uint32          `json:"size"`
	Machines map[string]Slot `json:"machines"` // keyed by the instance without its -g<generation>
}

type Slot struct {
	ID string `json:"id"`
	K  uint32 `json:"k"`
}

// LoadSandboxes reads a Sandboxes file and refuses one that could never attest anything correctly.
func LoadSandboxes(path string) (Sandboxes, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Sandboxes{}, err
	}
	var s Sandboxes
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Sandboxes{}, fmt.Errorf("sandboxes %s: %w", path, err)
	}
	return s, s.valid()
}

func (s Sandboxes) valid() error {
	if s.Template == "" || strings.ContainsAny(s.Template, "@/") {
		return fmt.Errorf("sandboxes: template %q", s.Template)
	}
	if s.Size == 0 {
		return errors.New("sandboxes: size 0")
	}
	seen := map[uint32]string{}
	for name, slot := range s.Machines {
		if _, _, ok := stripGeneration(name + "-g1"); !ok || generation.MatchString(name) {
			return fmt.Errorf("sandboxes: machine name %q", name)
		}
		if uint64(s.Base)+(uint64(slot.K)+1)*uint64(s.Size) > 1<<32 { // k+1 in 64 bits: uint32 2^32-1 + 1 wraps to 0
			return fmt.Errorf("sandboxes: %s: range k=%d overflows", name, slot.K)
		}
		if other, dup := seen[slot.K]; dup {
			return fmt.Errorf("sandboxes: %s and %s share k=%d", other, name, slot.K)
		}
		seen[slot.K] = name
	}
	return nil
}

var generation = regexp.MustCompile(`-g[0-9]+$`)

// stripGeneration drops the trailing -g<generation> of a machine instance: spool-a-g2 is spool-a.
func stripGeneration(instance string) (name, gen string, ok bool) {
	loc := generation.FindStringIndex(instance)
	if loc == nil || loc[0] == 0 {
		return "", "", false
	}
	return instance[:loc[0]], instance[loc[0]+2:], true
}

// MachinePolicy is NodePolicy plus sandbox identities: a peer in the payload of a registered sandbox machine, every
// payload uid inside the sandbox's fixed range, gets /node/<node>/unit/<template>.service/<instance without -g<gen>>.
// A peer in a machine unit of the sandbox template that fails any rule is REFUSED, never given a uid identity.
// Peers outside that template are NodePolicy's.
func MachinePolicy(td, node string, s Sandboxes) Policy {
	host := NodePolicy(td, node)
	return func(p Peer) (spiffeid.ID, error) {
		template, instance, _, ok := MachineOf(p.Cgroup)
		if !ok || template != s.Template {
			return host(p)
		}
		refuse := func(why string, args ...any) (spiffeid.ID, error) {
			return spiffeid.ID{}, fmt.Errorf("%w: sandbox %s: %s", ErrUnattested, instance, fmt.Sprintf(why, args...))
		}
		m := p.Machine
		if m == nil || m.Template != template || m.Instance != instance {
			return refuse("no machine facts")
		}
		name, _, ok := stripGeneration(instance)
		if !ok {
			return refuse("instance has no -g<generation>")
		}
		if !m.Payload {
			return refuse("not in the payload")
		}
		if !m.Registered {
			return refuse("not registered with machined")
		}
		slot, ok := s.Machines[name]
		if !ok {
			return refuse("not in the sandbox map")
		}
		lo := s.Base + slot.K*s.Size
		if m.UIDMap != fmt.Sprintf("0 %d %d", lo, s.Size) {
			return refuse("user namespace %q is not range k=%d", m.UIDMap, slot.K)
		}
		in := func(uid uint32) bool { return uid >= lo && uid-lo < s.Size }
		if !in(p.UID) {
			return refuse("uid %d outside the range", p.UID)
		}
		if len(m.UIDs) == 0 {
			return refuse("no payload process read")
		}
		for _, uid := range m.UIDs {
			if !in(uid) {
				return refuse("payload runs host uid %d (mixed)", uid)
			}
		}
		return spiffeid.New(td, "node", node, "unit", template+".service", name)
	}
}

// parseUIDMap normalises one uid_map line ("0 1895890944 65536", padded by the kernel) to single spaces;
// more than one line is returned joined by ";" so it can never equal a single-range expectation.
func parseUIDMap(raw string) string {
	var lines []string
	for line := range strings.SplitSeq(strings.TrimSpace(raw), "\n") {
		f := strings.Fields(line)
		for i := range f {
			if _, err := strconv.ParseUint(f[i], 10, 32); err != nil {
				return "unparsable"
			}
		}
		lines = append(lines, strings.Join(f, " "))
	}
	return strings.Join(lines, ";")
}
