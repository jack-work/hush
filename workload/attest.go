package workload

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jack-work/hush/spiffeid"
)

var ErrUnattested = errors.New("unattested")

type Peer struct {
	PID    int
	UID    uint32
	Cgroup string
	Mixed  bool
}

type Attestor func(conn net.Conn) (Peer, error)

type Policy func(Peer) (spiffeid.ID, error)

func UnitOf(cgroup string) (unit, dir string, ok bool) {
	rest, ok := strings.CutPrefix(cgroup, "/system.slice/")
	if !ok {
		return "", "", false
	}
	dir = "/system.slice"
	for part := range strings.SplitSeq(rest, "/") {
		dir += "/" + part
		if strings.HasSuffix(part, ".slice") {
			continue
		}
		if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
			return part, dir, true
		}
		return "", "", false
	}
	return "", "", false
}

func NodePolicy(td, node string) Policy {
	return func(p Peer) (spiffeid.ID, error) {
		if unit, _, ok := UnitOf(p.Cgroup); ok && !p.Mixed {
			if id, err := spiffeid.New(td, append([]string{"node", node, "unit"}, unitSegments(unit)...)...); err == nil {
				return id, nil
			}
		}
		if p.Cgroup == "" && p.PID == 0 {
			return spiffeid.ID{}, fmt.Errorf("%w: no peer", ErrUnattested)
		}
		return spiffeid.New(td, "node", node, "uid", fmt.Sprint(p.UID))
	}
}

func unitSegments(unit string) []string {
	name, suffix, ok := strings.Cut(unit, "@")
	if !ok {
		return []string{unit}
	}
	dot := strings.LastIndex(suffix, ".")
	if dot < 0 {
		return []string{unit}
	}
	return []string{name + suffix[dot:], suffix[:dot]}
}
