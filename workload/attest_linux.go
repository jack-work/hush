//go:build linux

package workload

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const soPeerPidfd = 77

func PeerAttestor(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("%w: not a unix socket", ErrUnattested)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("%w: %v", ErrUnattested, err)
	}
	var cred *unix.Ucred
	pidfd := -1
	var sockErr, fdErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		pidfd, fdErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, soPeerPidfd)
	}); err != nil {
		return Peer{}, fmt.Errorf("%w: %v", ErrUnattested, err)
	}
	if sockErr != nil {
		return Peer{}, fmt.Errorf("%w: peer credentials: %v", ErrUnattested, sockErr)
	}
	if fdErr != nil || pidfd < 0 {
		return Peer{}, fmt.Errorf("%w: no peer pidfd (Linux 6.5 or later): %v", ErrUnattested, fdErr)
	}
	defer unix.Close(pidfd)
	pid, err := pidfdPID(pidfd)
	if err != nil {
		return Peer{}, err
	}
	if pid != int(cred.Pid) {
		return Peer{}, fmt.Errorf("%w: pidfd names pid %d, credentials %d", ErrUnattested, pid, cred.Pid)
	}
	cg, err := cgroupOf(pid)
	if err != nil {
		return Peer{}, err
	}
	mixed := false
	if _, dir, ok := UnitOf(cg); ok {
		mixed = !hostRoots.unitRunsAs(dir, cred.Uid)
	}
	var machine *Machine
	if t, inst, rest, ok := MachineOf(cg); ok {
		machine = hostRoots.readMachine(machinedRegistry, t, inst, rest)
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil && !errors.Is(err, unix.EPERM) {
		return Peer{}, fmt.Errorf("%w: the peer exited while it was read: %v", ErrUnattested, err)
	}
	return Peer{PID: pid, UID: cred.Uid, Cgroup: cg, Mixed: mixed, Machine: machine}, nil
}

// roots are where the attestor reads the kernel's views; tests point them at a fixture tree.
type roots struct{ proc, cgroup string }

var hostRoots = roots{proc: "/proc", cgroup: "/sys/fs/cgroup"}

// Registry answers, for a machine name, the unit and leader pid systemd-machined registered for it.
type Registry func(name string) (unit string, leader uint32, err error)

// readMachine gathers the facts MachinePolicy decides on. A fact it cannot read stays at its refusing zero value.
func (r roots) readMachine(reg Registry, template, instance, rest string) *Machine {
	unit := template + "@" + instance + ".service"
	m := &Machine{Template: template, Instance: instance}
	m.Payload = rest == "payload" || strings.HasPrefix(rest, "payload/")
	regUnit, leader, err := reg(instance)
	m.Registered = err == nil && regUnit == unit && leader > 0
	if !m.Registered {
		return m
	}
	if raw, err := os.ReadFile(filepath.Join(r.proc, strconv.FormatUint(uint64(leader), 10), "uid_map")); err == nil {
		m.UIDMap = parseUIDMap(string(raw))
	}
	if uids, err := r.uidsUnder(filepath.Join("/machine.slice", unit, "payload")); err == nil {
		m.UIDs = uids // a partial walk could miss a mixed process: on any error, no uids (the policy refuses)
	}
	return m
}

// uidsUnder lists the uid of every live process in a cgroup subtree (a process that exits mid-walk is skipped).
func (r roots) uidsUnder(dir string) ([]uint32, error) {
	var uids []uint32
	err := filepath.WalkDir(filepath.Join(r.cgroup, dir), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
		if err != nil {
			return err
		}
		for f := range strings.FieldsSeq(string(raw)) {
			owner, err := r.uidOf(f)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			uids = append(uids, owner)
		}
		return nil
	})
	return uids, err
}

func pidfdPID(pidfd int) (int, error) {
	f, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnattested, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || pid <= 0 {
				return 0, fmt.Errorf("%w: the peer has exited", ErrUnattested)
			}
			return pid, nil
		}
	}
	return 0, fmt.Errorf("%w: pidfd names no pid", ErrUnattested)
}

func cgroupOf(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnattested, err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p, nil
		}
	}
	return "", errors.Join(ErrUnattested, errors.New("no cgroup v2 path"))
}

func (r roots) unitRunsAs(dir string, uid uint32) bool {
	uids, err := r.uidsUnder(dir)
	if err != nil {
		return false
	}
	for _, u := range uids {
		if u != uid {
			return false
		}
	}
	return true
}

func (r roots) uidOf(pid string) (uint32, error) {
	raw, err := os.ReadFile(filepath.Join(r.proc, pid, "status"))
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(v)
			if len(f) < 2 {
				break
			}
			n, err := strconv.ParseUint(f[1], 10, 32)
			return uint32(n), err
		}
	}
	return 0, errors.New("no Uid line")
}
