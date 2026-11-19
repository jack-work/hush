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
		mixed = !unitRunsAs(dir, cred.Uid)
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil && !errors.Is(err, unix.EPERM) {
		return Peer{}, fmt.Errorf("%w: the peer exited while it was read: %v", ErrUnattested, err)
	}
	return Peer{PID: pid, UID: cred.Uid, Cgroup: cg, Mixed: mixed}, nil
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

func unitRunsAs(dir string, uid uint32) bool {
	root := filepath.Join("/sys/fs/cgroup", dir)
	ok := true
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
			owner, err := uidOf(f)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil || owner != uid {
				ok = false
				return fs.SkipAll
			}
		}
		return nil
	})
	return ok && err == nil
}

func uidOf(pid string) (uint32, error) {
	raw, err := os.ReadFile("/proc/" + pid + "/status")
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
