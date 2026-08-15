//go:build !windows

package agent

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

// listenFdsStart is the first descriptor a service manager passes to an
// activated service (systemd's sd_listen_fds(3) protocol reserves 0-2 for
// stdio). It is a var, not a const, only so tests can point the adoption
// path at a descriptor they control: a Go process cannot safely clobber
// fd 3, which the runtime may already own (netpoll's epoll fd lives down
// there). Nothing outside tests writes it.
var listenFdsStart = 3

// inheritedListener returns the listening socket handed to this process by
// the service manager, or (nil, nil) when there is none — meaning "bind it
// yourself", the path `hush up -d` has always taken.
//
// The contract is systemd's, and it is deliberately narrow:
//
//	LISTEN_PID must equal our pid. systemd sets it after fork so the
//	claim cannot be inherited by a child; a mismatch means the fds are
//	someone else's and we must ignore them rather than adopt a stranger's
//	descriptor.
//
//	LISTEN_FDS must be exactly 1. hush's socket unit declares one
//	ListenStream; any other count is a misconfiguration worth failing
//	loudly for, not guessing at.
//
// When the claim is ours the variables are unset, again per the protocol:
// the agent re-execs nothing today, but a leaked LISTEN_PID that happens
// to match a future child's pid is the kind of bug that takes a week.
func inheritedListener() (net.Listener, error) {
	pidStr, fdsStr := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	if pidStr == "" || fdsStr == "" {
		return nil, nil
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid != os.Getpid() {
		// Not addressed to us. Silence is correct: plenty of processes
		// are started by a manager that activated something else.
		return nil, nil
	}

	n, err := strconv.Atoi(fdsStr)
	if err != nil {
		return nil, fmt.Errorf("socket activation: LISTEN_FDS=%q is not a number", fdsStr)
	}
	switch {
	case n == 0:
		return nil, nil
	case n > 1:
		return nil, fmt.Errorf("socket activation: got %d descriptors, hush expects exactly 1", n)
	}

	clearActivationEnv()

	fd := listenFdsStart
	syscall.CloseOnExec(fd)

	// os.NewFile takes ownership of fd; net.FileListener dups it, so the
	// original is closed here and the listener owns the survivor.
	f := os.NewFile(uintptr(fd), "hush-agent.socket")
	if f == nil {
		return nil, fmt.Errorf("socket activation: fd %d is not open", fd)
	}
	ln, err := net.FileListener(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("socket activation: adopt fd %d: %w", fd, err)
	}
	if _, ok := ln.(*net.UnixListener); !ok {
		ln.Close()
		return nil, fmt.Errorf("socket activation: fd %d is a %T, want a unix socket", fd, ln)
	}

	// A listener built from an inherited descriptor does not unlink its
	// path on Close (net/file_unix.go), which is exactly what we want:
	// the socket node belongs to the service manager, and it re-arms on
	// it after we exit.
	return ln, nil
}

func clearActivationEnv() {
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		os.Unsetenv(k)
	}
}
