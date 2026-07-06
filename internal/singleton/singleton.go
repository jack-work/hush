// Package singleton provides a process-lifetime single-instance lock
// backed by an advisory lock on a pid file. Acquiring the lock is the
// claim: there is no window between checking for a live holder and
// becoming one, and the OS releases the lock when the process exits,
// however it exits.
//
// The pid file is never unlinked by design. On Unix the flock attaches
// to the inode, so removing the file would let a second holder lock a
// fresh inode at the same path. On Windows the byte-range lock attaches
// to the handle with the same hazard. The file's contents (the holder's
// pid) are informational only, for `hush down` and humans.
package singleton

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

// ErrHeld is returned (wrapped) by Acquire when another process already
// holds the lock. Callers use errors.Is to distinguish a live sibling
// from a genuine filesystem error.
var ErrHeld = errors.New("single-instance lock already held")

// Lock is a held single-instance lock. Release drops it; the pid file
// stays in place.
type Lock struct {
	f *os.File
}

// Acquire takes an exclusive, non-blocking lock on path, creating the
// file if needed, and records pid as its contents. It returns a Lock
// wrapping ErrHeld if another process holds the lock.
func Acquire(path string, pid int) (*Lock, error) {
	f, err := acquire(path, pid)
	if err != nil {
		return nil, err
	}
	return &Lock{f: f}, nil
}

// Release drops the lock. The pid file is left in place (it is the lock
// inode/handle). Safe to call on a nil or already-released Lock.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// Free reports whether the exclusive lock at path is currently
// available: true if no live holder (or the file does not exist),
// false if a holder is present. It does not keep the lock.
func Free(path string) (bool, error) {
	return free(path)
}

// Holder reads the pid recorded in the lock file. Best-effort and
// informational: the value is only meaningful while a holder is alive.
func Holder(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}
