//go:build windows

package singleton

import (
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/windows"
)

// LockFileEx is mandatory on Windows, not advisory: a locked byte range
// blocks reads and writes from every handle, including the holder's own
// unrelated readers. `hush down` reads the pid at offset 0, so the lock
// region is placed at a high, fixed offset that no real file content
// ever occupies. Locking beyond EOF is allowed and is the standard
// single-instance trick (SQLite, boltdb do the same).
const (
	lockOffsetLow  = 0
	lockOffsetHigh = 0x80000000
	lockBytes      = 1
)

func acquire(path string, pid int) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	ol := &windows.Overlapped{Offset: lockOffsetLow, OffsetHigh: lockOffsetHigh}
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, lockBytes, 0, ol,
	)
	if err != nil {
		f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, ErrHeld
		}
		return nil, err
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(pid)), 0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func free(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	defer f.Close()
	ol := &windows.Overlapped{Offset: lockOffsetLow, OffsetHigh: lockOffsetHigh}
	// Shared, non-blocking probe: fails iff an exclusive lock is held.
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, lockBytes, 0, ol,
	)
	if err != nil {
		return false, nil
	}
	windows.UnlockFileEx(windows.Handle(f.Fd()), 0, lockBytes, 0, ol)
	return true, nil
}
