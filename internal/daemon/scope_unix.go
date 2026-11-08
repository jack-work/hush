//go:build !windows

package daemon

import (
	"os"
	"path/filepath"
	"syscall"
)

func ownManagerSocket(socket string) bool {
	if !trustedManagerDir(filepath.Dir(socket), os.Getuid()) {
		return false
	}
	fi, err := os.Stat(socket)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

func trustedManagerDir(dir string, uid int) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid
}
