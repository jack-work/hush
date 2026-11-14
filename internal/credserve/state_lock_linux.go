package credserve

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func LockState(dir string) (*os.File, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&0077 != 0 {
		return nil, errors.New("credential state directory must be private")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("credential state directory must belong to this owner")
	}
	path := filepath.Join(dir, ".credential-owner.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("credential owner lock unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0077 != 0 || st.Nlink != 1 {
		f.Close()
		return nil, errors.New("unsafe credential owner lock")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errors.New("credential state already has an owner; stop that owner before login or replacement")
	}
	return f, nil
}
