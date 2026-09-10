package unlock

import (
	"context"
	"fmt"
	"os"
)

// fileUnlocker reads the passphrase out of a file the user owns. It is
// the exec backend minus the subprocess: where `exec = ["cat", path]`
// would fork a shell helper to do nothing but read bytes, this reads
// the bytes. The difference that matters is that we can see the file's
// mode before trusting it, which a helper's stdout cannot tell us.
//
// One trailing newline (LF or CRLF) is stripped, matching exec, so a
// passphrase written with `echo` or an editor that insists on a final
// newline works. No other whitespace is touched.
//
// This is the method for a host where no Secret Service can be reached
// and nobody is at the terminal to type: WSL, a container, a headless
// box. The security claim is exactly the file's mode plus whatever
// protects the home directory, and no more. Say so when you offer it.
type fileUnlocker struct {
	path string
}

func (u *fileUnlocker) Passphrase(ctx context.Context) ([]byte, error) {
	if u.path == "" {
		return nil, fmt.Errorf("unlock method 'file' requires unlock.file to name a path")
	}
	fi, err := os.Stat(u.path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("unlock file %s does not exist: write the passphrase to it with mode 0600, or change unlock.method in hush.toml", u.path)
	}
	if err != nil {
		return nil, fmt.Errorf("unlock file %s: %w", u.path, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("unlock file %s is a directory", u.path)
	}
	if err := checkFileMode(u.path, fi.Mode()); err != nil {
		return nil, err
	}
	out, err := os.ReadFile(u.path)
	if err != nil {
		return nil, fmt.Errorf("read unlock file %s: %w", u.path, err)
	}
	out = stripOneNewline(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("unlock file %s is empty", u.path)
	}
	return out, nil
}

// stripOneNewline removes exactly one trailing line ending, CRLF before
// LF. Shared with the exec backend's contract on purpose: two ways to
// supply a passphrase that disagreed about the final byte would be a
// trap nobody could debug.
func stripOneNewline(b []byte) []byte {
	if n := len(b); n >= 2 && b[n-2] == '\r' && b[n-1] == '\n' {
		return b[:n-2]
	}
	if n := len(b); n >= 1 && b[n-1] == '\n' {
		return b[:n-1]
	}
	return b
}
