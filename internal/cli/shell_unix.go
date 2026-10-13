//go:build !windows

package cli

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// commandScriptNames lists candidate command-script filenames in priority
// order for `hush run`.
func commandScriptNames() []string {
	return []string{"command.sh"}
}

// scriptFD is the child file descriptor the rendered script is handed on.
// 0/1/2 are the standard streams, so ExtraFiles[0] lands on 3.
const scriptFD = 3

// shellCommand builds the process that runs a rendered command script.
//
// The rendered text may contain decrypted secrets, so it is passed on an
// anonymous file descriptor rather than as an argument. This matters: argv
// is exposed through /proc/<pid>/cmdline, which is mode 444: world
// readable by every user and every process on the box, for as long as the
// command runs. A memfd has no path, never touches a filesystem, is not
// visible in /proc/<pid>/cmdline, and dies with the process.
//
// argv0 is accepted for signature compatibility with the Windows path but
// is not used here: with `sh <script> a b`, $0 is the script itself and
// cannot be set, so passing a name would shift every positional parameter
// by one. Caller arguments therefore land on $1, $2 … and "$@" exactly as a
// script expects, which is the property that matters.
//
// The returned cleanup closes the descriptor and must be called once the
// child has finished.
func shellCommand(rendered, scriptName, argv0 string, args []string) (*exec.Cmd, func(), error) {
	f, err := scriptFile(rendered)
	if err != nil {
		return nil, func() {}, err
	}
	// /dev/fd/N is the portable spelling of /proc/self/fd/N; sh opens it and
	// reads the script from there.
	argv := append([]string{fmt.Sprintf("/dev/fd/%d", scriptFD)}, args...)
	cmd := exec.Command("sh", argv...)
	cmd.ExtraFiles = []*os.File{f}
	return cmd, func() { f.Close() }, nil
}

// scriptFile puts the rendered script somewhere the child can read it and
// the rest of the system cannot see it.
//
// Preferred: an anonymous in-memory file (memfd_create), which has no name
// in any namespace. Fallback for kernels and platforms without memfd: a
// temp file unlinked immediately after creation, so it has no reachable
// path either: weaker only in that its bytes may touch a filesystem.
func scriptFile(content string) (*os.File, error) {
	if fd, err := unix.MemfdCreate("hush-script", unix.MFD_CLOEXEC); err == nil {
		f := os.NewFile(uintptr(fd), "hush-script")
		if err := writeScript(f, content); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	}

	f, err := os.CreateTemp("", "hush-script-")
	if err != nil {
		return nil, fmt.Errorf("stage script: %w", err)
	}
	// Unlink now: the descriptor stays valid, the path does not exist.
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, fmt.Errorf("unlink staged script: %w", err)
	}
	if err := writeScript(f, content); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func writeScript(f *os.File, content string) error {
	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("write script: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind script: %w", err)
	}
	return nil
}
