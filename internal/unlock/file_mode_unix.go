//go:build !windows

package unlock

import (
	"fmt"
	"io/fs"
)

// checkFileMode refuses anything a second account could read. 0600 and
// 0400 pass; 0640 does not, and neither does 0644, which is what a file
// created by a careless `echo > passphrase` under a permissive umask
// looks like. The error names the path and the mode because "permission
// denied" with neither is the least actionable message in computing.
func checkFileMode(path string, mode fs.FileMode) error {
	if perm := mode.Perm(); perm&0o077 != 0 {
		return fmt.Errorf("unlock file %s has mode %#o: it must not be readable by group or other, run: chmod 600 %s", path, perm, path)
	}
	return nil
}
