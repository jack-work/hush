//go:build windows

package unlock

import "io/fs"

// Windows has no POSIX mode bits: os.Stat synthesizes 0666 (or 0444 for
// a read-only file) for every regular file, so the unix check would
// reject every path unconditionally. ACLs are the real access control
// here and reading them is out of scope, so we accept the file and let
// the caller's directory permissions carry the weight.
func checkFileMode(string, fs.FileMode) error { return nil }
