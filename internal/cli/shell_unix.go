//go:build !windows

package cli

import "os/exec"

// commandScriptNames lists candidate command-script filenames in priority
// order for `hush run`.
func commandScriptNames() []string {
	return []string{"command.sh"}
}

// shellCommand builds the process that runs a rendered command script.
// The rendered text (which contains decrypted secrets) is passed as an
// argument rather than written to disk. scriptName is unused on Unix.
//
// argv0 and args land after the script text, so the script sees them as
// $0, $1, $2 … and can use "$@" naturally.
func shellCommand(rendered, scriptName, argv0 string, args []string) *exec.Cmd {
	sh := append([]string{"-c", rendered, argv0}, args...)
	return exec.Command("sh", sh...)
}
