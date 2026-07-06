//go:build !windows

package cmd

import "os/exec"

// commandScriptNames lists candidate command-script filenames in priority
// order for `hush run`.
func commandScriptNames() []string {
	return []string{"command.sh"}
}

// shellCommand builds the process that runs a rendered command script.
// The rendered text (which contains decrypted secrets) is passed as an
// argument rather than written to disk. scriptName is unused on Unix.
func shellCommand(rendered, scriptName string) *exec.Cmd {
	return exec.Command("sh", "-c", rendered)
}

// defaultEditor is the fallback for `hush edit` when $EDITOR is unset.
func defaultEditor() string {
	return "vi"
}
