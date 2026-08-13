//go:build windows

package cmd

import (
	"os/exec"
	"path/filepath"
)

// commandScriptNames lists candidate command-script filenames in priority
// order for `hush run`: PowerShell first, then cmd, then a POSIX script
// (runnable if Git Bash's sh is on PATH).
func commandScriptNames() []string {
	return []string{"command.ps1", "command.cmd", "command.sh"}
}

// shellCommand builds the process that runs a rendered command script,
// choosing the interpreter by the script's extension. The rendered text
// (which contains decrypted secrets) is passed as an argument, never
// written to disk, matching the Unix sh -c posture. PowerShell handles a
// multi-line -Command argument fine; cmd is best kept to single commands.
//
// Positional args ($0, $1 …) are only wired up for the POSIX .sh path,
// where the semantics match Unix. PowerShell's -Command and cmd's /C have
// no equivalent positional convention, so .ps1 and .cmd scripts continue
// to read extra args through the {{.Args}} template accessor.
func shellCommand(rendered, scriptName, argv0 string, args []string) *exec.Cmd {
	switch filepath.Ext(scriptName) {
	case ".ps1":
		ps := "powershell.exe"
		if p, err := exec.LookPath("pwsh"); err == nil {
			ps = p
		}
		return exec.Command(ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", rendered)
	case ".sh":
		sh := append([]string{"-c", rendered, argv0}, args...)
		return exec.Command("sh", sh...)
	default: // .cmd and anything else
		return exec.Command("cmd.exe", "/C", rendered)
	}
}

// defaultEditor is the fallback for `hush edit` when $EDITOR is unset.
// notepad is always present and needs no PATH setup, unlike vi.
func defaultEditor() string {
	return "notepad"
}
