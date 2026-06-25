package unlock

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// execUnlocker runs an external command and reads the passphrase from
// its stdout. The command is the user's responsibility — anything from
// `pass show hush/passphrase` to a custom shim that talks to a corporate
// secrets API. Stderr is propagated so password-manager prompts (e.g.
// `op` asking for biometric unlock) reach the user.
//
// One trailing newline (LF or CRLF) is stripped from the captured
// output, matching what most CLIs emit. The rest is returned verbatim.
// We deliberately do NOT trim other whitespace: a passphrase that
// genuinely contains a leading space or tab is the user's prerogative.
type execUnlocker struct {
	// argv must be non-empty. argv[0] is the executable; the remainder
	// are arguments. We don't shell-parse — argv comes from a typed TOML
	// array, so quoting and word-splitting are the user's concern at
	// config-write time, not ours at exec time.
	argv []string
}

func (u *execUnlocker) Passphrase(ctx context.Context) ([]byte, error) {
	if len(u.argv) == 0 {
		return nil, fmt.Errorf("unlock method 'exec' requires unlock.exec to be a non-empty argv array")
	}
	cmd := exec.CommandContext(ctx, u.argv[0], u.argv[1:]...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// Stderr is left attached to the calling process so the user sees
	// any interactive prompt the helper might raise (1Password biometric,
	// pass GPG passphrase, ssh-askpass, ...).
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exec %q: %w", u.argv[0], err)
	}
	out := stdout.Bytes()
	// Strip exactly one trailing newline. CRLF first, then LF.
	if n := len(out); n >= 2 && out[n-2] == '\r' && out[n-1] == '\n' {
		out = out[:n-2]
	} else if n := len(out); n >= 1 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("exec %q produced an empty passphrase", u.argv[0])
	}
	return out, nil
}
