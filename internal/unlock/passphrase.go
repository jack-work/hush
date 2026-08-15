package unlock

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/term"
)

// passphraseUnlocker prompts the user on the controlling terminal.
// This is the historical default — `hush up` and `hush up -d` both
// landed here before the resolver existed.
//
// The prompt is written to stderr (the input is read from stdin's fd)
// so the unlocker composes cleanly with command pipelines that capture
// stdout. Echo is disabled via golang.org/x/term.
type passphraseUnlocker struct{}

func (passphraseUnlocker) Passphrase(_ context.Context) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf(
			"unlock method 'passphrase' requires a controlling terminal; " +
				"none available (stdin is not a TTY)")
	}
	fmt.Fprint(os.Stderr, "Enter passphrase for hush identity: ")
	pp, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return pp, nil
}
