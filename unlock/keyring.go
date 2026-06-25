package unlock

import (
	"context"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

// keyringUnlocker fetches the passphrase from the OS keyring via
// zalando/go-keyring, which abstracts over libsecret (Linux), the
// macOS Keychain, and Windows Credential Manager. Pure-Go on Windows,
// thin cgo elsewhere.
//
// The (Service, Account) pair identifies the entry; both fields are
// configured under [unlock.keyring] and default to ("hush", "default")
// at config-load time. A dev shell sets HUSH_KEYRING_SERVICE to
// namespace per-shell entries — see flake.nix.
type keyringUnlocker struct {
	service string
	account string
}

// ErrKeyringEntryMissing is returned (wrapped) when the configured
// (service, account) pair has no value in the keyring. Callers
// distinguish this from other keyring errors so they can guide the
// user toward `hush keyring set` instead of bailing with a stack trace.
var ErrKeyringEntryMissing = errors.New("keyring entry not found")

func (u *keyringUnlocker) Passphrase(_ context.Context) ([]byte, error) {
	if u.service == "" {
		return nil, fmt.Errorf("unlock method 'keyring' requires unlock.keyring.service")
	}
	if u.account == "" {
		return nil, fmt.Errorf("unlock method 'keyring' requires unlock.keyring.account")
	}
	v, err := keyring.Get(u.service, u.account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, fmt.Errorf(
				"%w: service=%q account=%q (seed it with `hush keyring set`)",
				ErrKeyringEntryMissing, u.service, u.account)
		}
		return nil, fmt.Errorf("keyring lookup (service=%q account=%q): %w",
			u.service, u.account, err)
	}
	if v == "" {
		return nil, fmt.Errorf(
			"keyring entry is empty (service=%q account=%q)", u.service, u.account)
	}
	// go-keyring returns a string; the underlying bytes are immutable
	// to us. Copy to a slice the caller can wipe.
	return []byte(v), nil
}
