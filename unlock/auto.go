package unlock

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

// autoUnlocker is the friction-free default. It tries the OS keyring
// first; if no entry exists, prompts on TTY, stores the answer in the
// keyring, returns it. Subsequent invocations are silent.
//
// If the keyring is unavailable (no Secret Service on Linux, dbus
// missing, headless box) the backend falls back to a plain TTY prompt
// every startup and prints a one-time hint about installing a keyring
// provider or selecting a different unlock method.
//
// The (service, account) pair comes from [unlock.keyring] in hush.toml
// (defaults: <app>/default at the config layer). When the embedded
// managed mode is in play, the service is typically the consuming app's
// name, so figaro's keyring entry is independent of, say, gws's.
type autoUnlocker struct {
	service string
	account string
}

func (u *autoUnlocker) Passphrase(ctx context.Context) ([]byte, error) {
	if u.service == "" || u.account == "" {
		return nil, fmt.Errorf("unlock method 'auto' requires non-empty service and account")
	}

	// 1. Try keyring read.
	v, err := keyring.Get(u.service, u.account)
	switch {
	case err == nil && v != "":
		// Cached. Silent path.
		return []byte(v), nil

	case errors.Is(err, keyring.ErrNotFound):
		// Keyring is reachable but has no entry yet. Prompt once,
		// store it for next time, return it.
		return u.bootstrapViaKeyring(ctx)

	default:
		// Other keyring errors (no provider, dbus broken, etc.) ->
		// TTY-only fallback with a single hint.
		printKeyringUnavailableOnce(err)
		return (&passphraseUnlocker{}).Passphrase(ctx)
	}
}

// bootstrapViaKeyring prompts the user for a passphrase on TTY, stores
// it in the keyring, and returns it. Used on first-run when the
// keyring is reachable but empty.
func (u *autoUnlocker) bootstrapViaKeyring(ctx context.Context) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "[hush] no passphrase saved for %q yet — prompting once, then saving to your OS keyring.\n", u.service)
	pp, err := (&passphraseUnlocker{}).Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	if err := keyring.Set(u.service, u.account, string(pp)); err != nil {
		// Don't fail the unlock just because the cache write failed —
		// the user can still proceed; we just won't be silent next time.
		fmt.Fprintf(os.Stderr, "[hush] warning: couldn't save passphrase to keyring (%v). You'll be prompted again next startup.\n", err)
		return pp, nil
	}
	fmt.Fprintf(os.Stderr, "[hush] saved to keyring — future startups will be silent.\n")
	return pp, nil
}

// keyringUnavailableHinted ensures the "no keyring" hint prints only
// once per process. Important because the same backend may be invoked
// multiple times in some flows (e.g. lazy re-unlock after TTL).
var keyringUnavailableHinted = false

func printKeyringUnavailableOnce(err error) {
	if keyringUnavailableHinted {
		return
	}
	keyringUnavailableHinted = true
	fmt.Fprintf(os.Stderr, "[hush] no OS keyring available (%v). You'll be prompted for the passphrase on each startup.\n", err)
	fmt.Fprintln(os.Stderr, "[hush] To fix on Linux: install gnome-keyring or KWallet. Or set unlock.method = \"exec\" in hush.toml to use `pass`/`rbw`/etc.")
}
