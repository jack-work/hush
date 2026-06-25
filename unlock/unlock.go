// Package unlock resolves the passphrase that decrypts the on-disk age
// identity at agent startup.
//
// Hush owns its own bootstrap by design: it's a secrets server in the
// Vault / 1Password Connect category, and the defining property of that
// category is that consuming applications don't know where secrets come
// from — they ask the server. The unlock-method choice lives here so
// every consumer (figaro, gws, brave, future things) gets the same UX
// for free.
//
// Today's backends are local-friendly: a TTY prompt (the default), the
// OS keyring (via the keyring sibling package), and a generic external
// command. Future work may add cluster-friendly methods (kubernetes
// service-account JWT, OIDC, AWS IAM) without touching the Unlocker
// interface or the call sites.
package unlock

import (
	"context"
	"fmt"

	"github.com/jack-work/hush/config"
)

// An Unlocker returns the passphrase bytes that decrypt the age
// identity. Callers are responsible for zeroing the returned slice as
// soon as the identity is unlocked.
//
// Implementations should respect ctx for cancellation and timeouts;
// the TTY backend, for example, will not honor cancellation while
// blocked on terminal input.
type Unlocker interface {
	// Passphrase returns the passphrase bytes. A typical caller looks
	// like:
	//
	//   pp, err := u.Passphrase(ctx)
	//   if err != nil { return err }
	//   id, err := identity.Unlock(file, pp)
	//   for i := range pp { pp[i] = 0 }
	//
	// The slice is allocated freshly per call; the Unlocker holds no
	// reference to it after returning.
	Passphrase(ctx context.Context) ([]byte, error)
}

// New constructs an Unlocker from the unlock section of the resolved
// hush config. An empty Method is treated as "passphrase" (TTY prompt),
// preserving today's default behavior.
//
// New does not perform any I/O; backends do their work in Passphrase.
// This makes it cheap to call from cmd.PersistentPreRun or library code
// that wants to validate config without actually unlocking.
func New(cfg config.UnlockConfig) (Unlocker, error) {
	switch cfg.Method {
	case "", "auto":
		return &autoUnlocker{
			service: cfg.Keyring.Service,
			account: cfg.Keyring.Account,
		}, nil
	case "passphrase":
		return &passphraseUnlocker{}, nil
	case "keyring":
		return &keyringUnlocker{
			service: cfg.Keyring.Service,
			account: cfg.Keyring.Account,
		}, nil
	case "exec":
		return &execUnlocker{argv: cfg.Exec}, nil
	default:
		return nil, fmt.Errorf("unknown unlock method %q (valid: auto, passphrase, keyring, exec)", cfg.Method)
	}
}
