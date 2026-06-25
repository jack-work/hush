package unlock

import (
	"context"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/jack-work/hush/config"
)

func autoCfg(svc, acct string) config.UnlockConfig {
	return config.UnlockConfig{
		Method: "auto",
		Keyring: config.KeyringConfig{
			Service: svc,
			Account: acct,
		},
	}
}

func TestAutoUnlocker_KeyringHitIsSilent(t *testing.T) {
	const svc, acct, pp = "hush-auto-test-hit", "default", "stored-pass"
	if err := keyring.Set(svc, acct, pp); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete(svc, acct) })

	u, err := New(autoCfg(svc, acct))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(got) != pp {
		t.Fatalf("got %q, want %q", got, pp)
	}
}

func TestAutoUnlocker_EmptyServiceErrors(t *testing.T) {
	u, _ := New(autoCfg("", "default"))
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty service")
	}
}

func TestAutoUnlocker_EmptyAccountErrors(t *testing.T) {
	u, _ := New(autoCfg("svc", ""))
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty account")
	}
}

// We can't easily exercise the "miss → prompt → store" path in a unit
// test because the inner TTY prompt is gated by term.IsTerminal. The
// path is covered manually via `hush up` in a clean dev shell. The
// inverse — keyring unreachable → TTY fallback — is similarly TTY-gated.
