package unlock

import (
	"context"
	"errors"
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

	u, err := New(autoCfg(svc, acct), Hooks{})
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
	u, _ := New(autoCfg("", "default"), Hooks{})
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty service")
	}
}

func TestAutoUnlocker_EmptyAccountErrors(t *testing.T) {
	u, _ := New(autoCfg("svc", ""), Hooks{})
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty account")
	}
}

// verifyOnly accepts exactly one passphrase.
func verifyOnly(want string) func([]byte) error {
	return func(pp []byte) error {
		if string(pp) != want {
			return errors.New("incorrect passphrase")
		}
		return nil
	}
}

func promptWith(pp string) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) { return []byte(pp), nil }
}

func TestAutoUnlocker_MissPromptsVerifiesStores(t *testing.T) {
	const svc, acct = "hush-auto-test-miss", "default"
	_ = keyring.Delete(svc, acct)
	t.Cleanup(func() { _ = keyring.Delete(svc, acct) })

	u, _ := New(autoCfg(svc, acct), Hooks{
		Verify: verifyOnly("good"),
		Prompt: promptWith("good"),
	})
	got, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(got) != "good" {
		t.Fatalf("got %q, want %q", got, "good")
	}
	if v, err := keyring.Get(svc, acct); err != nil || v != "good" {
		t.Fatalf("keyring after store: %q, %v", v, err)
	}
}

func TestAutoUnlocker_UnverifiedPromptIsNotPersisted(t *testing.T) {
	const svc, acct = "hush-auto-test-junk", "default"
	_ = keyring.Delete(svc, acct)
	t.Cleanup(func() { _ = keyring.Delete(svc, acct) })

	u, _ := New(autoCfg(svc, acct), Hooks{
		Verify: verifyOnly("good"),
		Prompt: promptWith("j"), // a stray byte off an unattended terminal
	})
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for unverifiable passphrase")
	}
	if _, err := keyring.Get(svc, acct); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("junk was persisted to the keyring: %v", err)
	}
}

func TestAutoUnlocker_StaleEntryInvalidatedAndReprompted(t *testing.T) {
	const svc, acct = "hush-auto-test-stale", "default"
	if err := keyring.Set(svc, acct, "j"); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete(svc, acct) })

	u, _ := New(autoCfg(svc, acct), Hooks{
		Verify: verifyOnly("good"),
		Prompt: promptWith("good"),
	})
	got, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(got) != "good" {
		t.Fatalf("got %q, want %q", got, "good")
	}
	if v, err := keyring.Get(svc, acct); err != nil || v != "good" {
		t.Fatalf("keyring after heal: %q, %v", v, err)
	}
}

// The built-in TTY prompt and the keyring-unreachable fallback remain
// gated by term.IsTerminal; those are covered manually via `hush up`
// in a clean dev shell.
