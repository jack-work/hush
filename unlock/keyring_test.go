package unlock

import (
	"context"
	"errors"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/jack-work/hush/config"
)

// keyring.MockInit replaces the real backend with an in-memory map for
// the duration of the test process. Cheap and avoids dbus/Keychain.
func init() {
	// Tests set up entries explicitly via keyring.Set; uninitialized
	// reads return ErrNotFound, which is exactly what we want.
	keyring.MockInit()
}

func keyringCfg(service, account string) config.UnlockConfig {
	return config.UnlockConfig{
		Method: "keyring",
		Keyring: config.KeyringConfig{
			Service: service,
			Account: account,
		},
	}
}

func TestKeyringUnlocker_RoundTrip(t *testing.T) {
	const svc, acct, pp = "hush-test", "default", "hunter2"
	if err := keyring.Set(svc, acct, pp); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}
	t.Cleanup(func() { _ = keyring.Delete(svc, acct) })

	u, err := New(keyringCfg(svc, acct))
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

func TestKeyringUnlocker_MissingEntryWrapsSentinel(t *testing.T) {
	u, _ := New(keyringCfg("hush-test", "nonexistent"))
	_, err := u.Passphrase(context.Background())
	if err == nil {
		t.Fatal("expected error for missing entry, got nil")
	}
	if !errors.Is(err, ErrKeyringEntryMissing) {
		t.Fatalf("expected ErrKeyringEntryMissing, got %v", err)
	}
}

func TestKeyringUnlocker_EmptyServiceIsError(t *testing.T) {
	u, _ := New(keyringCfg("", "default"))
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty service, got nil")
	}
}

func TestKeyringUnlocker_EmptyAccountIsError(t *testing.T) {
	u, _ := New(keyringCfg("hush-test", ""))
	if _, err := u.Passphrase(context.Background()); err == nil {
		t.Fatal("expected error for empty account, got nil")
	}
}
