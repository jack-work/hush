package unlock

import (
	"context"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/zalando/go-keyring"

	"github.com/jack-work/hush/identity"
)

// The Verify hook every real consumer wires (managed.verifyPassphrase,
// cmd/up.go) is identity.Unlock, which zeroes the passphrase it is
// handed. Verifying in place therefore handed the caller — and
// keyring.Set — a buffer of NUL bytes: the agent failed to unlock with
// "incorrect passphrase" and the keyring was poisoned with NULs, which
// then failed verification forever. Both backends must verify against a
// private copy.

func writeIdentity(t *testing.T, pass string) string {
	t.Helper()
	k, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	path := filepath.Join(t.TempDir(), "identity.age")
	if err := identity.EncryptToFile([]byte(k.String()+"\n"), path, pass); err != nil {
		t.Fatalf("encrypt identity: %v", err)
	}
	return path
}

// realVerify is byte-for-byte what managed.(*Hush).verifyPassphrase does.
func realVerify(idFile string) func([]byte) error {
	return func(pp []byte) error {
		id, err := identity.Unlock(idFile, pp)
		if err == nil {
			id.Zero()
		}
		return err
	}
}

func TestAutoUnlocker_KeyringHitSurvivesDestructiveVerify(t *testing.T) {
	const svc, acct, pass = "hush-verify-hit", "default", "hunter2"
	keyring.MockInit()
	if err := keyring.Set(svc, acct, pass); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	u, _ := New(autoCfg(svc, acct), Hooks{Verify: realVerify(writeIdentity(t, pass))})
	got, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(got) != pass {
		t.Fatalf("caller got %q, want %q", got, pass)
	}
}

func TestAutoUnlocker_KeyringStoreSurvivesDestructiveVerify(t *testing.T) {
	const svc, acct, pass = "hush-verify-miss", "default", "hunter2"
	keyring.MockInit()

	u, _ := New(autoCfg(svc, acct), Hooks{
		Verify: realVerify(writeIdentity(t, pass)),
		Prompt: func(context.Context) ([]byte, error) { return []byte(pass), nil },
	})
	got, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(got) != pass {
		t.Fatalf("caller got %q, want %q", got, pass)
	}
	if v, err := keyring.Get(svc, acct); err != nil || v != pass {
		t.Fatalf("keyring holds %q (err %v), want %q", v, err, pass)
	}
}

func TestKeyringUnlocker_SurvivesDestructiveVerify(t *testing.T) {
	const svc, acct, pass = "hush-verify-explicit", "default", "hunter2"
	keyring.MockInit()
	if err := keyring.Set(svc, acct, pass); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	cfg := autoCfg(svc, acct)
	cfg.Method = "keyring"
	u, _ := New(cfg, Hooks{Verify: realVerify(writeIdentity(t, pass))})
	got, err := u.Passphrase(context.Background())
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(got) != pass {
		t.Fatalf("caller got %q, want %q", got, pass)
	}
}
