package unlock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jack-work/hush/config"
	"github.com/jack-work/hush/internal/oskeyring"
)

type silentKeyring struct{ release chan struct{} }

func (s silentKeyring) Get(string, string) (string, error) { <-s.release; return "", nil }
func (s silentKeyring) Set(string, string, string) error   { <-s.release; return nil }
func (s silentKeyring) Delete(string, string) error        { <-s.release; return nil }

func useSilentKeyring(t *testing.T) {
	t.Helper()
	s := silentKeyring{release: make(chan struct{})}
	restore := oskeyring.Use(s, 50*time.Millisecond)
	t.Cleanup(func() {
		close(s.release)
		restore()
	})
}

func passphraseWithin(t *testing.T, u Unlocker) ([]byte, error) {
	t.Helper()
	type out struct {
		pp  []byte
		err error
	}
	done := make(chan out, 1)
	go func() {
		pp, err := u.Passphrase(context.Background())
		done <- out{pp, err}
	}()
	select {
	case o := <-done:
		return o.pp, o.err
	case <-time.After(5 * time.Second):
		t.Fatal("Passphrase still waiting on a keyring that never answers")
		return nil, nil
	}
}

// The 11-04 hang: a Secret Service out of file descriptors never answered the
// auto unlocker's read, and every figaro command waited on it.
func TestAutoUnlockerAsksInsteadWhenTheKeyringNeverAnswers(t *testing.T) {
	useSilentKeyring(t)
	u, _ := New(autoCfg("hush-auto-test-silent", "default"), Hooks{
		Verify: verifyOnly("good"),
		Prompt: promptWith("good"),
	})
	got, err := passphraseWithin(t, u)
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if string(got) != "good" {
		t.Fatalf("got %q, want the prompted passphrase", got)
	}
}

func TestAutoUnlockerNamesTheKeyringWhenAskingInsteadAlsoFails(t *testing.T) {
	useSilentKeyring(t)
	u, _ := New(autoCfg("hush-auto-test-silent-noprompt", "default"), Hooks{
		Prompt: func(context.Context) ([]byte, error) { return nil, errors.New("stdin is not a terminal") },
	})
	_, err := passphraseWithin(t, u)
	if !errors.Is(err, oskeyring.ErrUnresponsive) {
		t.Fatalf("err = %v, want it to carry ErrUnresponsive", err)
	}
}

func TestKeyringUnlockerFailsWithinTheBoundWhenTheKeyringNeverAnswers(t *testing.T) {
	useSilentKeyring(t)
	u, _ := New(config.UnlockConfig{
		Method:  "keyring",
		Keyring: config.KeyringConfig{Service: "hush-keyring-test-silent", Account: "default"},
	}, Hooks{})
	_, err := passphraseWithin(t, u)
	if !errors.Is(err, oskeyring.ErrUnresponsive) {
		t.Fatalf("err = %v, want ErrUnresponsive", err)
	}
}
