package unlock

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
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

func captureStderr(t *testing.T, run func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = prev }()
	run()
	w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func withStdinNotATerminal(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = prev
		r.Close()
		w.Close()
	})
}

// Fail closed: with no terminal to ask on, a keyring that never answers ends
// in an error that names it, with no passphrase and no other source tried.
func TestASilentKeyringWithNoTerminalFailsClosedAndSaysWhy(t *testing.T) {
	useSilentKeyring(t)
	withStdinNotATerminal(t)
	keyringUnresponsiveHint = sync.Once{}
	u, _ := New(autoCfg("hush-auto-test-silent-notty", "default"), Hooks{Verify: verifyOnly("good")})
	var pp []byte
	var err error
	captureStderr(t, func() { pp, err = passphraseWithin(t, u) })
	if pp != nil {
		t.Fatalf("got a passphrase %q from a keyring that never answered", pp)
	}
	if !errors.Is(err, oskeyring.ErrUnresponsive) {
		t.Fatalf("err = %v, want ErrUnresponsive", err)
	}
	if !strings.Contains(err.Error(), "OS keyring did not answer") {
		t.Fatalf("error %q does not name the keyring", err)
	}
}

func TestASilentKeyringNeverPutsThePassphraseOnStderrOrInTheError(t *testing.T) {
	useSilentKeyring(t)
	keyringUnresponsiveHint = sync.Once{}
	const secret = "correct-horse-battery-staple"
	u, _ := New(autoCfg("hush-auto-test-silent-secret", "default"), Hooks{
		Verify: verifyOnly(secret),
		Prompt: promptWith(secret),
	})
	var err error
	logged := captureStderr(t, func() { _, err = passphraseWithin(t, u) })
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if strings.Contains(logged, secret) {
		t.Fatalf("the passphrase reached stderr:\n%s", logged)
	}
	if !strings.Contains(logged, "OS keyring did not answer") {
		t.Fatalf("stderr does not say the keyring was stuck:\n%s", logged)
	}

	u, _ = New(autoCfg("hush-auto-test-silent-secret2", "default"), Hooks{
		Prompt: func(context.Context) ([]byte, error) { return nil, errors.New("no terminal") },
	})
	captureStderr(t, func() { _, err = passphraseWithin(t, u) })
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
}

// Concurrent unlocks against a stuck keyring printed the hint from a plain
// bool, a data race; now it prints exactly once and -race stays quiet.
func TestTheStuckKeyringHintPrintsOnceUnderConcurrentUnlocks(t *testing.T) {
	keyringUnresponsiveHint = sync.Once{}
	logged := captureStderr(t, func() {
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				printKeyringUnresponsiveOnce("hush-hint-test", oskeyring.ErrUnresponsive)
			}()
		}
		wg.Wait()
	})
	if n := strings.Count(logged, "while reading the passphrase"); n != 1 {
		t.Fatalf("hint printed %d times, want once:\n%s", n, logged)
	}
}
