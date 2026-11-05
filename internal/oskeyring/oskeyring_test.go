package oskeyring

import (
	"errors"
	"testing"
	"time"
)

type silent struct{ release chan struct{} }

func (s silent) Get(string, string) (string, error) { <-s.release; return "", nil }
func (s silent) Set(string, string, string) error   { <-s.release; return nil }
func (s silent) Delete(string, string) error        { <-s.release; return nil }

func useSilent(t *testing.T, limit time.Duration) {
	t.Helper()
	s := silent{release: make(chan struct{})}
	restore := Use(s, limit)
	t.Cleanup(func() {
		close(s.release)
		restore()
	})
}

// The 11-04 hang: gnome-keyring-daemon out of file descriptors never answered,
// and every figaro command waited on it forever.
func TestAKeyringThatNeverAnswersIsGivenUpOnWithinTheBound(t *testing.T) {
	useSilent(t, 50*time.Millisecond)
	calls := map[string]func() error{
		"get": func() error { _, err := Get("figaro", "default"); return err },
		"set": func() error { return Set("figaro", "default", "x") },
		"del": func() error { return Delete("figaro", "default") },
	}
	for name, call := range calls {
		start := time.Now()
		done := make(chan error, 1)
		go func() { done <- call() }()
		var err error
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: still waiting on a keyring that never answers", name)
		}
		if !errors.Is(err, ErrUnresponsive) {
			t.Fatalf("%s: err = %v, want ErrUnresponsive", name, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("%s: returned after %s, want within the bound", name, took)
		}
	}
}

type answering map[string]string

func (a answering) Get(s, acct string) (string, error) {
	v, ok := a[s+"/"+acct]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (a answering) Set(s, acct, v string) error { a[s+"/"+acct] = v; return nil }
func (a answering) Delete(s, acct string) error { delete(a, s+"/"+acct); return nil }

func TestAKeyringThatAnswersIsPassedThroughUnchanged(t *testing.T) {
	store := answering{}
	defer Use(store, time.Second)()
	if _, err := Get("figaro", "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing entry: err = %v, want ErrNotFound", err)
	}
	if err := Set("figaro", "default", "pp"); err != nil {
		t.Fatal(err)
	}
	if v, err := Get("figaro", "default"); err != nil || v != "pp" {
		t.Fatalf("got %q, %v", v, err)
	}
	if err := Delete("figaro", "default"); err != nil {
		t.Fatal(err)
	}
}

// The bound is a constant: nothing an aria or a config file can write moves it.
func TestTheBoundIsFiveSecondsByDefault(t *testing.T) {
	if _, limit := current(); limit != 5*time.Second {
		t.Fatalf("default bound is %s, want 5s", limit)
	}
}
