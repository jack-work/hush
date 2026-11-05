package oskeyring

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingSilent struct {
	calls   *atomic.Int32
	release chan struct{}
}

func (s countingSilent) Get(string, string) (string, error) {
	s.calls.Add(1)
	<-s.release
	return "", nil
}
func (s countingSilent) Set(string, string, string) error { s.calls.Add(1); <-s.release; return nil }
func (s countingSilent) Delete(string, string) error      { s.calls.Add(1); <-s.release; return nil }

func useCountingSilent(t *testing.T, limit time.Duration) (*atomic.Int32, func()) {
	t.Helper()
	s := countingSilent{calls: new(atomic.Int32), release: make(chan struct{})}
	restore := Use(s, limit)
	var once sync.Once
	release := func() { once.Do(func() { close(s.release) }) }
	t.Cleanup(func() {
		release()
		restore()
	})
	return s.calls, release
}

func concurrentGets(n int) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = Get("figaro", "default")
		}()
	}
	wg.Wait()
	return errs
}

// A stuck Secret Service used to cost one blocked goroutine per keyring call,
// for as long as the process lived. One call reaches it; everyone after the
// first timeout is turned away without touching it.
func TestAStuckKeyringHoldsOneGoroutineAndTurnsTheRestAwayAtOnce(t *testing.T) {
	calls, _ := useCountingSilent(t, 50*time.Millisecond)
	if _, err := Get("figaro", "default"); !errors.Is(err, ErrUnresponsive) {
		t.Fatalf("first call: err = %v, want ErrUnresponsive", err)
	}
	start := time.Now()
	for i, err := range concurrentGets(50) {
		if !errors.Is(err, ErrUnresponsive) {
			t.Fatalf("caller %d: err = %v, want ErrUnresponsive", i, err)
		}
	}
	if took := time.Since(start); took > 25*time.Millisecond {
		t.Fatalf("50 callers after the timeout took %s, want them turned away at once", took)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("the stuck keyring was called %d times, want 1", n)
	}
}

func TestManyCallersArrivingTogetherReachAStuckKeyringOnce(t *testing.T) {
	calls, _ := useCountingSilent(t, 50*time.Millisecond)
	start := time.Now()
	for i, err := range concurrentGets(50) {
		if !errors.Is(err, ErrUnresponsive) {
			t.Fatalf("caller %d: err = %v, want ErrUnresponsive", i, err)
		}
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("callers took %s, want each within the bound", took)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("the stuck keyring was called %d times, want 1", n)
	}
}

func TestAKeyringThatRecoversIsAskedAgain(t *testing.T) {
	calls, release := useCountingSilent(t, 50*time.Millisecond)
	if _, err := Get("figaro", "default"); !errors.Is(err, ErrUnresponsive) {
		t.Fatalf("first call: err = %v, want ErrUnresponsive", err)
	}
	release()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := Get("figaro", "default")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still refused after the keyring answered: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := calls.Load(); n < 2 {
		t.Fatalf("keyring called %d times, want the recovered keyring asked again", n)
	}
}

type lockedMap struct {
	mu sync.Mutex
	m  map[string]string
}

func (l *lockedMap) Get(s, a string) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := l.m[s+"/"+a]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}
func (l *lockedMap) Set(s, a, v string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[s+"/"+a] = v
	return nil
}
func (l *lockedMap) Delete(s, a string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, s+"/"+a)
	return nil
}

func TestAHealthyKeyringServesConcurrentCallersWithoutRefusals(t *testing.T) {
	store := &lockedMap{m: map[string]string{"figaro/default": "pp"}}
	defer Use(store, time.Second)()
	for i, err := range concurrentGets(50) {
		if err != nil {
			t.Fatalf("caller %d on a healthy keyring: %v", i, err)
		}
	}
}
