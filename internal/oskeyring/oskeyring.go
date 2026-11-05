package oskeyring

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

var ErrNotFound = keyring.ErrNotFound

var ErrUnresponsive = errors.New("the OS keyring did not answer")

type Backend interface {
	Get(service, account string) (string, error)
	Set(service, account, value string) error
	Delete(service, account string) error
}

type secretService struct{}

func (secretService) Get(service, account string) (string, error) {
	return keyring.Get(service, account)
}

func (secretService) Set(service, account, value string) error {
	return keyring.Set(service, account, value)
}

func (secretService) Delete(service, account string) error {
	return keyring.Delete(service, account)
}

const defaultTimeout = 5 * time.Second

type flight struct {
	slot     chan struct{}
	mu       sync.Mutex
	inFlight bool
	stuck    bool
}

func newFlight() *flight { return &flight{slot: make(chan struct{}, 1)} }

func (f *flight) isStuck() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stuck
}

func (f *flight) begin() {
	f.mu.Lock()
	f.inFlight = true
	f.mu.Unlock()
}

func (f *flight) end() {
	f.mu.Lock()
	f.inFlight, f.stuck = false, false
	f.mu.Unlock()
	<-f.slot
}

func (f *flight) abandon() {
	f.mu.Lock()
	if f.inFlight {
		f.stuck = true
	}
	f.mu.Unlock()
}

var (
	mu      sync.Mutex
	backend Backend = secretService{}
	timeout         = defaultTimeout
	calls           = newFlight()
)

func Use(b Backend, limit time.Duration) (restore func()) {
	mu.Lock()
	prevBackend, prevTimeout, prevCalls := backend, timeout, calls
	backend, timeout, calls = b, limit, newFlight()
	mu.Unlock()
	return func() {
		mu.Lock()
		backend, timeout, calls = prevBackend, prevTimeout, prevCalls
		mu.Unlock()
	}
}

func current() (Backend, time.Duration, *flight) {
	mu.Lock()
	defer mu.Unlock()
	return backend, timeout, calls
}

type result struct {
	value string
	err   error
}

func unresponsiveWithin(limit time.Duration) error {
	return fmt.Errorf("%w within %s", ErrUnresponsive, limit)
}

func bounded(call func(Backend) (string, error)) (string, error) {
	b, limit, f := current()
	if f.isStuck() {
		return "", fmt.Errorf("%w: an earlier call is still waiting on it", ErrUnresponsive)
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case f.slot <- struct{}{}:
	case <-timer.C:
		return "", unresponsiveWithin(limit)
	}
	f.begin()
	done := make(chan result, 1)
	go func() {
		v, err := call(b)
		f.end()
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-timer.C:
		f.abandon()
		return "", unresponsiveWithin(limit)
	}
}

func Get(service, account string) (string, error) {
	return bounded(func(b Backend) (string, error) { return b.Get(service, account) })
}

func Set(service, account, value string) error {
	_, err := bounded(func(b Backend) (string, error) { return "", b.Set(service, account, value) })
	return err
}

func Delete(service, account string) error {
	_, err := bounded(func(b Backend) (string, error) { return "", b.Delete(service, account) })
	return err
}
