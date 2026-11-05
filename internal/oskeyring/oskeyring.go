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

var (
	mu      sync.Mutex
	backend Backend = secretService{}
	timeout         = defaultTimeout
)

func Use(b Backend, limit time.Duration) (restore func()) {
	mu.Lock()
	prevBackend, prevTimeout := backend, timeout
	backend, timeout = b, limit
	mu.Unlock()
	return func() {
		mu.Lock()
		backend, timeout = prevBackend, prevTimeout
		mu.Unlock()
	}
}

func current() (Backend, time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	return backend, timeout
}

type result struct {
	value string
	err   error
}

func bounded(call func(Backend) (string, error)) (string, error) {
	b, limit := current()
	done := make(chan result, 1)
	go func() {
		v, err := call(b)
		done <- result{v, err}
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.value, r.err
	case <-timer.C:
		return "", fmt.Errorf("%w within %s", ErrUnresponsive, limit)
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
