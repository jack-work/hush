package unlock

import (
	"testing"

	"github.com/jack-work/hush/config"
)

func TestNew_DefaultsToPassphrase(t *testing.T) {
	u, err := New(config.UnlockConfig{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := u.(*passphraseUnlocker); !ok {
		t.Fatalf("empty method should yield passphraseUnlocker, got %T", u)
	}
}

func TestNew_ExplicitPassphrase(t *testing.T) {
	u, err := New(config.UnlockConfig{Method: "passphrase"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := u.(*passphraseUnlocker); !ok {
		t.Fatalf("expected passphraseUnlocker, got %T", u)
	}
}

func TestNew_UnknownMethod(t *testing.T) {
	_, err := New(config.UnlockConfig{Method: "telepathy"})
	if err == nil {
		t.Fatal("expected error for unknown method, got nil")
	}
}
