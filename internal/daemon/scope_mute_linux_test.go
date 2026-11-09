package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// figaro's first `ls` with a new vault sat for 80 s and more: the agent child
// waited on fd 3 for an identity its parent never wrote, because the parent
// was blocked moving it into a scope, on a Subscribe call the user manager
// never answered. A manager that answers nothing must cost the spawn at most
// the move's deadline.
func TestAManagerThatNeverAnswersDoesNotHoldTheSpawn(t *testing.T) {
	dir, err := os.MkdirTemp("", "hush-mute-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "private")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- moveIntoScope(placement{managerSocket: socket, scopePrefix: "hush-agent-mute"}, os.Getpid())
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a manager that answered nothing reported a move")
		}
		if took := time.Since(start); took > scopeMoveWait+2*time.Second {
			t.Fatalf("the move gave up after %s, past its %s deadline", took, scopeMoveWait)
		}
	case <-time.After(scopeMoveWait + 10*time.Second):
		t.Fatal("the move to a mute manager never returned")
	}
}
