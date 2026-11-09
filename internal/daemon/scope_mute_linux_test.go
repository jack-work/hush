package daemon

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// The hang figaro's release gate caught came after authentication: the
// manager let us in, then never answered a call. A manager that completes AUTH
// EXTERNAL and then sits on StartTransientUnit must cost the spawn at most
// the move's deadline. Two guards hold it: the dial's context closes the
// connection at the deadline, and the call carries the same context. Remove
// both and this hangs.
func TestAManagerThatAuthenticatesButNeverAnswersDoesNotHoldTheSpawn(t *testing.T) {
	dir, err := os.MkdirTemp("", "hush-silent-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "private")
	asked := silentManager(t, socket)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- moveIntoScope(placement{managerSocket: socket, scopePrefix: "hush-agent-silent"}, os.Getpid())
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a manager that never answered StartTransientUnit reported a move")
		}
		if took := time.Since(start); took > scopeMoveWait+2*time.Second {
			t.Fatalf("the move gave up after %s, past its %s deadline", took, scopeMoveWait)
		}
	case <-time.After(scopeMoveWait + 10*time.Second):
		t.Fatal("the move to a manager that never answers the call never returned")
	}
	select {
	case <-asked:
	default:
		t.Fatal("the move gave up before it asked for the scope; the fake never saw StartTransientUnit")
	}
}

// silentManager listens on socket as a systemd private bus would: it runs the
// server side of SASL AUTH EXTERNAL, then reads messages and answers none.
// The returned channel closes once a StartTransientUnit call arrives.
func silentManager(t *testing.T, socket string) <-chan struct{} {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	asked := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				in := bufio.NewReader(c)
				if b, err := in.ReadByte(); err != nil || b != 0 {
					return
				}
				for {
					line, err := in.ReadString('\n')
					if err != nil {
						return
					}
					switch cmd := strings.TrimRight(line, "\r\n"); {
					case cmd == "AUTH":
						fmt.Fprint(c, "REJECTED EXTERNAL\r\n")
					case cmd == "AUTH EXTERNAL" || strings.HasPrefix(cmd, "AUTH EXTERNAL "):
						fmt.Fprint(c, "OK 0123456789abcdef0123456789abcdef\r\n")
					case cmd == "NEGOTIATE_UNIX_FD":
						fmt.Fprint(c, "AGREE_UNIX_FD\r\n")
					case cmd == "BEGIN":
						var seen []byte
						buf := make([]byte, 4096)
						for {
							n, err := in.Read(buf)
							seen = append(seen, buf[:n]...)
							if bytes.Contains(seen, []byte("StartTransientUnit")) {
								once.Do(func() { close(asked) })
							}
							if err != nil {
								return
							}
						}
					default:
						fmt.Fprint(c, "ERROR\r\n")
					}
				}
			}()
		}
	}()
	return asked
}
