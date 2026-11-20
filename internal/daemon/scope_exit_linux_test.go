package daemon

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// hush#37 L1 Low: an agent that exited at once never showed up in its scope,
// so the move waited out its whole deadline before the spawn went on.
func TestAnAgentThatExitsAtOnceDoesNotHoldTheSpawnForTheScopeWait(t *testing.T) {
	dir, err := os.MkdirTemp("", "hush-exit-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "private")
	answeringManager(t, socket)

	agent := exec.Command("/bin/true")
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agent.Wait() })
	for deadline := time.Now().Add(5 * time.Second); !exited(agent.Process.Pid); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("/bin/true did not exit")
		}
	}
	start := time.Now()
	err = moveIntoScope(placement{managerSocket: socket, scopePrefix: "hush-agent-exit"}, agent.Process.Pid)
	if err == nil {
		t.Fatal("a move of an agent that had exited reported success")
	}
	if took := time.Since(start); took > scopeMoveWait/2 {
		t.Fatalf("the move of an exited agent took %s: %v", took, err)
	}
}

// answeringManager speaks the server side of a systemd private bus and
// answers every method call with an empty reply, so StartTransientUnit
// succeeds and moves nothing.
func answeringManager(t *testing.T, socket string) {
	t.Helper()
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
			go serveAnswers(c)
		}
	}()
}

func serveAnswers(c net.Conn) {
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
			for {
				m, err := dbus.DecodeMessage(in)
				if err != nil {
					return
				}
				if m.Type != dbus.TypeMethodCall {
					continue
				}
				reply := &dbus.Message{
					Type:    dbus.TypeMethodReply,
					Flags:   dbus.FlagNoAutoStart,
					Headers: map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(m.Serial())},
				}
				if reply.EncodeTo(c, binary.LittleEndian) != nil {
					return
				}
			}
		default:
			fmt.Fprint(c, "ERROR\r\n")
		}
	}
}
