package daemon

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// hush 0.14.5 subscribed to the user manager's signals before asking for the
// scope. Four `hush oauth get keel` processes then sat on a call the manager
// never answered while every unit change on the box was queued for them, one
// parked goroutine per signal once the 16-slot channel filled, and grew to
// 1.8-3.2 GiB over seven days. A manager that broadcasts while it sits on
// the call must cost the spawn its deadline and nothing that grows.
func TestAManagerThatBroadcastsWhileSittingOnTheCallDoesNotGrowTheSpawn(t *testing.T) {
	dir, err := os.MkdirTemp("", "hush-flood-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "private")
	sent := floodingManager(t, socket)

	baseline := runtime.NumGoroutine()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- moveIntoScope(placement{managerSocket: socket, scopePrefix: "hush-agent-flood"}, os.Getpid())
	}()
	peak := baseline
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	limit := time.After(scopeMoveWait + 10*time.Second)
	for {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a manager that never answered StartTransientUnit reported a move")
			}
			if took := time.Since(start); took > scopeMoveWait+2*time.Second {
				t.Fatalf("the move gave up after %s, past its %s deadline", took, scopeMoveWait)
			}
			if n := sent(); n < 1000 {
				t.Fatalf("the fake sent only %d signals, too few to show growth", n)
			}
			if peak-baseline > 100 {
				t.Fatalf("goroutines rose from %d to %d while the manager broadcast %d signals", baseline, peak, sent())
			}
			return
		case <-tick.C:
			if n := runtime.NumGoroutine(); n > peak {
				peak = n
			}
			if peak-baseline > 1000 {
				t.Fatalf("goroutines rose from %d to %d while the manager broadcast %d signals", baseline, peak, sent())
			}
		case <-limit:
			t.Fatalf("the move never returned; goroutines peaked at %d over a baseline of %d", peak, baseline)
		}
	}
}

// floodingManager speaks the server side of a systemd private bus: SASL AUTH
// EXTERNAL, then an empty reply to every method call except
// StartTransientUnit, which it never answers. From BEGIN on it broadcasts
// PropertiesChanged signals as fast as the client reads them. The returned
// func counts the signals written.
func floodingManager(t *testing.T, socket string) func() int {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); ln.Close() })
	var mu sync.Mutex
	sent := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFlood(c, stop, &mu, &sent)
		}
	}()
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return sent
	}
}

func serveFlood(c net.Conn, stop <-chan struct{}, mu *sync.Mutex, sent *int) {
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
			var wmu sync.Mutex
			write := func(m *dbus.Message) error {
				wmu.Lock()
				defer wmu.Unlock()
				return m.EncodeTo(c, binary.LittleEndian)
			}
			go func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					if write(propertiesChanged()) != nil {
						return
					}
					mu.Lock()
					*sent++
					mu.Unlock()
				}
			}()
			for {
				m, err := dbus.DecodeMessage(in)
				if err != nil {
					return
				}
				if m.Type != dbus.TypeMethodCall {
					continue
				}
				if member, _ := m.Headers[dbus.FieldMember].Value().(string); member == "StartTransientUnit" {
					continue
				}
				reply := &dbus.Message{
					Type:    dbus.TypeMethodReply,
					Flags:   dbus.FlagNoAutoStart,
					Headers: map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(m.Serial())},
				}
				if write(reply) != nil {
					return
				}
			}
		default:
			fmt.Fprint(c, "ERROR\r\n")
		}
	}
}

func propertiesChanged() *dbus.Message {
	return &dbus.Message{
		Type: dbus.TypeSignal,
		Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath:      dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/systemd1/unit/figla_2etimer")),
			dbus.FieldInterface: dbus.MakeVariant("org.freedesktop.DBus.Properties"),
			dbus.FieldMember:    dbus.MakeVariant("PropertiesChanged"),
			dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf("", map[string]dbus.Variant{}, []string{})),
		},
		Body: []interface{}{"org.freedesktop.systemd1.Unit", map[string]dbus.Variant{"ActiveState": dbus.MakeVariant("active")}, []string{}},
	}
}
