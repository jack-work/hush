package daemon

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/godbus/dbus/v5"
)

const scopeJobWait = 5 * time.Second

func moveIntoScope(p placement, pid int) error {
	conn, err := dbus.Dial("unix:path=" + p.managerSocket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Getuid()))}); err != nil {
		return err
	}
	manager := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	if err := manager.Call("org.freedesktop.systemd1.Manager.Subscribe", 0).Err; err != nil {
		return err
	}
	name := p.scopeFor(pid)
	props := []struct {
		Name  string
		Value dbus.Variant
	}{
		{"PIDs", dbus.MakeVariant([]uint32{uint32(pid)})},
		{"Description", dbus.MakeVariant("hush agent")},
		{"CollectMode", dbus.MakeVariant("inactive-or-failed")},
	}
	aux := []struct {
		Name  string
		Props []struct {
			Name  string
			Value dbus.Variant
		}
	}{}
	var job dbus.ObjectPath
	if err := manager.Call("org.freedesktop.systemd1.Manager.StartTransientUnit", 0, name, "fail", props, aux).Store(&job); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), scopeJobWait)
	defer cancel()
	for {
		select {
		case s, ok := <-signals:
			if !ok {
				return fmt.Errorf("the user manager hung up before %s started", name)
			}
			if s.Name != "org.freedesktop.systemd1.Manager.JobRemoved" || len(s.Body) < 4 {
				continue
			}
			if path, _ := s.Body[1].(dbus.ObjectPath); path != job {
				continue
			}
			if result, _ := s.Body[3].(string); result != "done" {
				return fmt.Errorf("starting %s: %s", name, result)
			}
			return nil
		case <-ctx.Done():
			return fmt.Errorf("starting %s: no answer in %s", name, scopeJobWait)
		}
	}
}
