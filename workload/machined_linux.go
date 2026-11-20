//go:build linux

package workload

import (
	"context"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

// machinedRegistry asks systemd-machined, over the system bus, which unit and leader it registered for a machine.
// A cgroup directory alone proves nothing: only machined's record does (a root process can mkdir a cgroup).
func machinedRegistry(name string) (string, uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return "", 0, fmt.Errorf("system bus: %w", err)
	}
	defer conn.Close()
	var path dbus.ObjectPath
	manager := conn.Object("org.freedesktop.machine1", "/org/freedesktop/machine1")
	if err := manager.CallWithContext(ctx, "org.freedesktop.machine1.Manager.GetMachine", 0, name).Store(&path); err != nil {
		return "", 0, fmt.Errorf("machined: %s: %w", name, err)
	}
	machine := conn.Object("org.freedesktop.machine1", path)
	unit, err := machine.GetProperty("org.freedesktop.machine1.Machine.Unit")
	if err != nil {
		return "", 0, err
	}
	leader, err := machine.GetProperty("org.freedesktop.machine1.Machine.Leader")
	if err != nil {
		return "", 0, err
	}
	u, ok1 := unit.Value().(string)
	l, ok2 := leader.Value().(uint32)
	if !ok1 || !ok2 {
		return "", 0, fmt.Errorf("machined: %s: unexpected property types %T %T", name, unit.Value(), leader.Value())
	}
	return u, l, nil
}
