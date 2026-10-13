package units

import (
	"strings"
	"testing"
)

// section returns the body of the named INI section from a unit file, so a
// test can assert not merely that a directive is present but that it is
// somewhere systemd will read it.
func section(unit, name string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(unit, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			in = t == "["+name+"]"
			continue
		}
		if in {
			b.WriteString(t)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func renderService(t *testing.T) string {
	t.Helper()
	for _, u := range Render("/usr/bin/hush", "/run/user/1000/hush") {
		if u.Name == "hush-agent.service" {
			return u.Content
		}
	}
	t.Fatal("Render returned no hush-agent.service")
	return ""
}

// TestServiceHasNoStartLimit guards the one-way door: if an activated
// service trips a start rate limit, systemd stops the SOCKET unit that
// triggers it, and on-demand starting is dead until a human intervenes —
// silently, since every consumer just keeps reporting that no agent is
// running.
func TestServiceHasNoStartLimit(t *testing.T) {
	unit := renderService(t)

	if !strings.Contains(unit, "StartLimitIntervalSec=0") {
		t.Error("hush-agent.service must disable the start rate limit; " +
			"tripping it stops the socket unit and kills activation for good")
	}

	// Placement is the whole game. StartLimitIntervalSec moved from
	// [Service] to [Unit] in systemd 229, and the old placement is ignored
	// rather than rejected — the unit would look hardened and behave
	// exactly as before.
	if !strings.Contains(section(unit, "Unit"), "StartLimitIntervalSec=0") {
		t.Error("StartLimitIntervalSec must be in [Unit]; systemd ignores it in [Service]")
	}
	if strings.Contains(section(unit, "Service"), "StartLimitIntervalSec") {
		t.Error("StartLimitIntervalSec found in [Service], where systemd ignores it")
	}
}

// TestServiceDoesNotRestart pins the other half of the lifecycle: the TTL
// is meant to end the process, and the socket unit re-arms for the next
// client. A Restart= directive would defeat the TTL by keeping decrypted
// key material resident.
func TestServiceDoesNotRestart(t *testing.T) {
	if svc := section(renderService(t), "Service"); !strings.Contains(svc, "Restart=no") {
		t.Error("hush-agent.service must not restart on exit; the TTL is supposed to end it")
	}
}

// TestSocketUsesSpecifierForDefaultRuntimeDir keeps the shipped units
// portable between users: the default runtime dir renders as %t rather
// than a hard-coded uid path.
func TestSocketUsesSpecifierForDefaultRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	var sock string
	for _, u := range Render("/usr/bin/hush", "/run/user/1000/hush") {
		if u.Name == "hush-agent.socket" {
			sock = u.Content
		}
	}
	if !strings.Contains(sock, "ListenStream=%t/hush/agent.sock") {
		t.Errorf("default runtime dir should render as %%t, got:\n%s", section(sock, "Socket"))
	}
}
