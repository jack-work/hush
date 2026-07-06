//go:build windows

package daemon

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// handoffTimeout bounds how long the parent waits for the child to
// connect and read the identity, and how long the child retries dialing.
const handoffTimeout = 15 * time.Second

// Spawn starts exe+args as a detached background agent that survives the
// launching terminal. The identity is handed over an AF_UNIX socket in
// the temp dir (in-memory, never disk); the child dials it via
// identitySockEnv. extraEnv plus every HUSH_* override in the current
// environment are propagated through the launcher, because a WMI-created
// process inherits only the user's base environment. Returns the pid of
// the launched process (the launcher wrapper, not the agent; read
// agent.pid for the agent's own pid once it is up).
func Spawn(exe string, args, extraEnv []string, id io.WriterTo) (int, error) {
	sockPath := filepath.Join(os.TempDir(),
		fmt.Sprintf("hush-handoff-%d-%d.sock", os.Getpid(), time.Now().UnixNano()))
	os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return 0, fmt.Errorf("handoff listen: %w", err)
	}
	defer func() {
		ln.Close()
		os.Remove(sockPath)
	}()

	launcherPath, err := writeLauncher(exe, args, extraEnv, sockPath)
	if err != nil {
		return 0, err
	}
	defer os.Remove(launcherPath)

	pid, err := spawnViaWMI(launcherPath)
	if err != nil {
		// WMI unavailable: fall back to a direct detached spawn. It may
		// not escape the terminal's job object, but it is better than
		// failing outright.
		pid, err = spawnDirect(launcherPath)
		if err != nil {
			return 0, err
		}
	}

	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetDeadline(time.Now().Add(handoffTimeout))
	}
	conn, err := ln.Accept()
	if err != nil {
		return 0, fmt.Errorf("handoff accept (child never connected): %w", err)
	}
	defer conn.Close()
	if _, err := id.WriteTo(conn); err != nil {
		return 0, fmt.Errorf("hand off identity: %w", err)
	}
	return pid, nil
}

// ReadIdentity is the child side of the handoff: it dials the AF_UNIX
// socket named by identitySockEnv and reads the raw identity bytes.
func ReadIdentity() ([]byte, error) {
	sockPath := os.Getenv(identitySockEnv)
	if sockPath == "" {
		return nil, fmt.Errorf("%s not set", identitySockEnv)
	}

	var conn net.Conn
	var err error
	deadline := time.Now().Add(handoffTimeout)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		return nil, fmt.Errorf("dial identity handoff %q: %w", sockPath, err)
	}
	defer conn.Close()

	raw, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read identity handoff: %w", err)
	}
	return raw, nil
}

// writeLauncher emits a .cmd that sets the child environment and execs
// the agent, redirecting stderr to a log for early-crash forensics.
func writeLauncher(exe string, args, extraEnv []string, sockPath string) (string, error) {
	f, err := os.CreateTemp("", "hush-launch-*.cmd")
	if err != nil {
		return "", fmt.Errorf("create launcher: %w", err)
	}
	path := f.Name()

	set := func(k, v string) {
		// %% escapes a literal % inside `set "k=v"`. Quotes protect
		// spaces and cmd metacharacters.
		fmt.Fprintf(f, "@set \"%s=%s\"\r\n", k, strings.ReplaceAll(v, "%", "%%"))
	}
	set(ChildEnvVar, "1")
	set(identitySockEnv, sockPath)

	seen := map[string]bool{ChildEnvVar: true, identitySockEnv: true}
	for _, e := range extraEnv {
		if k, v, ok := strings.Cut(e, "="); ok && !seen[k] {
			set(k, v)
			seen[k] = true
		}
	}
	// Propagate HUSH_* overrides from the current environment (config /
	// state / runtime dir pins, keyring service) that WMI would drop.
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "HUSH_") {
			continue
		}
		if k, v, ok := strings.Cut(e, "="); ok && !seen[k] {
			set(k, v)
			seen[k] = true
		}
	}

	logPath := filepath.Join(os.TempDir(), "hush-agent-stderr.log")
	fmt.Fprintf(f, "@\"%s\"", exe)
	for _, a := range args {
		fmt.Fprintf(f, " \"%s\"", a)
	}
	fmt.Fprintf(f, " 2>>\"%s\"\r\n", logPath)

	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("write launcher: %w", err)
	}
	return path, nil
}

// spawnViaWMI creates the process through WMI Win32_Process.Create, which
// runs it under the WMI provider host, outside the caller's job object.
// The PowerShell is written to a temp script to sidestep inline-quoting
// pitfalls when passing a complex command through os/exec on Windows.
func spawnViaWMI(launcherPath string) (int, error) {
	script := fmt.Sprintf(
		"$ErrorActionPreference='Stop'\r\n"+
			"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "+
			"-Arguments @{CommandLine='cmd.exe /C \"%s\"'}\r\n"+
			"if ($r.ReturnValue -ne 0) { exit 1 }\r\n"+
			"Write-Output $r.ProcessId\r\n",
		launcherPath,
	)
	psPath, err := writeTemp("hush-wmi-*.ps1", script)
	if err != nil {
		return 0, err
	}
	defer os.Remove(psPath)

	out, err := exec.Command("powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", psPath).Output()
	if err != nil {
		return 0, fmt.Errorf("WMI spawn: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0, fmt.Errorf("WMI spawn: no pid returned")
	}
	pid, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return 0, fmt.Errorf("parse WMI pid from %q: %w", out, err)
	}
	return pid, nil
}

// spawnDirect is the fallback when WMI is unavailable: a direct detached
// spawn with BREAKAWAY_FROM_JOB. The breakaway is silently ignored when
// the job forbids it, so this may not survive a terminal close.
func spawnDirect(launcherPath string) (int, error) {
	const (
		createNewProcessGroup  = 0x00000200
		createNoWindow         = 0x08000000
		createBreakawayFromJob = 0x01000000
		detachedProcess        = 0x00000008
	)
	child := exec.Command("cmd.exe", "/C", launcherPath)
	child.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | createNoWindow |
			createBreakawayFromJob | detachedProcess,
	}
	if err := child.Start(); err != nil {
		return 0, fmt.Errorf("direct spawn: %w", err)
	}
	return child.Process.Pid, nil
}

func writeTemp(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
