//go:build windows

package e2e

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// prepareHandoff wires the identity handoff for a controllable agent
// child on Windows, mirroring internal/daemon's protocol: an AF_UNIX
// socket named by HUSH_IDENTITY_SOCK that the child dials. The child is
// a normal (non-detached) process here so the test keeps its handle.
func (w *world) prepareHandoff(t *testing.T, cmd *exec.Cmd) func() {
	t.Helper()
	sockPath := filepath.Join(w.base, "handoff.sock")
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("handoff listen: %v", err)
	}
	cmd.Env = append(cmd.Env, "HUSH_IDENTITY_SOCK="+sockPath)
	return func() {
		defer ln.Close()
		defer os.Remove(sockPath)
		if ul, ok := ln.(*net.UnixListener); ok {
			ul.SetDeadline(time.Now().Add(10 * time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("handoff accept: %v", err)
			return
		}
		defer conn.Close()
		conn.Write(w.id)
	}
}
