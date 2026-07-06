//go:build !windows

package e2e

import (
	"os"
	"os/exec"
	"testing"
)

// prepareHandoff wires the identity handoff for a controllable agent
// child: an inherited pipe on fd 3. The returned closure writes the
// identity (zeroing nothing; the harness owns the bytes) after Start.
func (w *world) prepareHandoff(t *testing.T, cmd *exec.Cmd) func() {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.ExtraFiles = []*os.File{pr}
	return func() {
		pr.Close()
		pw.Write(w.id)
		pw.Close()
	}
}
