package daemon

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A spawned agent that exits must not stay a zombie of its spawner: a
// long-lived consumer renews its agent every few minutes (figaro#138).
func TestSpawnedAgentIsReapedWhenItExits(t *testing.T) {
	t.Setenv(noScopeEnv, "1")
	pid, err := Spawn("/bin/sh", []string{"-c", "cat <&3 >/dev/null"}, nil, bytes.NewReader([]byte("id")), Options{Instance: "test"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		state := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])[0]
		if time.Now().After(deadline) {
			t.Fatalf("agent %d still in state %s after it exited", pid, state)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// hush#37: the agent was reaped before it was moved into its scope, so the
// pid handed to systemd could already name another process.
func TestSpawnedAgentIsNotReapedBeforeItsScopeMove(t *testing.T) {
	t.Setenv(noScopeEnv, "1")
	moved := make(chan error, 1)
	was := scopeAgent
	t.Cleanup(func() { scopeAgent = was })
	scopeAgent = func(pid int, _ string) error {
		time.Sleep(200 * time.Millisecond)
		_, err := os.Stat("/proc/" + strconv.Itoa(pid))
		moved <- err
		return nil
	}
	_, _ = Spawn("/bin/true", nil, nil, bytes.NewReader([]byte("id")), Options{Instance: "test"})
	if err := <-moved; err != nil {
		t.Fatalf("the agent was reaped before its scope move: %v", err)
	}
}
