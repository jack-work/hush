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
