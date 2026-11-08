package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
)

const noScopeEnv = "HUSH_NO_AGENT_SCOPE"

type placement struct {
	managerSocket string
	scopePrefix   string
}

func placeAgent(getenv func(string) string, managerAt func(string) bool, instance string) (placement, bool) {
	xdg := getenv("XDG_RUNTIME_DIR")
	if xdg == "" || truthy(getenv(noScopeEnv)) {
		return placement{}, false
	}
	socket := filepath.Join(xdg, "systemd", "private")
	if !managerAt(socket) {
		return placement{}, false
	}
	sum := sha256.Sum256([]byte(instance))
	return placement{managerSocket: socket, scopePrefix: "hush-agent-" + hex.EncodeToString(sum[:4])}, true
}

func (p placement) scopeFor(pid int) string {
	return fmt.Sprintf("%s-%d.scope", p.scopePrefix, pid)
}

func truthy(v string) bool {
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES", "on", "ON":
		return true
	}
	return false
}
