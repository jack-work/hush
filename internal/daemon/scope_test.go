package daemon

import (
	"strings"
	"testing"
)

// An agent a unit spawns (a figla reminder, an update job) must not die when
// that unit ends: where a user manager answers, it gets a scope of its own.

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func managerAt(socket string) func(string) bool { return func(p string) bool { return p == socket } }

func TestTheAgentStaysWhereItIsWithoutAUserManager(t *testing.T) {
	present := managerAt("/run/user/1000/systemd/private")
	cases := map[string]struct {
		env    map[string]string
		exists func(string) bool
	}{
		"no runtime dir":                {map[string]string{}, present},
		"a runtime dir with no manager": {map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}, managerAt("")},
		"asked not to, as tests ask":    {map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000", noScopeEnv: "1"}, present},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if p, ok := placeAgent(envOf(c.env), c.exists, "/run/user/1000/hush"); ok {
				t.Fatalf("placed the agent in %+v", p)
			}
		})
	}
}

func TestTheAgentGetsAScopeOfItsOwnWhenAUserManagerAnswers(t *testing.T) {
	env := envOf(map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"})
	exists := managerAt("/run/user/1000/systemd/private")
	a, ok := placeAgent(env, exists, "/run/user/1000/hush")
	if !ok {
		t.Fatal("a reachable user manager was not used")
	}
	if name := a.scopeFor(77); !strings.HasPrefix(name, "hush-agent-") || !strings.HasSuffix(name, "-77.scope") {
		t.Fatalf("scope %q, want hush-agent-<instance>-77.scope", name)
	}
	b, _ := placeAgent(env, exists, "/tmp/figaro-dev-clean-hush")
	if a.scopePrefix == b.scopePrefix {
		t.Fatalf("two agent instances share the scope name %q", a.scopePrefix)
	}
}
