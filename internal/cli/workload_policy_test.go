package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// RED if servePolicy accepts a policy and map that do not belong together.
func TestServePolicyNeedsAMatchingMap(t *testing.T) {
	good := filepath.Join(t.TempDir(), "machines.json")
	if err := os.WriteFile(good, []byte(`{"template":"pool-svc","base":1895825408,"size":65536,"machines":{"spool-a":{"id":"a","k":1}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		desc, policy, machines, err string
	}{
		{"control: node without a map", "node", "", ""},
		{"control: node+machines with a map", "node+machines", good, ""},
		{"node with a map", "node", good, "--machines needs --policy node+machines"},
		{"node+machines without a map", "node+machines", "", "--policy node+machines needs --machines"},
		{"an unknown policy", "machines", "", `--policy "machines": want node or node+machines`},
		{"a map that does not exist", "node+machines", filepath.Join(t.TempDir(), "none.json"), "open "},
	}
	for _, c := range cases {
		cmd := &cobra.Command{}
		cmd.Flags().String("policy", "node", "")
		cmd.Flags().String("machines", "", "")
		_ = cmd.Flags().Set("policy", c.policy)
		_ = cmd.Flags().Set("machines", c.machines)
		p, err := servePolicy(cmd, "kelliher", "spain")
		if c.err == "" {
			if err != nil || p == nil {
				t.Errorf("%s: %v", c.desc, err)
			}
			continue
		}
		if err == nil || len(err.Error()) < len(c.err) || err.Error()[:len(c.err)] != c.err {
			t.Errorf("%s: got %v, want an error starting %q", c.desc, err, c.err)
		}
	}
}
