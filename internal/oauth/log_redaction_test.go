package oauth

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// El Inspector XII on fix/agent-scope: the agent's stderr is now kept in
// agent.log, so whatever the oauth logger writes is durable. A token
// endpoint's body reaches a log line, an error or a file only through
// EndpointDetail. Every failure shape here carries a marker in the body; it
// must not survive into the log, the error or the state dir.
func TestATokenEndpointsBodyNeverReachesTheLog(t *testing.T) {
	const marker = "SECRETMARKERdoNotLogMe0123456789abcdefABCDEF"
	bodies := map[string]fakeDoer{
		"invalid_grant with a description": {400, `{"error":"invalid_grant","error_description":"token ` + marker + ` revoked"}`},
		"an html error page":               {502, `<html><body>upstream ` + marker + `</body></html>`},
		"json that is not an oauth error":  {400, `{"message":"` + marker + `"}`},
		"unauthorized with the token":      {401, `{"error":"invalid_client","error_description":"` + marker + `"}`},
		"a server error":                   {500, marker},
	}
	for name, doer := range bodies {
		t.Run(name, func(t *testing.T) {
			dir, key := t.TempDir(), newTestKey(t)
			var logged bytes.Buffer
			m := NewManager(dir, []age.Identity{key}, key.Recipient(), log.New(&logged, "", 0))
			t.Cleanup(m.Stop)
			if err := m.Register(testCfg, Tokens{AccessToken: "A1", RefreshToken: "R1", ExpiresIn: 3600}); err != nil {
				t.Fatal(err)
			}
			m.httpClient = doer
			_, err := m.Refresh("prov")
			if err != nil && strings.Contains(err.Error(), marker) {
				t.Fatalf("the refresh error carries the endpoint's body: %v", err)
			}
			if strings.Contains(logged.String(), marker) {
				t.Fatalf("the agent's log carries the endpoint's body:\n%s", logged.String())
			}
			_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				raw, _ := os.ReadFile(path)
				if bytes.Contains(raw, []byte(marker)) {
					t.Fatalf("%s carries the endpoint's body", path)
				}
				return nil
			})
		})
	}
}
