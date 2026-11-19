package spiffeid

import (
	"strings"
	"testing"
)

func TestParseAcceptsWhatTheContractNames(t *testing.T) {
	for _, s := range []string{
		"spiffe://kelliher/node/spain",
		"spiffe://kelliher/node/spain/unit/figaro.service",
		"spiffe://kelliher/node/merlin/uid/1000",
		"spiffe://kelliher/node/merlin/figaro/ce338ad521f91555eab99fc9ac83f8ac",
		"spiffe://a/x_y-z.w",
	} {
		id, err := Parse(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if id.String() != s {
			t.Fatalf("round trip %s -> %s", s, id)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	for name, s := range map[string]string{
		"other scheme":    "https://kelliher/node/spain",
		"no path":         "spiffe://kelliher",
		"bare slash":      "spiffe://kelliher/",
		"empty segment":   "spiffe://kelliher/node//spain",
		"trailing slash":  "spiffe://kelliher/node/spain/",
		"dot":             "spiffe://kelliher/node/./spain",
		"dotdot":          "spiffe://kelliher/node/../root",
		"port":            "spiffe://kelliher:443/node/spain",
		"user info":       "spiffe://x@kelliher/node/spain",
		"query":           "spiffe://kelliher/node/spain?a=b",
		"fragment":        "spiffe://kelliher/node/spain#f",
		"escape":          "spiffe://kelliher/node/sp%61in",
		"upper domain":    "spiffe://Kelliher/node/spain",
		"dotted domain":   "spiffe://kelliher.info/node/spain",
		"bad char":        "spiffe://kelliher/node/sp ain",
		"too long":        "spiffe://kelliher/" + strings.Repeat("a", maxLen),
		"empty":           "",
		"leading hyphen":  "spiffe://-kelliher/node/spain",
		"trailing hyphen": "spiffe://kelliher-/node/spain",
	} {
		if _, err := Parse(s); err == nil {
			t.Errorf("%s: %q parsed", name, s)
		}
	}
}

func TestNodeScope(t *testing.T) {
	cases := []struct {
		id     string
		node   string
		isNode bool
		under  string
	}{
		{"spiffe://k/node/spain", "spain", true, "spain"},
		{"spiffe://k/node/spain/unit/x.service", "spain", false, "spain"},
		{"spiffe://k/svc/spain", "", false, ""},
		{"spiffe://k/node", "", false, ""},
	}
	for _, c := range cases {
		id, err := Parse(c.id)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := id.Node()
		if n != c.node || id.IsNode() != c.isNode {
			t.Errorf("%s: node %q isNode %v", c.id, n, id.IsNode())
		}
		if c.under != "" && !id.Under(c.under) {
			t.Errorf("%s: not under %s", c.id, c.under)
		}
		if id.Under("merlin") {
			t.Errorf("%s: under merlin", c.id)
		}
	}
}
