package policy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// vector is one row of the shared truth table (testdata/truth-table.json): the
// gateway's suite and hush's run the same rows.
type vector struct {
	Name      string `json:"name"`
	Kanidm    string `json:"kanidm"`    // member | not
	Baseline  bool   `json:"baseline"`  // the baseline lists (role, service)
	Temporary string `json:"temporary"` // none | live | expired | live-other-subject
	Suspended string `json:"suspended"` // none | live | expired | live-any | live-other-grant
	Ceiling   bool   `json:"ceiling"`
	Allow     bool   `json:"allow"`
	Status    int    `json:"status"`
	Text      string `json:"text"`
}

const principal, service = "keel", "ghe"

func TestTruthTable(t *testing.T) {
	raw, err := os.ReadFile("testdata/truth-table.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	live, gone := now.Add(time.Hour), now.Add(-time.Minute)
	entry := func(subject, grant string, until time.Time) Entry {
		return Entry{Subject: subject, Grant: grant, ExpiresAt: until}
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			var o Overlay
			switch v.Temporary {
			case "live":
				o.Grants = append(o.Grants, entry(principal, "grant-"+service, live))
			case "expired":
				o.Grants = append(o.Grants, entry(principal, "grant-"+service, gone))
			case "live-other-subject":
				o.Grants = append(o.Grants, entry("rou2", "grant-"+service, live))
			case "none":
			default:
				t.Fatalf("unknown temporary %q", v.Temporary)
			}
			until := gone
			switch v.Suspended {
			case "live":
				until = live
				o.Suspensions = append(o.Suspensions, entry(principal, "grant-"+service, live))
			case "live-any":
				until = live
				o.Suspensions = append(o.Suspensions, entry(principal, Wildcard, live))
			case "live-other-grant":
				o.Suspensions = append(o.Suspensions, entry(principal, "grant-ado", live))
			case "expired":
				o.Suspensions = append(o.Suspensions, entry(principal, "grant-"+service, gone))
			case "none":
			default:
				t.Fatalf("unknown suspended %q", v.Suspended)
			}
			if v.Kanidm != "member" && v.Kanidm != "not" {
				t.Fatalf("unknown kanidm %q", v.Kanidm)
			}
			got := Decide(Request{
				Principal: principal, Service: service, Now: now,
				Standing: v.Baseline && v.Kanidm == "member",
				Ceiling:  v.Ceiling,
			}, o)
			stamp := until.UTC().Format(time.RFC3339)
			want := Decision{Allow: v.Allow, Status: v.Status,
				Text: strings.NewReplacer("<service>", service, "<t>", stamp).Replace(v.Text)}
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

// A suspension without expires_at lasts until it is lifted.
func TestSuspensionWithoutExpiry(t *testing.T) {
	o := Overlay{Suspensions: []Entry{{Subject: principal, Grant: Wildcard}}}
	got := Decide(Request{Principal: principal, Service: service, Standing: true, Ceiling: true, Now: time.Now()}, o)
	if got.Allow || got.Text != "suspended for ghe until lifted" {
		t.Fatalf("got %+v", got)
	}
}
