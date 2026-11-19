// Package policy decides one gateway request under the fleet's authorization
// rule: allow = (standing OR temporary) AND NOT suspended AND inside the ceiling.
//
// The gateway supplies standing (the deployment's baseline and the identity
// provider's group membership) and the ceiling; hush's runtime overlay supplies
// the temporary grants and the suspensions. Decide is the one implementation:
// hush's tests and the gateway's tests run the same vectors (testdata).
package policy

import (
	"net/http"
	"time"
)

// Wildcard is the grant a suspension names to cut every service of a subject.
const Wildcard = "*"

// Entry is one overlay entry: Subject (a principal name) holds Grant
// ("grant-<service>") until ExpiresAt, or, in Overlay.Suspensions, is denied
// it. A suspension with no ExpiresAt lasts until it is lifted.
type Entry struct {
	ID         string    `json:"id"`
	Subject    string    `json:"subject"`
	Grant      string    `json:"grant"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
	Reason     string    `json:"reason"`
	ApprovedBy string    `json:"approved_by"`
}

// Live reports whether e still applies at now.
func (e Entry) Live(now time.Time) bool { return e.ExpiresAt.IsZero() || now.Before(e.ExpiresAt) }

// Overlay is hush's runtime layer as the gateway reads it (GET /v1/overlay).
// Sequence grows with every change, so a reader can tell a newer snapshot.
type Overlay struct {
	Sequence    uint64  `json:"sequence"`
	Grants      []Entry `json:"grants"`
	Suspensions []Entry `json:"suspensions"`
}

// Request is what the gateway knows about one call.
type Request struct {
	Principal string
	Service   string
	Standing  bool // the baseline lists (role, service) AND the principal is in group grant-<service>
	Ceiling   bool // the deployment's ceiling admits this role, service, method and path
	Now       time.Time
}

// Decision is the answer; a refusal carries the status and text the gateway sends.
type Decision struct {
	Allow  bool
	Status int
	Text   string
}

// Decide applies the rule. The ceiling is checked first (no overlay widens it),
// then suspensions (a deny beats every allow), then the grants. Expiry is judged
// against r.Now, never against when the overlay was read.
func Decide(r Request, o Overlay) Decision {
	grant := "grant-" + r.Service
	if !r.Ceiling {
		return refuse("outside the flake ceiling for " + r.Service)
	}
	for _, s := range o.Suspensions {
		if s.Subject == r.Principal && (s.Grant == grant || s.Grant == Wildcard) && s.Live(r.Now) {
			until := "lifted"
			if !s.ExpiresAt.IsZero() {
				until = s.ExpiresAt.UTC().Format(time.RFC3339)
			}
			return refuse("suspended for " + r.Service + " until " + until)
		}
	}
	if r.Standing {
		return Decision{Allow: true}
	}
	var lapsed time.Time
	for _, g := range o.Grants {
		if g.Subject != r.Principal || g.Grant != grant {
			continue
		}
		if g.Live(r.Now) {
			return Decision{Allow: true}
		}
		if g.ExpiresAt.After(lapsed) {
			lapsed = g.ExpiresAt
		}
	}
	if !lapsed.IsZero() {
		return refuse("no grant for " + r.Service + " (temporary expired " + lapsed.UTC().Format(time.RFC3339) + ")")
	}
	return refuse("no grant for " + r.Service)
}

func refuse(text string) Decision {
	return Decision{Status: http.StatusForbidden, Text: text}
}
