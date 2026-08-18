package oauth

import (
	"context"
	"fmt"
	"net/http"
	"sort"
)

// A GRANT is how one credential kind mints a fresh access token from the
// durable secret hush is holding for it.
//
// Everything else about a credential's runtime is the same whatever the
// grant: single-flight, persist-before-publish, proactive renewal partway
// through the lifetime, backoff on transient failure, atomic publication to
// readers, encryption at rest. That machinery lives in Manager and knows
// nothing about wire formats. A grant is the one method that does.
//
// Grants are NAMED and compiled in, not described by config. A config-driven
// grant would make hush "a daemon that will send a stored secret to whatever
// URL a file names", which is an exfiltration primitive living inside the
// program whose whole job is holding secrets. The cost of the compiled form
// is roughly sixty lines per credential kind, and there will never be many.
type Grant interface {
	// Name is the value stored as `grant` on disk and sent over the wire.
	Name() string

	// Mint exchanges the durable secret for a fresh access token. It is
	// called under the config's single-flight lock, so exactly one is in
	// progress per credential at a time.
	//
	// Errors MUST wrap ErrRefreshPermanent (the credential is dead; stop
	// the proactive loop and make the human re-login) or ErrRefreshTransient
	// (retry with backoff). Getting that classification wrong is expensive
	// in both directions: a transient failure called permanent silently
	// stops renewing a live credential, and a dead credential called
	// transient retries forever.
	Mint(ctx context.Context, doer httpDoer, cfg Config, durable string) (Tokens, error)

	// Validate checks a registration before anything is written.
	Validate(cfg Config, tok Tokens) error

	// MintsOnRegister reports whether Register may mint the first access
	// token itself when the caller supplies only the durable secret. True
	// for exchanges (the durable secret is all a human has); false where
	// the access token arrives from an authorization-code flow.
	MintsOnRegister() bool
}

var grants = map[string]Grant{}

func registerGrant(g Grant) { grants[g.Name()] = g }

// GrantNames lists the compiled-in grants, for help text and errors.
func GrantNames() []string {
	out := make([]string, 0, len(grants))
	for n := range grants {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// grantFor resolves a config's grant, defaulting to refresh_token so every
// credential written by an older hush keeps working untouched.
func grantFor(cfg Config) (Grant, error) {
	name := cfg.Grant
	if name == "" {
		name = GrantRefreshToken
	}
	g, ok := grants[name]
	if !ok {
		return nil, fmt.Errorf("%w: unknown grant %q (have %v)", ErrRefreshPermanent, name, GrantNames())
	}
	return g, nil
}

// httpStatusClass is the default reading of a response code: 5xx and
// transport failures are worth retrying, 4xx means the credential itself was
// rejected. Grants whose provider disagrees (Copilot answers a burst with
// 403) override it.
func httpStatusClass(status int) error {
	if status >= 500 {
		return ErrRefreshTransient
	}
	if status != http.StatusOK {
		return ErrRefreshPermanent
	}
	return nil
}
