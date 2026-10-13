package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// SpecFile is the optional per-command metadata file that sits beside
// command.sh and secrets.toml.
const SpecFile = "command.toml"

// Delivery names how a command's decrypted secrets reach the process that
// uses them.
//
//	script: secrets are rendered into the script text through {{.name}}.
//	         The legacy default. Kept working forever, but it means the
//	         plaintext lives inside a program that an interpreter parses,
//	         which is how caller data and secret data end up in the same
//	         lexer.
//	env: secrets never touch the script. Each is placed in the child's
//	         environment under a name the command declares, and the script
//	         (or binary) reads it as "$VAR".
const (
	DeliveryScript = "script"
	DeliveryEnv    = "env"
)

// Spec is a command's declared shape. Every field is optional: a command
// directory with no command.toml at all loads as the legacy script command
// it has always been, which is what keeps existing installs working.
type Spec struct {
	Description string `toml:"description"`

	// Delivery is "script" (default) or "env".
	Delivery string `toml:"delivery"`

	// Exec names a binary to run directly, with no interpreter anywhere in
	// the path. Must be absolute: a bare name would resolve through PATH,
	// and PATH is exactly what shims manipulate.
	//
	// When set, no command script is read and Delivery is implicitly "env",
	// there is no script for a secret to be rendered into.
	Exec string `toml:"exec"`

	// Args are fixed arguments placed before the caller's own. They are
	// passed as argv elements, never concatenated, so a caller cannot
	// escape from a value position into a flag position.
	Args []string `toml:"args"`

	// Env is plain, non-secret environment the child is given:
	// AWS_REQUEST_CHECKSUM_CALCULATION = "WHEN_REQUIRED". Values are
	// literal, never decrypted, and come from a world-readable file.
	// Precedence and refusals: docs/command-env.md.
	Env map[string]string `toml:"env"`

	// Secrets maps a key in secrets.toml to the environment variable the
	// child should see it under: token = "BRAVE_TOKEN".
	Secrets map[string]string `toml:"secrets"`

	// OAuth maps a hush oauth credential name to an environment variable:
	// herald = "HERALD_TOKEN".
	//
	// Unlike Secrets, which are static and permanent, these are short-lived
	// access tokens the agent refreshes. That difference is the whole point:
	// a static key leaked into a log or a transcript is a leak until you
	// notice and rotate by hand, while an access token expires before you
	// finish reading it. Prefer this shape wherever the upstream supports
	// it.
	OAuth map[string]string `toml:"oauth"`

	// Timeout kills the child if it outlives the duration. Zero means wait
	// forever, which is the historical behavior.
	Timeout Duration `toml:"timeout"`

	// path records where this spec was loaded from, or "" for a default.
	path string
}

// Duration is a time.Duration that unmarshals from a TOML string ("30s").
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	if s == "" {
		d.Duration = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("not a duration (want e.g. \"30s\"): %q", s)
	}
	d.Duration = v
	return nil
}

// Scriptless reports whether the command runs a binary directly.
func (s *Spec) Scriptless() bool { return s.Exec != "" }

// EnvDelivery reports whether secrets reach the child through the
// environment rather than through rendered script text.
func (s *Spec) EnvDelivery() bool {
	return s.Delivery == DeliveryEnv || s.Scriptless()
}

// NeedsOAuth reports whether this command draws on a hush oauth credential.
func (s *Spec) NeedsOAuth() bool { return len(s.OAuth) > 0 }

// LoadSpec reads command.toml from a command directory. A missing file is
// not an error: it yields the legacy default.
func LoadSpec(cmdDir string) (*Spec, error) {
	p := filepath.Join(cmdDir, SpecFile)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Spec{Delivery: DeliveryScript}, nil
		}
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var s Spec
	if err := toml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	s.path = p
	if s.Delivery == "" {
		if s.Exec != "" {
			s.Delivery = DeliveryEnv
		} else {
			s.Delivery = DeliveryScript
		}
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &s, nil
}

// Validate rejects specs that would behave surprisingly. It is deliberately
// strict: a misconfigured credential boundary should fail loudly at load
// rather than quietly at exec.
func (s *Spec) Validate() error {
	switch s.Delivery {
	case DeliveryScript, DeliveryEnv:
	default:
		return fmt.Errorf("delivery = %q: want %q or %q", s.Delivery, DeliveryScript, DeliveryEnv)
	}
	if s.Exec != "" {
		if !filepath.IsAbs(s.Exec) {
			return fmt.Errorf("exec = %q: must be an absolute path", s.Exec)
		}
		if s.Delivery == DeliveryScript {
			return fmt.Errorf("exec is set but delivery = %q: a binary has no script to render secrets into", DeliveryScript)
		}
	}
	if s.Exec == "" && len(s.Args) > 0 {
		return fmt.Errorf("args is set without exec: script commands receive arguments as \"$@\"")
	}
	seen := map[string]string{}
	for key, envName := range s.Secrets {
		if envName == "" {
			return fmt.Errorf("secrets.%s: empty environment variable name", key)
		}
		if strings.ContainsAny(envName, "= \t\n\x00") {
			return fmt.Errorf("secrets.%s = %q: not a valid environment variable name", key, envName)
		}
		if prev, dup := seen[envName]; dup {
			return fmt.Errorf("%s and secrets.%s both map to %s", prev, key, envName)
		}
		seen[envName] = "secrets." + key
	}
	for name, envName := range s.OAuth {
		if name == "" {
			return fmt.Errorf("oauth: empty credential name")
		}
		if envName == "" {
			return fmt.Errorf("oauth.%s: empty environment variable name", name)
		}
		if strings.ContainsAny(envName, "= \t\n\x00") {
			return fmt.Errorf("oauth.%s = %q: not a valid environment variable name", name, envName)
		}
		if prev, dup := seen[envName]; dup {
			return fmt.Errorf("%s and oauth.%s both map to %s", prev, name, envName)
		}
		seen[envName] = "oauth." + name
	}
	if err := s.validateEnv(seen); err != nil {
		return err
	}
	if len(s.OAuth) > 0 && !s.EnvDelivery() {
		return fmt.Errorf("oauth requires delivery = %q or exec: an access token must not be rendered into script text", DeliveryEnv)
	}
	if s.Timeout.Duration < 0 {
		return fmt.Errorf("timeout = %s: must not be negative", s.Timeout.Duration)
	}
	return nil
}

// validateEnv checks [env] against the rules in docs/command-env.md. claimed
// maps an environment variable name to the table that already owns it.
func (s *Spec) validateEnv(claimed map[string]string) error {
	names := make([]string, 0, len(s.Env))
	for n := range s.Env {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		if !reEnvName.MatchString(n) {
			return fmt.Errorf("env.%q: not a valid environment variable name (want [A-Za-z_][A-Za-z0-9_]*)", n)
		}
		if reservedEnv[n] {
			return fmt.Errorf("env.%s: reserved, hush controls it for every child", n)
		}
		if word := credentialWord(n); word != "" {
			return fmt.Errorf("env.%s: %s belongs in [secrets] or [oauth]; [env] is plaintext on disk", n, word)
		}
		v := s.Env[n]
		if strings.Contains(v, "AGE-ENC[") {
			return fmt.Errorf("env.%s: an encrypted value belongs in secrets.toml, where hush will decrypt it", n)
		}
		if strings.ContainsAny(v, "\x00") {
			return fmt.Errorf("env.%s: value contains a NUL byte", n)
		}
		if owner, dup := claimed[n]; dup {
			return fmt.Errorf("%s and env.%s both map to %s: a credential must not be shadowed by plain text", owner, n, n)
		}
	}
	return nil
}

var reEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reservedEnv names the variables hush sets for the child itself. PATH is the
// one that matters: the shims directory is stripped from it so a brokered
// command cannot re-enter hush, and a spec that overwrote PATH would put it
// back. The loader variables are here because they choose code the child runs.
var reservedEnv = map[string]bool{
	"PATH":                  true,
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"LD_AUDIT":              true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
}

// credentialWords are the words a credential usually wears in a variable
// name. Names are checked, values are not: see docs/command-env.md.
var credentialWords = []string{
	"SECRET", "PASSWORD", "PASSWD", "PASSPHRASE", "TOKEN",
	"CREDENTIAL", "PRIVATE_KEY", "API_KEY", "APIKEY", "ACCESS_KEY",
}

// credentialWord returns the first credential word a name contains, or "".
func credentialWord(name string) string {
	upper := strings.ToUpper(name)
	for _, w := range credentialWords {
		if strings.Contains(upper, w) {
			return w
		}
	}
	return ""
}

// PlainEnv renders [env] as KEY=value, sorted by name so a child's
// environment is deterministic.
func (s *Spec) PlainEnv() []string {
	if len(s.Env) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.Env))
	for n := range s.Env {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n+"="+s.Env[n])
	}
	return out
}

// OAuthEnv resolves each declared oauth credential to a current access
// token through the agent.
//
// get is the resolver (client.OAuthGet). Errors name the credential, since
// the usual cause is simply that the CLI has never logged in.
func (s *Spec) OAuthEnv(get func(string) (string, error)) ([]string, error) {
	if len(s.OAuth) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(s.OAuth))
	for n := range s.OAuth {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]string, 0, len(names))
	for _, n := range names {
		tok, err := get(n)
		if err != nil {
			return nil, fmt.Errorf("oauth credential %q: %w (try: hush oauth login %s)", n, err, n)
		}
		if tok == "" {
			return nil, fmt.Errorf("oauth credential %q has no access token (try: hush oauth login %s)", n, n)
		}
		out = append(out, s.OAuth[n]+"="+tok)
	}
	return out, nil
}

// SecretEnv maps decrypted values onto the environment names this spec
// declares. A declared key with no matching secret is an error: silently
// handing a child an empty credential produces a confusing failure much
// later, usually as an opaque 401.
func (s *Spec) SecretEnv(values map[string]string) ([]string, error) {
	if len(s.Secrets) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(s.Secrets))
	for k := range s.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		v, ok := values[k]
		if !ok {
			return nil, fmt.Errorf("secrets.%s declared in %s but not present in secrets.toml", k, SpecFile)
		}
		out = append(out, s.Secrets[k]+"="+v)
	}
	return out, nil
}
