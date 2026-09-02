package cli

import (
	"fmt"
	"os"
	"path/filepath"
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
//	script — secrets are rendered into the script text through {{.name}}.
//	         The legacy default. Kept working forever, but it means the
//	         plaintext lives inside a program that an interpreter parses,
//	         which is how caller data and secret data end up in the same
//	         lexer.
//	env    — secrets never touch the script. Each is placed in the child's
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
	// When set, no command script is read and Delivery is implicitly "env" —
	// there is no script for a secret to be rendered into.
	Exec string `toml:"exec"`

	// Args are fixed arguments placed before the caller's own. They are
	// passed as argv elements, never concatenated, so a caller cannot
	// escape from a value position into a flag position.
	Args []string `toml:"args"`

	// Secrets maps a key in secrets.toml to the environment variable the
	// child should see it under: token = "BRAVE_TOKEN".
	Secrets map[string]string `toml:"secrets"`

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
			return fmt.Errorf("secrets.%s and secrets.%s both map to %s", prev, key, envName)
		}
		seen[envName] = key
	}
	if s.Timeout.Duration < 0 {
		return fmt.Errorf("timeout = %s: must not be negative", s.Timeout.Duration)
	}
	return nil
}

// SecretEnv maps decrypted values onto the environment names this spec
// declares. A declared key with no matching secret is an error — silently
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
