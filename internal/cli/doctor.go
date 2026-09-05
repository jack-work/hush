package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
)

// `hush doctor` reports, per command, how its credentials reach the process
// that uses them: the worklist for migrating off script-embedded secrets.
//
// Nothing here rewrites anything. Shell quoting is context-sensitive enough
// that a mechanical rewrite of {{.token}} inside single quotes would produce
// a literal $VAR and a mystifying failure; the diagnosis is automatic, the
// edit is yours.

func init() {
	doctorCmd.Flags().BoolVar(&doctorMigrate, "migrate", false,
		"print the suggested command.toml and edits for each finding")
	rootCmd.AddCommand(doctorCmd)
}

var doctorMigrate bool

var doctorCmd = &cobra.Command{
	Use:   "doctor [command]",
	Short: "Report how each command delivers its secrets",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDoctor,
}

// Finding levels, worst first.
type level int

const (
	levelOK level = iota
	levelNote
	levelWarn
)

type finding struct {
	level level
	text  string
}

type diagnosis struct {
	name     string
	delivery string
	findings []finding
}

func (d diagnosis) worst() level {
	w := levelOK
	for _, f := range d.findings {
		if f.level > w {
			w = f.level
		}
	}
	return w
}

var (
	// {{.Args}} / {{index.Args 0}}, caller data rendered into program text.
	reTemplateArgs = regexp.MustCompile(`{{-?\s*(?:index\s+)?\.Args\b`)
	// {{.name}} for any name that is not a builtin: a secret reference.
	reTemplateField = regexp.MustCompile(`{{-?\s*\.([A-Za-z_][A-Za-z0-9_]*)`)
)

func runDoctor(cmd *cobra.Command, args []string) error {
	var names []string
	if len(args) == 1 {
		names = []string{args[0]}
	} else {
		entries, err := os.ReadDir(cfg.CommandsDir)
		if err != nil {
			return fmt.Errorf("read commands dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
	}
	if len(names) == 0 {
		fmt.Printf("no commands in %s\n", cfg.CommandsDir)
		return nil
	}

	var warned int
	for _, name := range names {
		d, err := diagnose(name)
		if err != nil {
			fmt.Printf("%-14s %s\n", name, err)
			warned++
			continue
		}
		mark := map[level]string{levelOK: "ok  ", levelNote: "note", levelWarn: "WARN"}[d.worst()]
		fmt.Printf("%s %-14s %-7s", mark, d.name, d.delivery)
		if len(d.findings) == 0 {
			fmt.Println()
		} else {
			for i, f := range d.findings {
				if i > 0 {
					fmt.Printf("%s %-14s %-7s", "    ", "", "")
				}
				fmt.Println(f.text)
			}
		}
		if d.worst() == levelWarn {
			warned++
			if doctorMigrate {
				fmt.Print(migrationHint(d))
			}
		}
	}

	if warned > 0 && !doctorMigrate {
		fmt.Fprintf(os.Stderr, "\n%d command(s) need attention. `hush doctor --migrate` prints suggested edits.\n", warned)
	}
	return nil
}

func diagnose(name string) (diagnosis, error) {
	dir := filepath.Join(cfg.CommandsDir, name)
	if _, err := os.Stat(dir); err != nil {
		return diagnosis{}, fmt.Errorf("no such command")
	}
	spec, err := LoadSpec(dir)
	if err != nil {
		return diagnosis{}, err
	}

	d := diagnosis{name: name, delivery: spec.Delivery}
	if spec.Scriptless() {
		d.delivery = "exec"
		d.findings = append(d.findings, finding{levelOK, "runs " + spec.Exec + " directly, no interpreter"})
		return d, nil
	}

	var script string
	for _, candidate := range commandScriptNames() {
		if b, err := os.ReadFile(filepath.Join(dir, candidate)); err == nil {
			script = string(b)
			break
		}
	}
	if script == "" {
		d.delivery = "config"
		d.findings = append(d.findings, finding{levelNote, "config-only: read through the client library"})
		return d, nil
	}

	secretKeys, _ := secretKeyNames(filepath.Join(dir, "secrets.toml"))

	if reTemplateArgs.MatchString(script) {
		d.findings = append(d.findings, finding{levelWarn,
			"renders caller arguments into script text ({{.Args}}), use positional \"$1\" / \"$@\""})
	}

	if !spec.EnvDelivery() {
		var used []string
		for _, m := range reTemplateField.FindAllStringSubmatch(script, -1) {
			field := m[1]
			if field == "Args" || field == "Cmd" {
				continue
			}
			if _, isSecret := secretKeys[field]; isSecret || len(secretKeys) == 0 {
				used = append(used, field)
			}
		}
		used = dedupe(used)
		if len(used) > 0 {
			d.findings = append(d.findings, finding{levelWarn,
				"secrets rendered into script text: " + strings.Join(used, ", ")})
		}
	}

	if len(d.findings) == 0 && spec.EnvDelivery() {
		d.findings = append(d.findings, finding{levelOK, "secrets delivered through the environment"})
	}
	return d, nil
}

// secretKeyNames returns the key names in a secrets.toml without decrypting
// anything: doctor never needs the values, and never asks the agent.
func secretKeyNames(path string) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	var raw map[string]string
	if err := toml.Unmarshal(data, &raw); err != nil {
		return out, err
	}
	for k := range raw {
		out[k] = struct{}{}
	}
	return out, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func migrationHint(d diagnosis) string {
	dir := filepath.Join(cfg.CommandsDir, d.name)
	keys, _ := secretKeyNames(filepath.Join(dir, "secrets.toml"))
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("\n     ── suggested " + filepath.Join(dir, SpecFile) + " ──\n")
	b.WriteString("     delivery = \"env\"\n")
	if len(names) > 0 {
		b.WriteString("\n     [secrets]\n")
		for _, k := range names {
			b.WriteString(fmt.Sprintf("     %s = %q\n", k, envNameFor(d.name, k)))
		}
	}
	b.WriteString("\n     ── then in command.sh ──\n")
	for _, k := range names {
		b.WriteString(fmt.Sprintf("     {{.%s}}  ->  $%s      (drop any surrounding quotes' escaping)\n",
			k, envNameFor(d.name, k)))
	}
	b.WriteString("     {{index .Args 0}}  ->  \"$1\"\n")
	b.WriteString("     {{.Args}}          ->  \"$@\"\n\n")
	return b.String()
}

// envNameFor suggests HUSH_<COMMAND>_<KEY>, uppercased: a name unlikely to
// collide with anything already in the environment.
func envNameFor(cmd, key string) string {
	clean := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToUpper(s) {
			if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			} else {
				b.WriteRune('_')
			}
		}
		return b.String()
	}
	return "HUSH_" + clean(cmd) + "_" + clean(key)
}
