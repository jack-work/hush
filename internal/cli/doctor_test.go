package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jack-work/hush/config"
)

func commandsDir(t *testing.T, cmds map[string]map[string]string) {
	t.Helper()
	root := t.TempDir()
	for name, files := range cmds {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for n, body := range files {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	prev := cfg
	cfg = &config.Config{CommandsDir: root}
	t.Cleanup(func() { cfg = prev })
}

func doctorOutput(t *testing.T, migrate bool, args ...string) string {
	t.Helper()
	prevMigrate := doctorMigrate
	doctorMigrate = migrate
	defer func() { doctorMigrate = prevMigrate }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prevOut, prevErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	runErr := runDoctor(nil, args)
	os.Stdout, os.Stderr = prevOut, prevErr
	w.Close()
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("doctor: %v\n%s", runErr, out)
	}
	return string(out)
}

const pipesRootToFigaro = "printf '%s' '{{.root}}' | figaro troupe create estate\n"

func secretsWithRoot() string { return "root = \"age-encrypted\"\n" }

// troupe-root pipes the troupe root into figaro on stdin: env delivery would
// put the root in figaro's environment and every child's, so script delivery
// is the reviewed choice. Saying so in command.toml is what makes it one.
func TestADeclaredScriptDeliveryIsANoteNotAWarning(t *testing.T) {
	commandsDir(t, map[string]map[string]string{
		"troupe-root": {
			"command.sh":   pipesRootToFigaro,
			"secrets.toml": secretsWithRoot(),
			SpecFile:       "delivery = \"script\"\n",
		},
	})
	d, err := diagnose("troupe-root")
	if err != nil {
		t.Fatal(err)
	}
	if d.worst() == levelWarn {
		t.Fatalf("a declared script delivery still warns: %+v", d.findings)
	}
	var note string
	for _, f := range d.findings {
		if f.level == levelNote && strings.Contains(f.text, "by declaration") {
			note = f.text
		}
	}
	if !strings.Contains(note, "root") {
		t.Fatalf("no note naming the rendered secret: %+v", d.findings)
	}
}

// Without the key, nothing changes: the legacy default still warns, with or
// without a command.toml.
func TestScriptDeliveryByDefaultStillWarns(t *testing.T) {
	commandsDir(t, map[string]map[string]string{
		"no-spec":     {"command.sh": pipesRootToFigaro, "secrets.toml": secretsWithRoot()},
		"spec-no-key": {"command.sh": pipesRootToFigaro, "secrets.toml": secretsWithRoot(), SpecFile: "description = \"x\"\n"},
	})
	for _, name := range []string{"no-spec", "spec-no-key"} {
		d, err := diagnose(name)
		if err != nil {
			t.Fatal(err)
		}
		if d.worst() != levelWarn {
			t.Fatalf("%s: default script delivery no longer warns: %+v", name, d.findings)
		}
	}
}

func TestMigrateSkipsADeclaredScriptCommandAndStillSuggestsForTheRest(t *testing.T) {
	commandsDir(t, map[string]map[string]string{
		"troupe-root": {"command.sh": pipesRootToFigaro, "secrets.toml": secretsWithRoot(), SpecFile: "delivery = \"script\"\n"},
		"declared-args": {
			"command.sh":   pipesRootToFigaro + "echo {{.Args}}\n",
			"secrets.toml": secretsWithRoot(),
			SpecFile:       "delivery = \"script\"\n",
		},
		"legacy": {"command.sh": pipesRootToFigaro, "secrets.toml": secretsWithRoot()},
	})
	out := doctorOutput(t, true)
	for _, declared := range []string{"troupe-root", "declared-args"} {
		if strings.Contains(out, filepath.Join(declared, SpecFile)) {
			t.Fatalf("--migrate suggested env delivery for the declared script command %s:\n%s", declared, out)
		}
	}
	if !strings.Contains(out, filepath.Join("legacy", SpecFile)) {
		t.Fatalf("--migrate stopped suggesting for an undeclared command:\n%s", out)
	}
}

// The declaration excuses rendered secrets only: caller arguments rendered
// into the script text are a separate hazard and still warn.
func TestADeclaredScriptStillWarnsAboutRenderedArguments(t *testing.T) {
	commandsDir(t, map[string]map[string]string{
		"args": {"command.sh": "echo {{.Args}}\n", SpecFile: "delivery = \"script\"\n"},
	})
	d, err := diagnose("args")
	if err != nil {
		t.Fatal(err)
	}
	if d.worst() != levelWarn {
		t.Fatalf("rendered caller arguments no longer warn under a declared script: %+v", d.findings)
	}
}
