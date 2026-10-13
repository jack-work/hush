//go:build !windows

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jack-work/hush/config"
)

// run a built child and capture its stdout.
func capture(t *testing.T, cmd *exec.Cmd, timeout time.Duration) string {
	t.Helper()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := runBrokered(cmd, timeout); err != nil {
		t.Fatalf("run: %v\noutput: %s", err, out.String())
	}
	return out.String()
}

// The load-bearing property of Phase 0: a rendered script carrying a secret
// must not be visible in the child's /proc/<pid>/cmdline, which is mode 444
// and readable by every process on the machine.
func TestScriptIsNotVisibleInChildCmdline(t *testing.T) {
	const secret = "s3cr3t-canary-value"
	spec := &Spec{Delivery: DeliveryScript}
	script := "cat /proc/$$/cmdline | tr '\\0' ' '; echo; echo TOKEN_WAS={{.token}} >/dev/null"

	cmd, cleanup, err := buildChild(spec, "canary", "command.sh", script,
		map[string]string{"token": secret}, nil, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	out := capture(t, cmd, 10*time.Second)

	if strings.Contains(out, secret) {
		t.Errorf("secret leaked into the child's cmdline:\n%s", out)
	}
	if !strings.Contains(out, "/dev/fd/") {
		t.Errorf("expected the script to be passed on a file descriptor, got cmdline: %s", out)
	}
}

// The script must still actually run, and still see its secret, under the
// legacy delivery. This is the compatibility guarantee.
func TestLegacyScriptDeliveryStillRendersSecrets(t *testing.T) {
	spec := &Spec{Delivery: DeliveryScript}
	cmd, cleanup, err := buildChild(spec, "legacy", "command.sh",
		"echo got={{.token}}", map[string]string{"token": "abc123"}, nil, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if out := capture(t, cmd, 10*time.Second); !strings.Contains(out, "got=abc123") {
		t.Errorf("output = %q", out)
	}
}

// Positional arguments reach the script as "$@" and are never program text.
// The classic injection payload must come back as an inert string.
func TestCallerArgumentsAreNotProgramText(t *testing.T) {
	spec := &Spec{Delivery: DeliveryScript}
	payload := `'; echo PWNED; '`
	cmd, cleanup, err := buildChild(spec, "args", "command.sh",
		`printf 'arg=[%s]\n' "$1"`, nil, []string{payload}, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	out := capture(t, cmd, 10*time.Second)
	// The payload text itself contains "PWNED", so look for evidence of
	// *execution*: a line that is nothing but the echoed word.
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "PWNED" {
			t.Errorf("argument was evaluated as program text:\n%s", out)
		}
	}
	if !strings.Contains(out, "arg=["+payload+"]") {
		t.Errorf("argument did not arrive intact: %q", out)
	}
}

func TestEnvDeliveryPutsSecretInEnvironmentNotScript(t *testing.T) {
	spec := &Spec{Delivery: DeliveryEnv, Secrets: map[string]string{"token": "MY_TOKEN"}}
	cmd, cleanup, err := buildChild(spec, "envcmd", "command.sh",
		`echo token=$MY_TOKEN`, map[string]string{"token": "xyz789"}, nil, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if out := capture(t, cmd, 10*time.Second); !strings.Contains(out, "token=xyz789") {
		t.Errorf("output = %q", out)
	}
}

// Under env delivery a leftover {{.token}} must fail loudly rather than
// render empty — an empty credential fails much later, as an opaque 401.
func TestEnvDeliveryRejectsLeftoverSecretTemplate(t *testing.T) {
	spec := &Spec{Delivery: DeliveryEnv, Secrets: map[string]string{"token": "MY_TOKEN"}}
	_, cleanup, err := buildChild(spec, "stale", "command.sh",
		`echo token={{.token}}`, map[string]string{"token": "xyz"}, nil, nil)
	defer cleanup()
	if err == nil {
		t.Fatal("expected an error naming the migration")
	}
	if !strings.Contains(err.Error(), "MY_TOKEN") {
		t.Errorf("error should name the env var to use, got: %v", err)
	}
}

func TestScriptlessExecRunsBinaryWithNoShell(t *testing.T) {
	spec := &Spec{
		Exec:     "/bin/echo",
		Delivery: DeliveryEnv,
		Args:     []string{"fixed"},
	}
	cmd, cleanup, err := buildChild(spec, "echo", "", "", nil, []string{"caller"}, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(cmd.Path) == "sh" {
		t.Fatal("scriptless commands must not go through a shell")
	}
	out := capture(t, cmd, 10*time.Second)
	if strings.TrimSpace(out) != "fixed caller" {
		t.Errorf("output = %q, want fixed args before caller args", out)
	}
}

// A scriptless command cannot be injected into, because there is no
// interpreter to inject into. The payload must arrive as one inert argv
// element.
func TestScriptlessExecIsInjectionProof(t *testing.T) {
	spec := &Spec{Exec: "/bin/echo", Delivery: DeliveryEnv}
	payloads := []string{"$(echo PWNED)", "`echo PWNED`", "; echo PWNED"}
	cmd, cleanup, err := buildChild(spec, "echo", "", "", nil, payloads, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	out := strings.TrimSpace(capture(t, cmd, 10*time.Second))
	// echo prints its argv verbatim: the payloads must come back as literal
	// text, proving no shell ever expanded them.
	if want := strings.Join(payloads, " "); out != want {
		t.Errorf("argv was interpreted rather than passed through:\n got %q\nwant %q", out, want)
	}
}

// A command's [env] is a property of the command, so it must beat whatever
// the caller happened to export, and it must appear exactly once.
func TestPlainEnvOverridesInheritedValue(t *testing.T) {
	t.Setenv("AWS_REQUEST_CHECKSUM_CALCULATION", "WHEN_SUPPORTED")
	spec := &Spec{
		Delivery: DeliveryScript,
		Env:      map[string]string{"AWS_REQUEST_CHECKSUM_CALCULATION": "WHEN_REQUIRED"},
	}
	cmd, cleanup, err := buildChild(spec, "files", "command.sh",
		"echo mode=$AWS_REQUEST_CHECKSUM_CALCULATION\n", nil, nil, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, kv := range cmd.Env {
		if strings.HasPrefix(kv, "AWS_REQUEST_CHECKSUM_CALCULATION=") {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("the name appears %d times in the child environment, want 1: %v", seen, cmd.Env)
	}
	if out := capture(t, cmd, 10*time.Second); !strings.Contains(out, "mode=WHEN_REQUIRED") {
		t.Errorf("inherited value won over the spec: %q", out)
	}
}

// Plain env is orthogonal to delivery: a legacy script command gets it too,
// alongside secrets that are still rendered into the template.
func TestPlainEnvReachesLegacyScriptDelivery(t *testing.T) {
	spec := &Spec{
		Delivery: DeliveryScript,
		Env:      map[string]string{"REGION": "spain"},
	}
	cmd, cleanup, err := buildChild(spec, "legacy", "command.sh",
		"echo region=$REGION token={{.token}}\n", map[string]string{"token": "xyz"}, nil, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if out := capture(t, cmd, 10*time.Second); !strings.Contains(out, "region=spain token=xyz") {
		t.Errorf("output = %q", out)
	}
}

func TestChildEnvStripsShimDirFromPath(t *testing.T) {
	// stripShimDir consults cfg for the shims location; stand up a minimal
	// one rather than skipping, since this is the anti-recursion guarantee.
	saved := cfg
	t.Cleanup(func() { cfg = saved })
	cfg = &config.Config{StateDir: "/tmp/hush-test-state"}

	dir := shimDir()
	t.Setenv("PATH", dir+":/usr/bin:/bin")

	env := childEnv(nil, nil)
	var path string
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			path = strings.TrimPrefix(kv, "PATH=")
		}
	}
	for _, p := range strings.Split(path, ":") {
		if p == dir {
			t.Fatalf("shims dir survived in child PATH %q — a brokered command "+
				"invoking the real binary by name would re-enter hush", path)
		}
	}
	if !strings.Contains(path, "/usr/bin") {
		t.Errorf("stripping removed too much: %q", path)
	}
}

func TestTimeoutKillsRunawayChild(t *testing.T) {
	spec := &Spec{Delivery: DeliveryScript}
	cmd, cleanup, err := buildChild(spec, "sleepy", "command.sh", "sleep 30", nil, nil, nil)
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = runBrokered(cmd, 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("timeout took %s to fire", elapsed)
	}
}

// Shim dispatch must fire only for links inside the shims directory: a
// development build named hush-broker, or a hush.test binary, must behave
// like plain hush.
func TestShimCommandName(t *testing.T) {
	saved := cfg
	t.Cleanup(func() { cfg = saved })
	base := t.TempDir()
	cfg = &config.Config{StateDir: base}
	shims := filepath.Join(base, shimDirName)

	cases := map[string]string{
		filepath.Join(shims, "gh"):    "gh",
		filepath.Join(shims, "brave"): "brave",
		filepath.Join(shims, "hush"):  "",
		"hush":                        "",
		"/usr/bin/hush":               "",
		"hush.exe":                    "",
		"/tmp/hush-broker":            "", // a dev build is not a shim
		"/usr/local/bin/gh":           "", // the real tool is not a shim
		"./brave":                     "",
	}
	for argv0, want := range cases {
		if got := shimCommandName(argv0); got != want {
			t.Errorf("shimCommandName(%q) = %q, want %q", argv0, got, want)
		}
	}
}

// The staged script must have no reachable path: nothing another process
// could open by name.
func TestStagedScriptHasNoPath(t *testing.T) {
	f, err := scriptFile("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	link, err := os.Readlink(filepath.Join("/proc/self/fd", itoaFD(f.Fd())))
	if err != nil {
		t.Skipf("cannot inspect fd: %v", err)
	}
	if _, err := os.Stat(link); err == nil {
		t.Errorf("staged script is reachable at %s — it should be anonymous or unlinked", link)
	}
}

func itoaFD(fd uintptr) string {
	if fd == 0 {
		return "0"
	}
	var b []byte
	for fd > 0 {
		b = append([]byte{byte('0' + fd%10)}, b...)
		fd /= 10
	}
	return string(b)
}
