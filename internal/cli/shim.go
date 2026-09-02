package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// A shim is a symlink to the hush binary, named after a hush command and
// placed on PATH ahead of the real tool. Invoked through it, hush dispatches
// on argv[0] and runs that command with the caller's arguments untouched.
//
// This is what makes a brokered credential invisible to the caller: a script
// or an agent runs `gh pr list` exactly as it always has, and the token is
// injected on the way past. Aliases cannot do this — they are not visible to
// #!/bin/sh scripts or to a program that calls exec directly.
//
// The pattern is well travelled: ccache shadows gcc this way, pyenv and
// rbenv ship a shims directory, busybox dispatches on argv[0].
//
// argv[0] is a convenience, not an identity: anyone may copy and rename a
// link. It selects which command runs; it must never be what authorizes it.

// shimDirName is the subdirectory of the hush state directory holding shims.
const shimDirName = "bin"

// shimDir returns the absolute shims directory, or "" if config has not
// been loaded (which happens on the argv[0] path before cobra runs).
func shimDir() string {
	if cfg == nil {
		return ""
	}
	return filepath.Join(cfg.StateDir, shimDirName)
}

// shimCommandName inspects argv[0] and returns the hush command it names,
// or "" when hush was invoked under its own name.
//
// Dispatch is deliberately narrow: it fires only when the path we were
// invoked through lives in the shims directory. Treating *any* argv[0] that
// isn't "hush" as a command name would hijack every development build,
// every `hush.test` binary, and every renamed copy — surprising, and a
// nuisance to debug. A shim is a link we installed, in a directory we own.
func shimCommandName(argv0 string) string {
	base := filepath.Base(argv0)
	base = strings.TrimSuffix(base, ".exe")
	if base == "hush" || base == "" || base == "." || base == string(os.PathSeparator) {
		return ""
	}

	dir := shimDir()
	if dir == "" {
		return ""
	}
	invoked := argv0
	if !strings.ContainsRune(invoked, os.PathSeparator) {
		// Found through PATH: resolve to the entry that was actually run.
		found, err := exec.LookPath(invoked)
		if err != nil {
			return ""
		}
		invoked = found
	}
	abs, err := filepath.Abs(invoked)
	if err != nil {
		return ""
	}
	if filepath.Clean(filepath.Dir(abs)) != filepath.Clean(dir) {
		return ""
	}
	return base
}

func init() {
	shimCmd.AddCommand(shimInstallCmd, shimListCmd, shimRemoveCmd, shimDirCmd)
	rootCmd.AddCommand(shimCmd)
}

var shimCmd = &cobra.Command{
	Use:   "shim",
	Short: "Manage command shims: run brokered commands under their real names",
	Long: `A shim is a symlink named after a hush command that points at the hush
binary. With the shims directory early on PATH, running

    gh pr list

runs hush's "gh" command, which injects the credential and execs the real
gh with your arguments untouched. Scripts and programs that exec by name
pick this up; a shell alias would not.

The shims directory must precede the real tool on PATH. hush removes the
shims directory from the environment of every command it runs, so a
brokered command that invokes the real binary by name does not re-enter
hush.`,
}

var shimDirCmd = &cobra.Command{
	Use:   "dir",
	Short: "Print the shims directory",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(shimDir())
		return nil
	},
}

var shimInstallCmd = &cobra.Command{
	Use:   "install <command>...",
	Short: "Create a shim for one or more hush commands",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runShimInstall,
}

func runShimInstall(cmd *cobra.Command, args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate hush binary: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve hush binary: %w", err)
	}

	dir := shimDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create shims dir: %w", err)
	}

	for _, name := range args {
		if name != filepath.Base(name) || name == "hush" {
			return fmt.Errorf("invalid shim name %q", name)
		}
		if _, err := os.Stat(filepath.Join(cfg.CommandsDir, name)); err != nil {
			return fmt.Errorf("no hush command named %q (looked in %s)", name, cfg.CommandsDir)
		}
		link := filepath.Join(dir, name)
		if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("replace %s: %w", link, err)
		}
		if err := os.Symlink(exe, link); err != nil {
			return fmt.Errorf("link %s: %w", link, err)
		}
		fmt.Printf("%s -> %s\n", link, exe)
	}

	if !onPath(dir) {
		fmt.Fprintf(os.Stderr, "\nnote: %s is not on PATH. add it ahead of the real tools:\n"+
			"  export PATH=\"%s:$PATH\"\n", dir, dir)
	}
	return nil
}

var shimListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List installed shims and what they shadow",
	Args:  cobra.NoArgs,
	RunE:  runShimList,
}

func runShimList(cmd *cobra.Command, args []string) error {
	dir := shimDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("no shims installed (%s does not exist)\n", dir)
			return nil
		}
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		fmt.Printf("no shims installed in %s\n", dir)
		return nil
	}

	active := onPath(dir)
	for _, n := range names {
		shadowed := lookPathExcluding(n, dir)
		switch {
		case shadowed == "":
			fmt.Printf("%-16s (no real binary on PATH)\n", n)
		default:
			fmt.Printf("%-16s shadows %s\n", n, shadowed)
		}
	}
	if !active {
		fmt.Fprintf(os.Stderr, "\nnote: %s is not on PATH — these shims are inert.\n", dir)
	}
	return nil
}

var shimRemoveCmd = &cobra.Command{
	Use:   "rm <command>...",
	Short: "Remove shims",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, name := range args {
			link := filepath.Join(shimDir(), filepath.Base(name))
			if err := os.Remove(link); err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintf(os.Stderr, "no shim %q\n", name)
					continue
				}
				return err
			}
			fmt.Printf("removed %s\n", link)
		}
		return nil
	},
}

func onPath(dir string) bool {
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == dir {
			return true
		}
	}
	return false
}

// lookPathExcluding finds name on PATH, ignoring one directory — used to
// report what a shim shadows without finding the shim itself.
func lookPathExcluding(name, skip string) string {
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == skip || p == "" {
			continue
		}
		candidate := filepath.Join(p, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate
		}
	}
	return ""
}
