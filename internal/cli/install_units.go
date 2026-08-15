package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/internal/singleton"
	"github.com/jack-work/hush/internal/units"
)

var (
	flagUnitsPrint    bool
	flagUnitsNoEnable bool
)

func init() {
	installUnitsCmd.Flags().BoolVar(&flagUnitsPrint, "print", false,
		"write the rendered units to stdout instead of installing them")
	installUnitsCmd.Flags().BoolVar(&flagUnitsNoEnable, "no-enable", false,
		"install the files but do not reload or enable them")
	rootCmd.AddCommand(installUnitsCmd)
}

var installUnitsCmd = &cobra.Command{
	Use:   "install-units",
	Short: "Install the systemd user units that start the agent on demand",
	Long: `Install hush-agent.socket and hush-agent.service into your systemd
user directory, then enable the socket.

Afterwards nothing needs starting by hand: the first client to touch
the agent socket makes systemd start the agent, which unlocks by
whatever unlock.method your hush.toml names. When the TTL expires the
agent exits and the socket re-arms.

  hush install-units             install, reload, enable --now
  hush install-units --no-enable install the files only
  hush install-units --print     render to stdout (e.g. to pipe elsewhere)`,
	RunE: runInstallUnits,
}

func runInstallUnits(cmd *cobra.Command, args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		// A unit pointing at ~/.nix-profile/bin/hush would follow the
		// profile; one pointing at the store path is pinned. Neither is
		// wrong, but the resolved path is what the user is running now.
		exe = resolved
	}

	rendered := units.Render(exe, cfg.RuntimeDir)

	if flagUnitsPrint {
		for i, u := range rendered {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("# %s\n%s", u.Name, u.Content)
		}
		return nil
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd user units are Linux-only (this is %s); use --print to see them", runtime.GOOS)
	}

	dir, err := units.Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	for _, u := range rendered {
		path := filepath.Join(dir, u.Name)
		if err := os.WriteFile(path, []byte(u.Content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Printf("wrote %s\n", path)
	}

	if flagUnitsNoEnable {
		fmt.Printf("\nnot enabled (--no-enable). When you want it:\n" +
			"  systemctl --user daemon-reload\n" +
			"  systemctl --user enable --now hush-agent.socket\n")
		return nil
	}

	// systemd unlinks the socket path before binding it. A self-bound
	// agent still holding that path would keep serving an inode nobody
	// can reach — so stop it first and let the socket unit start its
	// successor on demand, which is the whole point of the exercise.
	if free, _ := singleton.Free(filepath.Join(cfg.RuntimeDir, "agent.pid")); !free {
		fmt.Println("stopping the running agent; the socket unit will start the next one on demand")
		if err := runDown(cmd, nil); err != nil {
			return fmt.Errorf("stop running agent: %w", err)
		}
	}

	for _, argv := range [][]string{
		{"--user", "daemon-reload"},
		{"--user", "enable", "--now", "hush-agent.socket"},
	} {
		fmt.Printf("systemctl %s\n", joinArgs(argv))
		out, err := exec.Command("systemctl", argv...).CombinedOutput()
		if len(out) > 0 {
			os.Stderr.Write(out)
		}
		if err != nil {
			return fmt.Errorf("systemctl %s: %w", joinArgs(argv), err)
		}
	}

	fmt.Printf("\nthe agent now starts on demand. Check it with:\n" +
		"  systemctl --user status hush-agent.socket\n" +
		"  hush status\n")
	return nil
}

func joinArgs(argv []string) string {
	s := ""
	for i, a := range argv {
		if i > 0 {
			s += " "
		}
		s += a
	}
	return s
}
