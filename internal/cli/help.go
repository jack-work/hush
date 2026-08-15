package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(helpCmd)
}

var helpCmd = &cobra.Command{
	Use:   "help",
	Short: "Show help and available commands",
	RunE:  runHelp,
}

func runHelp(cmd *cobra.Command, args []string) error {
	// The built-in list is cobra's to render. Keeping a second copy here
	// meant it drifted the moment a verb was renamed — it was still
	// advertising `edit`, `lock`, `encrypt-value` and `decrypt-value`
	// after all four had gone.
	if err := cmd.Root().Help(); err != nil {
		return err
	}

	commands := listCommands()
	shown := 0
	for _, c := range commands {
		if !c.runnable() {
			continue // litter; `hush status` reports it, help does not advertise it
		}
		if shown == 0 {
			fmt.Printf("\nYour commands (%s):\n", cfg.CommandsDir)
		}
		shown++
		if !c.hasScript {
			fmt.Printf("  %-16s config-only — secrets for library use\n", c.name)
			continue
		}
		detail := ""
		if c.hasSecrets {
			detail = " (has secrets)"
		}
		fmt.Printf("  %-16s hush %s [args...]%s\n", c.name, c.name, detail)
	}
	if shown == 0 {
		fmt.Println("\nNo commands yet. Run 'hush secret new <name>' to create one.")
	}

	return nil
}
