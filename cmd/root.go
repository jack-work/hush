package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gluck/hush/config"
)

var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:   "hush [command] [args...]",
	Short: "Secret-injecting command runner",
	Long: `hush is a secret-injecting command runner. Built-in commands: init, up,
encrypt-value. Any other argument is treated as a hush command name and
looked up in ~/.config/hush/commands/.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		cfg, err = config.Load()
		return err
	},
	// When no built-in subcommand matches, treat args as a hush command.
	Args: cobra.ArbitraryArgs,
	RunE: runCmd,
}

func init() {
	rootCmd.FParseErrWhitelist.UnknownFlags = true
	// Disable cobra's default help command — we have our own.
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
}

func Execute() {
	// Cobra doesn't natively route unknown subcommands to RunE — it errors.
	// Intercept: if the first arg looks like an unknown subcommand (not a flag,
	// not a built-in), rewrite it as a positional arg by inserting "--".
	if len(os.Args) > 1 {
		first := os.Args[1]
		if first != "" && first[0] != '-' && !isBuiltinCmd(first) {
			// Rewrite: hush brave foo → hush -- brave foo
			// This makes cobra pass all args to rootCmd.RunE.
			newArgs := []string{os.Args[0], "--"}
			newArgs = append(newArgs, os.Args[1:]...)
			os.Args = newArgs
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func isBuiltinCmd(name string) bool {
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == name || cmd.HasAlias(name) {
			return true
		}
	}
	// Also check built-in cobra commands.
	switch name {
	case "help", "completion":
		return true
	}
	return false
}
