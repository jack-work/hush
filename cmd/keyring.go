package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/zalando/go-keyring"
)

// The keyring subcommand mirrors `hush oauth`: a parent command that
// groups operations on a single backend. Today the operations are
// trivial round-trips through go-keyring; they exist so the user has
// a portable way to seed/inspect/clear the entry without having to
// know whether the platform is libsecret or wincred under the hood.

func init() {
	keyringCmd.AddCommand(keyringSetCmd)
	keyringCmd.AddCommand(keyringGetCmd)
	keyringCmd.AddCommand(keyringClearCmd)
	rootCmd.AddCommand(keyringCmd)
}

var keyringCmd = &cobra.Command{
	Use:   "keyring",
	Short: "Manage the hush passphrase entry in the OS keyring",
	Long: `The OS keyring (Secret Service on Linux, Keychain on macOS, Credential
Manager on Windows) can hold the hush passphrase so the agent unlocks
silently from a desktop session. Use these subcommands to seed and
inspect that entry.

The (service, account) pair comes from [unlock.keyring] in hush.toml
(defaults: hush / default). HUSH_KEYRING_SERVICE overrides the service
for dev shells.`,
}

var keyringSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Store the hush passphrase in the OS keyring (prompts twice)",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, acct := cfg.Unlock.Keyring.Service, cfg.Unlock.Keyring.Account
		if svc == "" || acct == "" {
			return fmt.Errorf("unlock.keyring.service and .account must be set in hush.toml")
		}

		fmt.Fprint(os.Stderr, "Enter passphrase: ")
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		if len(first) == 0 {
			return fmt.Errorf("passphrase cannot be empty")
		}
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		if string(first) != string(second) {
			// Wipe both before bailing.
			for i := range first {
				first[i] = 0
			}
			for i := range second {
				second[i] = 0
			}
			return fmt.Errorf("passphrases do not match")
		}
		for i := range second {
			second[i] = 0
		}

		if err := keyring.Set(svc, acct, string(first)); err != nil {
			return fmt.Errorf("keyring set (service=%q account=%q): %w", svc, acct, err)
		}
		for i := range first {
			first[i] = 0
		}

		fmt.Fprintf(os.Stderr, "Stored in keyring (service=%q, account=%q).\n", svc, acct)
		return nil
	},
}

var keyringGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show whether a hush passphrase is present in the keyring (never prints the value)",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, acct := cfg.Unlock.Keyring.Service, cfg.Unlock.Keyring.Account
		if svc == "" || acct == "" {
			return fmt.Errorf("unlock.keyring.service and .account must be set in hush.toml")
		}

		v, err := keyring.Get(svc, acct)
		if errors.Is(err, keyring.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "service=%q account=%q: ✗ not set\n", svc, acct)
			os.Exit(1)
			return nil
		}
		if err != nil {
			return fmt.Errorf("keyring get (service=%q account=%q): %w", svc, acct, err)
		}
		// Length is the only thing we'll surface. The value itself never
		// leaves this process — keyring entries are sensitive material
		// and a hush subcommand has no business printing one.
		fmt.Fprintf(os.Stderr, "service=%q account=%q: ✓ present (%d bytes)\n", svc, acct, len(v))
		return nil
	},
}

var keyringClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete the hush passphrase entry from the keyring",
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, acct := cfg.Unlock.Keyring.Service, cfg.Unlock.Keyring.Account
		if svc == "" || acct == "" {
			return fmt.Errorf("unlock.keyring.service and .account must be set in hush.toml")
		}

		err := keyring.Delete(svc, acct)
		if errors.Is(err, keyring.ErrNotFound) {
			fmt.Fprintf(os.Stderr, "service=%q account=%q: nothing to clear\n", svc, acct)
			return nil
		}
		if err != nil {
			return fmt.Errorf("keyring delete (service=%q account=%q): %w", svc, acct, err)
		}
		fmt.Fprintf(os.Stderr, "Cleared keyring entry (service=%q, account=%q).\n", svc, acct)
		return nil
	},
}
