package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/jack-work/hush/internal/secrets"
)

// The `secret` group gathers everything that moves plaintext into and out
// of a command's secrets.toml. These were five top-level verbs — hush,
// edit, encrypt, encrypt-value, decrypt-value — plus `lock`, which was
// `encrypt` over every command instead of one. Six entries in --help for
// one job, and `encrypt` vs `encrypt-value` vs `lock` gave no hint about
// which operated on a file, a string, or the whole store.

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage the secrets attached to hush commands",
	Long: `Secrets live in ~/.config/hush/commands/<name>/secrets.toml, one file per
command, encrypted per value so git sees which key changed and not what.`,
}

var (
	sealKeys []string
	sealOut  string
)

func init() {
	sealCmd.Flags().StringSliceVar(&sealKeys, "key", nil, "seal only these keys (default: every plaintext value)")
	sealCmd.Flags().StringVarP(&sealOut, "out", "o", "", "write elsewhere instead of overwriting secrets.toml (single command only)")
	secretCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(secretCmd)
}

var sealCmd = &cobra.Command{
	Use:   "seal [name]",
	Short: "Encrypt plaintext values in a command's secrets.toml",
	Long: `Encrypt any plaintext (non-AGE-ENC) value in place, so a file you have just
edited by hand goes back to being unreadable.

With no name, every command is sealed — the sweep you run before committing.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runSeal,
}

func runSeal(cmd *cobra.Command, args []string) error {
	recipient, err := loadRecipient()
	if err != nil {
		return err
	}

	// One command: honour --key and --out, and complain about a missing
	// file, since the user named something specific.
	if len(args) == 1 {
		path := filepath.Join(cfg.CommandsDir, args[0], "secrets.toml")
		n, err := sealFile(path, recipient, sealKeys, sealOut)
		if err != nil {
			return err
		}
		if n == 0 {
			fmt.Fprintln(os.Stderr, "nothing to seal")
			return nil
		}
		fmt.Fprintf(os.Stderr, "sealed %d value(s)\n", n)
		return nil
	}

	if len(sealKeys) > 0 || sealOut != "" {
		return fmt.Errorf("--key and --out apply to a single command; name one")
	}

	names := listCommands()
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "no commands found")
		return nil
	}

	total := 0
	for _, name := range names {
		path := filepath.Join(cfg.CommandsDir, name, "secrets.toml")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		n, err := sealFile(path, recipient, nil, "")
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "  %s: sealed %d value(s)\n", name, n)
			total += n
		}
	}

	if total == 0 {
		fmt.Fprintln(os.Stderr, "everything is already sealed")
	} else {
		fmt.Fprintf(os.Stderr, "sealed %d value(s) total\n", total)
	}
	return nil
}

// sealFile encrypts plaintext values in one secrets.toml and reports how
// many it changed. keys, when non-empty, restricts the work to those keys
// and makes a missing key an error — naming a key you do not have is a
// typo worth hearing about. out redirects the write.
func sealFile(path string, recipient age.Recipient, keys []string, out string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read secrets: %w", err)
	}

	var values map[string]string
	if err := toml.Unmarshal(data, &values); err != nil {
		return 0, fmt.Errorf("parse secrets: %w", err)
	}

	targets := keys
	if len(targets) == 0 {
		for k, v := range values {
			if !secrets.IsEncrypted(v) {
				targets = append(targets, k)
			}
		}
	}

	count := 0
	for _, k := range targets {
		v, ok := values[k]
		if !ok {
			return 0, fmt.Errorf("key %q not found in %s", k, path)
		}
		if secrets.IsEncrypted(v) {
			if len(keys) > 0 {
				fmt.Fprintf(os.Stderr, "  %s: already sealed, skipping\n", k)
			}
			continue
		}
		enc, err := secrets.EncryptValue(v, recipient)
		if err != nil {
			return 0, fmt.Errorf("seal %q: %w", k, err)
		}
		values[k] = enc
		count++
	}

	if count == 0 {
		return 0, nil
	}

	encoded, err := secrets.MarshalTOML(values)
	if err != nil {
		return 0, err
	}
	dest := path
	if out != "" {
		dest = out
	}
	if err := os.WriteFile(dest, encoded, 0600); err != nil {
		return 0, err
	}
	return count, nil
}

// loadRecipient reads the public half of the identity. Encrypting needs
// only the public key, so it works with no agent and no passphrase.
func loadRecipient() (age.Recipient, error) {
	pubPath := cfg.IdentityFile + ".pub"
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w (run 'hush init' first)", err)
	}
	return age.ParseX25519Recipient(strings.TrimSpace(string(pubData)))
}
