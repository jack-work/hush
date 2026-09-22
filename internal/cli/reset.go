package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"github.com/jack-work/hush/internal/secrets"
)

// `reset` exists because the recovery path was a list of rm commands the
// user had to assemble from the error message, and the dangerous half of
// it was invisible: deleting identity.age alone leaves every secrets.toml
// sealed to a key nobody holds, and the next `hush init` produces an
// identity that decrypts none of it. The failure then looks like a bug in
// hush ("I reinitialised and it still says incorrect passphrase") rather
// than the arithmetic of age. So the destruction is one verb, it states
// what dies before it dies, and it takes the dead ciphertext with it.
//
// Plaintext values are kept: they are still readable, so they are not the
// command's business. The keyring entry and the unlock file are cleared
// because both hold a passphrase that now unlocks nothing.

var (
	resetYes         bool
	resetKeepSecrets bool
)

func init() {
	resetCmd.Flags().BoolVarP(&resetYes, "yes", "y", false, "skip the confirmation prompt")
	resetCmd.Flags().BoolVar(&resetKeepSecrets, "keep-secrets", false, "leave sealed values in place (they stay unreadable)")
	rootCmd.AddCommand(resetCmd)
}

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Delete the hush identity and the secrets sealed to it, so init can start over",
	Long: `Remove the age identity, then start again with 'hush init'.

Use this when the passphrase is lost or wrong: the agent reports
"incorrect passphrase" and nothing can be decrypted.

EVERY SEALED SECRET DIES WITH THE KEY. age has no recovery, no escrow,
no second recipient: the passphrase you no longer have is the only way
back to those values. They are deleted rather than left behind, because
ciphertext nobody can read is litter that outlives the misunderstanding.
Have the original values to hand (a password manager, the vendor's
dashboard) before running this.

Plaintext values in secrets.toml are kept. So are command.sh and
command.toml, so re-sealing is 'hush secret seal <name>' once the values
are back in the file.`,
	RunE: runReset,
}

// doomedCommand is one command directory and the sealed keys it will lose.
type doomedCommand struct {
	name string
	keys []string
}

func runReset(cmd *cobra.Command, args []string) error {
	identityPath := cfg.IdentityFile
	pubPath := identityPath + ".pub"

	_, identityErr := os.Stat(identityPath)
	haveIdentity := identityErr == nil

	var doomed []doomedCommand
	sealedTotal := 0
	if !resetKeepSecrets {
		for _, c := range listCommands() {
			if !c.hasSecrets {
				continue
			}
			keys, err := sealedKeys(filepath.Join(cfg.CommandsDir, c.name, "secrets.toml"))
			if err != nil {
				return fmt.Errorf("%s: %w", c.name, err)
			}
			if len(keys) > 0 {
				doomed = append(doomed, doomedCommand{name: c.name, keys: keys})
				sealedTotal += len(keys)
			}
		}
	}

	unlockFile := ""
	if cfg.Unlock.Method == "file" && cfg.Unlock.File != "" {
		if _, err := os.Stat(cfg.Unlock.File); err == nil {
			unlockFile = cfg.Unlock.File
		}
	}

	if !haveIdentity && sealedTotal == 0 && unlockFile == "" {
		fmt.Fprintf(os.Stderr, "no identity at %s and nothing sealed: already reset\n", identityPath)
		return nil
	}

	// Say what dies, by name, before asking. Values are never printed.
	fmt.Fprintln(os.Stderr, "hush reset will delete:")
	if haveIdentity {
		fmt.Fprintf(os.Stderr, "  %s (and .pub)\n", identityPath)
	}
	for _, d := range doomed {
		fmt.Fprintf(os.Stderr, "  %s: %d sealed value(s) — %s\n", d.name, len(d.keys), strings.Join(d.keys, ", "))
	}
	if unlockFile != "" {
		fmt.Fprintf(os.Stderr, "  %s (the passphrase file)\n", unlockFile)
	}
	if svc, acct := cfg.Unlock.Keyring.Service, cfg.Unlock.Keyring.Account; svc != "" && acct != "" {
		fmt.Fprintf(os.Stderr, "  the OS keyring entry, if present (service %q, account %q)\n", svc, acct)
	}
	if sealedTotal > 0 {
		fmt.Fprintf(os.Stderr, "\n%d sealed value(s) become unrecoverable. This cannot be undone.\n", sealedTotal)
	}

	if !resetYes {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("refusing to reset without a terminal to confirm at: pass --yes if you mean it")
		}
		fmt.Fprint(os.Stderr, "\nType 'yes' to proceed: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("read confirmation: %w", err)
		}
		if strings.TrimSpace(line) != "yes" {
			return fmt.Errorf("aborted")
		}
	}

	// The agent holds the old key in memory and would keep answering with
	// it. Stop it first, so a half-reset state is never live.
	if err := runDown(cmd, nil); err != nil && !strings.Contains(err.Error(), "no agent running") {
		return fmt.Errorf("stop agent: %w", err)
	}

	for _, d := range doomed {
		path := filepath.Join(cfg.CommandsDir, d.name, "secrets.toml")
		if err := dropSealedValues(path, d.keys); err != nil {
			return fmt.Errorf("%s: %w", d.name, err)
		}
		fmt.Fprintf(os.Stderr, "%s: removed %d sealed value(s)\n", d.name, len(d.keys))
	}

	for _, p := range []string{identityPath, pubPath} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	if haveIdentity {
		fmt.Fprintf(os.Stderr, "removed %s\n", identityPath)
	}

	if unlockFile != "" {
		if err := os.Remove(unlockFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", unlockFile, err)
		}
		fmt.Fprintf(os.Stderr, "removed %s\n", unlockFile)
	}

	// Best effort: a box with no Secret Service (headless, WSL) errors
	// here for reasons that have nothing to do with the reset.
	if svc, acct := cfg.Unlock.Keyring.Service, cfg.Unlock.Keyring.Account; svc != "" && acct != "" {
		if err := keyring.Delete(svc, acct); err == nil {
			fmt.Fprintf(os.Stderr, "cleared keyring entry (service %q, account %q)\n", svc, acct)
		}
	}

	fmt.Fprintln(os.Stderr, "\nNext:")
	fmt.Fprintln(os.Stderr, "  hush init                      generate a new identity")
	if unlockFile != "" {
		fmt.Fprintf(os.Stderr, "  write the new passphrase to %s (mode 0600)\n", unlockFile)
	}
	for _, d := range doomed {
		fmt.Fprintf(os.Stderr, "  put the values back in %s, then: hush secret seal %s\n",
			filepath.Join(cfg.CommandsDir, d.name, "secrets.toml"), d.name)
	}
	return nil
}

// sealedKeys reports which keys in one secrets.toml are AGE-ENC wrapped.
// A file that does not parse is reported as an error rather than skipped:
// silently sparing a file we could not read would leave the user with
// ciphertext they were told was gone.
func sealedKeys(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read secrets: %w", err)
	}
	var values map[string]string
	if err := toml.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("parse secrets: %w", err)
	}
	var keys []string
	for k, v := range values {
		if secrets.IsEncrypted(v) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// dropSealedValues rewrites secrets.toml without the named keys, and
// removes the file when nothing readable is left, so `hush status` stops
// advertising secrets that are not there.
func dropSealedValues(path string, keys []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read secrets: %w", err)
	}
	var values map[string]string
	if err := toml.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("parse secrets: %w", err)
	}
	for _, k := range keys {
		delete(values, k)
	}
	if len(values) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	encoded, err := secrets.MarshalTOML(values)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0600)
}
