// coolapp is an example application demonstrating how to embed hush as a
// library dependency. It supports two modes transparently:
//
//   - If the user has hush installed and running, coolapp piggybacks on it.
//   - If not, coolapp manages its own hush identity and agent.
//
// Usage:
//
//	coolapp setup              # one-time: create identity, store a secret
//	coolapp secret             # decrypt and print the secret
//	coolapp status             # show which mode is active
package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/term"

	"github.com/jack-work/hush/managed"
	"github.com/jack-work/hush/secrets"
)

func main() {
	// ── Step 1: Agent child check ──────────────────────────────
	// If we were re-exec'd by managed.SpawnDaemon to serve as the
	// embedded hush agent, run it and exit. This MUST be checked
	// before any other logic.
	if managed.IsAgentChild() {
		if err := managed.RunAgentChild(); err != nil {
			log.Fatal(err)
		}
		return
	}

	// ── Step 2: Create a managed hush instance ─────────────────
	h, err := managed.New(managed.Options{
		AppName: "coolapp",
		// Optional overrides:
		// TTL:  1 * time.Hour,
		// Dirs: &config.Dirs{ConfigDir: "/custom/path"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// ── Step 3: Route subcommands ──────────────────────────────
	if len(os.Args) < 2 {
		fmt.Println("usage: coolapp <setup|secret|status>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "setup":
		cmdSetup(h)
	case "secret":
		cmdSecret(h)
	case "status":
		cmdStatus(h)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// cmdSetup walks the user through one-time setup.
func cmdSetup(h *managed.Hush) {
	fmt.Printf("coolapp setup (mode: %s)\n\n", h.Mode())

	if h.Mode() == managed.ModeExternal {
		fmt.Println("Using your existing hush installation — no setup needed.")
		fmt.Println("Store secrets with: hush hush coolapp")
		return
	}

	// Embedded mode: create identity if needed.
	if !h.HasIdentity() {
		fmt.Println("Creating a new hush identity for coolapp...")

		fmt.Fprint(os.Stderr, "Choose a passphrase: ")
		p1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		p2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatal(err)
		}

		if string(p1) != string(p2) {
			log.Fatal("passphrases don't match")
		}

		pubkey, err := h.Init(p1)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Identity created. Public key: %s\n", pubkey)
	} else {
		fmt.Println("Identity already exists.")
	}

	fmt.Println("\nSetup complete. Store secrets with:")
	fmt.Println("  coolapp stores secrets in:", h.Config().ConfigDir)

	// Example: encrypt a secret value using the public key.
	// In a real app, you'd use h.Encrypt() via the agent, or
	// secrets.EncryptValue() with the public key directly.
	fmt.Println("\nTo add a secret, ensure the agent is running and use the encrypt API.")
}

// cmdSecret decrypts and prints a secret. This demonstrates the core use case.
func cmdSecret(h *managed.Hush) {
	// Example: decrypt a hardcoded AGE-ENC value.
	// In a real app, you'd read this from a config file.
	example := map[string]string{
		"greeting": "hello-world-not-encrypted",
	}

	// For non-encrypted values, this is a passthrough.
	vals, err := h.Decrypt(example)
	if err != nil {
		log.Fatal(err)
	}

	for k, v := range vals {
		fmt.Printf("%s = %s\n", k, v)
	}
}

// cmdStatus shows which mode is active.
func cmdStatus(h *managed.Hush) {
	fmt.Printf("Mode:     %s\n", h.Mode())
	fmt.Printf("Config:   %s\n", h.Config().ConfigDir)
	fmt.Printf("Runtime:  %s\n", h.Config().RuntimeDir)
	fmt.Printf("Identity: %s\n", h.Config().IdentityFile)
	fmt.Printf("Has identity: %v\n", h.HasIdentity())

	if h.Client().Ping() == nil {
		fmt.Println("Agent: running")
	} else {
		fmt.Println("Agent: not running")
	}

	_ = secrets.IsEncrypted // just to show the import works
}
