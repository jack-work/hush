// Package managed provides a high-level interface for applications that embed
// hush as a dependency. It supports two modes transparently:
//
//   - External: if the hush CLI is installed and/or the default hush agent is
//     already running, delegate to it. The application shares the user's
//     existing hush identity and agent.
//
//   - Embedded: if hush is not installed, the application manages its own
//     identity and agent in a dedicated config directory. The consuming
//     binary re-execs itself to spawn the agent daemon.
//
// Usage from a consuming application's main():
//
//	func main() {
//	    // Check if we're a re-exec'd agent child — if so, run the agent and exit.
//	    if managed.IsAgentChild() {
//	        if err := managed.RunAgentChild(); err != nil {
//	            log.Fatal(err)
//	        }
//	        return
//	    }
//
//	    // Normal application code.
//	    h, err := managed.New(managed.Options{
//	        AppName: "coolapp",
//	    })
//	    if err != nil { log.Fatal(err) }
//
//	    vals, err := h.Decrypt(map[string]string{"token": "AGE-ENC[...]"})
//	    ...
//	}
package managed

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jack-work/hush/agent"
	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/config"
	"github.com/jack-work/hush/identity"
)

// Options configures a managed hush instance.
type Options struct {
	// AppName is used to namespace the embedded config directory
	// (e.g. ~/.config/<AppName>/hush/). Required.
	AppName string

	// Dirs overrides the default directory resolution. If set, these take
	// precedence over both external hush defaults and the AppName-derived
	// paths. Useful for testing or non-standard layouts.
	Dirs *config.Dirs

	// TTL for the embedded agent. Defaults to the value in the resolved
	// hush config (typically 30m).
	TTL time.Duration

	// AgentArgs are extra arguments passed to the re-exec'd child when
	// spawning an embedded agent. The consuming application can use these
	// to route into its agent subcommand if desired.
	AgentArgs []string

	// AgentEnv are extra environment variables (KEY=VALUE) passed to the
	// re-exec'd child. SpawnEnvVar is always set automatically.
	AgentEnv []string

	// Logger for the embedded agent. If nil, logs to stderr.
	Logger *log.Logger
}

// Hush is a managed hush client that transparently handles external vs
// embedded mode.
type Hush struct {
	cfg    *config.Config
	client *client.Client
	opts   Options
	mode   Mode
}

// Mode describes which hush backend is in use.
type Mode int

const (
	// ModeExternal means the system-installed hush agent is being used.
	ModeExternal Mode = iota
	// ModeEmbedded means this application is managing its own hush agent.
	ModeEmbedded
)

func (m Mode) String() string {
	switch m {
	case ModeExternal:
		return "external"
	case ModeEmbedded:
		return "embedded"
	default:
		return "unknown"
	}
}

// childConfigEnv is used to pass the config directory path to the re-exec'd
// agent child so it loads the correct config.
const childConfigEnv = "HUSH_MANAGED_CONFIG_DIR"
const childStateEnv = "HUSH_MANAGED_STATE_DIR"
const childRuntimeEnv = "HUSH_MANAGED_RUNTIME_DIR"

// IsAgentChild reports whether the current process was re-exec'd by managed
// to serve as an embedded hush agent. Call this early in main().
func IsAgentChild() bool {
	return os.Getenv(agent.SpawnEnvVar) == "1"
}

// RunAgentChild runs the embedded agent. Call this from main() when
// IsAgentChild() returns true. It blocks until the agent exits.
func RunAgentChild() error {
	// Resolve config from env vars set by the parent.
	dirs := config.Dirs{
		ConfigDir:  os.Getenv(childConfigEnv),
		StateDir:   os.Getenv(childStateEnv),
		RuntimeDir: os.Getenv(childRuntimeEnv),
	}

	cfg, err := config.LoadWithDirs(dirs)
	if err != nil {
		return fmt.Errorf("managed agent: load config: %w", err)
	}

	logger := log.New(os.Stderr, "hush: ", log.LstdFlags)

	// Try to set up a log file in the state dir.
	if err := os.MkdirAll(cfg.StateDir, 0700); err == nil {
		logPath := filepath.Join(cfg.StateDir, "hush.log")
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
			logger = log.New(f, "hush: ", log.LstdFlags)
			defer f.Close()
		}
	}

	return agent.RunChildFromPipe(cfg.TTL, cfg.RuntimeDir, logger)
}

// New creates a managed hush instance. It probes for an external hush agent
// first; if none is found, it prepares to manage an embedded one.
//
// New does NOT start the agent or prompt for a passphrase. Call EnsureReady()
// or one of the Decrypt/Encrypt methods to trigger that lazily.
func New(opts Options) (*Hush, error) {
	if opts.AppName == "" {
		return nil, fmt.Errorf("managed.Options.AppName is required")
	}

	h := &Hush{opts: opts}

	// 1. Try external hush agent (default XDG socket).
	if h.tryExternal() {
		return h, nil
	}

	// 2. Try external hush CLI on PATH — it might just need starting.
	if _, err := exec.LookPath("hush"); err == nil {
		if h.tryExternalCLI() {
			return h, nil
		}
	}

	// 3. Fall back to embedded mode.
	if err := h.setupEmbedded(); err != nil {
		return nil, err
	}

	return h, nil
}

// Mode returns whether this instance is using external or embedded hush.
func (h *Hush) Mode() Mode {
	return h.mode
}

// Config returns the resolved hush config.
func (h *Hush) Config() *config.Config {
	return h.cfg
}

// Decrypt sends values to the agent for decryption. Starts the agent if
// needed (may prompt for passphrase on stderr/stdin).
func (h *Hush) Decrypt(values map[string]string) (map[string]string, error) {
	if err := h.ensureAgent(); err != nil {
		return nil, err
	}
	return h.client.Decrypt(values)
}

// Encrypt sends values to the agent for encryption. Starts the agent if
// needed (may prompt for passphrase on stderr/stdin).
func (h *Hush) Encrypt(values map[string]string) (map[string]string, error) {
	if err := h.ensureAgent(); err != nil {
		return nil, err
	}
	return h.client.Encrypt(values)
}

// Client returns the underlying hush client for direct socket operations.
// The agent may not be running yet; call EnsureReady() first if needed.
func (h *Hush) Client() *client.Client {
	return h.client
}

// EnsureReady makes sure the agent is running, starting it if necessary.
// In embedded mode with no identity, returns an error describing what
// the user needs to do.
func (h *Hush) EnsureReady() error {
	return h.ensureAgent()
}

// Init generates a new hush identity in the managed config directory.
// Only meaningful in embedded mode. Returns the public key string.
func (h *Hush) Init(passphrase []byte) (publicKey string, err error) {
	if h.mode == ModeExternal {
		return "", fmt.Errorf("init not supported in external mode — use 'hush init' directly")
	}
	return initIdentity(h.cfg, passphrase)
}

// HasIdentity reports whether an identity file exists at the configured path.
func (h *Hush) HasIdentity() bool {
	_, err := os.Stat(h.cfg.IdentityFile)
	return err == nil
}

// --- internal ---

func (h *Hush) tryExternal() bool {
	// Check if the default hush agent socket is responsive.
	sockPath, err := client.DefaultSocket()
	if err != nil {
		return false
	}

	c := client.NewWithSocket(sockPath)
	if c.Ping() != nil {
		return false
	}

	// External agent is alive — use it.
	cfg, err := config.Load()
	if err != nil {
		return false
	}

	h.cfg = cfg
	h.client = c
	h.mode = ModeExternal
	return true
}

func (h *Hush) tryExternalCLI() bool {
	// hush is on PATH but agent isn't running. We won't start it here —
	// that requires a passphrase. We just note that external mode is
	// available and will try `hush up -d` when ensureAgent is called.
	cfg, err := config.Load()
	if err != nil {
		return false
	}

	// Only use external CLI if the user actually has an identity set up.
	if _, err := os.Stat(cfg.IdentityFile); err != nil {
		return false
	}

	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
	h.cfg = cfg
	h.client = client.NewWithSocket(sockPath)
	h.mode = ModeExternal
	return true
}

func (h *Hush) setupEmbedded() error {
	dirs := h.opts.Dirs
	if dirs == nil {
		// Derive from AppName: ~/.config/<appname>/hush/
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home dir: %w", err)
		}
		dirs = &config.Dirs{
			ConfigDir:  filepath.Join(home, ".config", h.opts.AppName, "hush"),
			StateDir:   filepath.Join(home, ".local", "state", h.opts.AppName, "hush"),
			RuntimeDir: filepath.Join(os.TempDir(), h.opts.AppName+"-hush"),
		}
	}

	cfg, err := config.LoadWithDirs(*dirs)
	if err != nil {
		return fmt.Errorf("managed: load config: %w", err)
	}

	if h.opts.TTL > 0 {
		cfg.TTL = h.opts.TTL
	}

	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
	h.cfg = cfg
	h.client = client.NewWithSocket(sockPath)
	h.mode = ModeEmbedded
	return nil
}

func (h *Hush) ensureAgent() error {
	// Already running?
	if h.client.Ping() == nil {
		return nil
	}

	switch h.mode {
	case ModeExternal:
		return h.startExternal()
	case ModeEmbedded:
		return h.startEmbedded()
	default:
		return fmt.Errorf("unknown hush mode")
	}
}

func (h *Hush) startExternal() error {
	hushBin, err := exec.LookPath("hush")
	if err != nil {
		return fmt.Errorf("hush agent is not running and hush binary not found on PATH.\n\n" +
			"Either start hush manually (hush up -d) or install hush:\n  go install github.com/jack-work/hush@latest")
	}

	// Shell out to hush up -d. This will prompt for passphrase via the
	// terminal, which is the correct UX for external mode.
	cmd := exec.Command(hushBin, "up", "-d")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start hush agent: %w", err)
	}

	return nil
}

func (h *Hush) startEmbedded() error {
	if !h.HasIdentity() {
		return fmt.Errorf("no hush identity found at %s.\n\n"+
			"Run your application's init/setup command to create one, or call Init() programmatically.",
			h.cfg.IdentityFile)
	}

	// Prompt for passphrase.
	passphrase, err := promptPassphrase("Enter passphrase for " + h.opts.AppName + " secrets: ")
	if err != nil {
		return err
	}

	id, err := identity.Unlock(h.cfg.IdentityFile, passphrase)
	if err != nil {
		return fmt.Errorf("unlock identity: %w", err)
	}

	// Re-exec ourselves as the agent daemon.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}

	env := append(h.opts.AgentEnv,
		childConfigEnv+"="+h.cfg.ConfigDir,
		childStateEnv+"="+h.cfg.StateDir,
		childRuntimeEnv+"="+h.cfg.RuntimeDir,
	)

	args := h.opts.AgentArgs
	if len(args) == 0 {
		// Default: no special args, the child detects via SpawnEnvVar.
		args = []string{}
	}

	pid, err := agent.SpawnDaemon(exe, args, env, id)
	if err != nil {
		return err
	}

	if err := agent.WaitForAgent(h.cfg.RuntimeDir, 3*time.Second); err != nil {
		return fmt.Errorf("embedded agent started (pid %d) but not responding: %w", pid, err)
	}

	return nil
}
