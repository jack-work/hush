//go:build linux

package cli

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jack-work/hush/internal/agent"
	"github.com/jack-work/hush/internal/credserve"
	"github.com/jack-work/hush/internal/oauth"
)

const credIdentityEnv = "HUSH_CRED_IDENTITY_FILE"

var credCmd = &cobra.Command{
	Use:   "cred",
	Short: "Serve plan credentials to one other uid over a unix socket (system mode)",
	Long: `System mode: one process holds one encrypted token file per instance and
answers GET /cred/<name> on a unix socket for a single allowed uid.

It shares nothing with the per-user agent: no hush.toml, no agent socket,
no keyring. Instances, the age recipient and the allowed user come from
--config; the age identity from the file --identity-file (or $` + credIdentityEnv + `)
names, normally under $CREDENTIALS_DIRECTORY.`,
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
}

var credServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Answer GET /cred/<name> for the allowed uid",
	Args:  cobra.NoArgs,
	RunE:  runCredServe,
}

var credLoginCmd = &cobra.Command{
	Use:   "login <name>",
	Short: "Sign an instance in; the code is read from the terminal, never argv",
	Args:  cobra.ExactArgs(1),
	RunE:  runCredLogin,
}

func init() {
	for _, c := range []*cobra.Command{credServeCmd, credLoginCmd} {
		c.Flags().String("config", "/etc/hush-cred/config.toml", "instances, recipient and allowed user")
		c.Flags().String("state-dir", "/var/lib/hush-cred", "where the encrypted token files live")
	}
	credServeCmd.Flags().String("identity-file", "", "age identity file (default $"+credIdentityEnv+")")
	credServeCmd.Flags().String("socket", "", "bind this path when not socket-activated")
	credLoginCmd.Flags().Bool("replace", false, "sign in again over a live credential (stop the server first)")
	credCmd.AddCommand(credServeCmd, credLoginCmd)
	rootCmd.AddCommand(credCmd)
}

func runCredServe(cmd *cobra.Command, _ []string) (result error) {
	confPath, _ := cmd.Flags().GetString("config")
	stateDir, _ := cmd.Flags().GetString("state-dir")
	idPath, _ := cmd.Flags().GetString("identity-file")
	sockPath, _ := cmd.Flags().GetString("socket")
	if idPath == "" {
		idPath = os.Getenv(credIdentityEnv)
	}
	if idPath == "" {
		return fmt.Errorf("no identity: pass --identity-file or set %s to a file path", credIdentityEnv)
	}

	conf, err := credserve.LoadConfig(confPath)
	if err != nil {
		return err
	}
	ids, err := loadCredIdentities(idPath, conf)
	if err != nil {
		return err
	}
	var uid uint32
	if conf.AllowUser != "" {
		if uid, err = lookupUID(conf.AllowUser); err != nil {
			return err
		}
	}
	principals, err := credserve.ResolvePrincipals(conf, lookupUID)
	if err != nil {
		return err
	}

	owner, err := credserve.LockState(stateDir)
	if err != nil {
		return err
	}
	defer owner.Close()
	listeners, systemdLn, err := credListeners(conf, sockPath)
	if err != nil {
		return err
	}
	for _, ln := range listeners {
		defer ln.Close()
	}
	if systemdLn != nil {
		defer systemdLn.Close()
	}

	logger := log.New(os.Stderr, "", 0)
	mgr := oauth.NewManager(stateDir, ids, conf.RecipientKey(), logger)
	mgr.SetHTTPClient(credserve.FencedClient(conf.EgressHosts(), nil))
	defer func() {
		if err := mgr.Stop(); err != nil {
			result = err
		}
	}()
	if err := mgr.Start(); err != nil {
		return err
	}

	srv := credserve.NewServer(conf, mgr, uid, logger)
	srv.SetPrincipals(principals, conf.AllowUser != "")
	srv.SetStaleFile(filepath.Join(stateDir, "stale.json"))
	srv.SetOverlayFile(filepath.Join(stateDir, "overlay.json"))
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go srv.RunOverlaySweep(ctx, time.Minute)
	if conf.AllowUser != "" {
		logger.Printf("cred: serving %d instances to uid %d", len(conf.Instances), uid)
	}
	for name, p := range principals {
		logger.Printf("cred: principal %s: %d credentials for %d uids", name, len(p.Credentials), len(p.UIDs))
	}
	if systemdLn != nil {
		logger.Printf("cred: systemd LoadCredential socket: %d units", len(conf.Systemd.Units))
		go func() {
			if err := srv.ServeSystemd(ctx, systemdLn); err != nil {
				logger.Printf("cred: systemd socket: %v", err)
				stop()
			}
		}()
	}
	return srv.ServeContext(ctx, listeners...)
}

func loadCredIdentities(path string, conf *credserve.Config) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("identity file %s does not parse as age identities", path)
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok && x.Recipient().String() == conf.Recipient {
			return ids, nil
		}
	}
	return nil, errors.New("the identity file holds no key for the config's recipient: logins would encrypt to a key this server cannot open")
}

func lookupUID(name string) (uint32, error) {
	if n, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(n), nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("allow_user: %w", err)
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("allow_user %s: uid %q", name, u.Uid)
	}
	return uint32(n), nil
}

func credListener(path string) (net.Listener, error) {
	ln, err := agent.InheritedListener()
	if err != nil || ln != nil {
		return ln, err
	}
	if path == "" {
		return nil, errors.New("not socket-activated and no --socket given")
	}
	_ = os.Remove(path)
	old := syscall.Umask(0o117)
	ln, err = net.Listen("unix", path)
	syscall.Umask(old)
	return ln, err
}

// credListeners opens the allow_user socket (when allow_user is set) and one
// socket per principal. Without principals it is exactly the old single
// socket. Socket-activated descriptors are matched to principals by their
// FileDescriptorName; the one descriptor not named for a principal is the
// allow_user socket.
func credListeners(conf *credserve.Config, legacyPath string) ([]net.Listener, net.Listener, error) {
	if len(conf.Principals) == 0 && conf.Systemd == nil {
		ln, err := credListener(legacyPath)
		if err != nil {
			return nil, nil, err
		}
		return []net.Listener{ln}, nil, nil
	}
	inherited, err := credserve.InheritedListeners()
	if err != nil {
		return nil, nil, err
	}
	var out []net.Listener
	var systemdLn net.Listener
	fail := func(err error) ([]net.Listener, net.Listener, error) {
		for _, ln := range out {
			ln.Close()
		}
		for _, ln := range inherited {
			ln.Close()
		}
		if systemdLn != nil {
			systemdLn.Close()
		}
		return nil, nil, err
	}
	if conf.Systemd != nil {
		systemdLn = inherited[credserve.SystemdFDName]
		delete(inherited, credserve.SystemdFDName)
		if systemdLn == nil {
			if systemdLn, err = bindSocket(conf.Systemd.Socket); err != nil {
				return fail(fmt.Errorf("systemd socket: %w", err))
			}
			// Only the owner and root (the system manager) connect.
			if err := os.Chmod(conf.Systemd.Socket, 0o600); err != nil {
				return fail(fmt.Errorf("systemd socket: %w", err))
			}
		}
	}
	for name, p := range conf.Principals {
		ln := inherited[name]
		delete(inherited, name)
		if ln == nil {
			if p.Socket == "" {
				return fail(fmt.Errorf("principal %s: not socket-activated and no socket path", name))
			}
			if ln, err = bindSocket(p.Socket); err != nil {
				return fail(fmt.Errorf("principal %s: %w", name, err))
			}
		}
		out = append(out, credserve.PrincipalListener(ln, name))
	}
	if conf.AllowUser == "" {
		if len(inherited) > 0 {
			return fail(errors.New("socket activation: a descriptor names no principal and allow_user is not set"))
		}
		return out, systemdLn, nil
	}
	switch len(inherited) {
	case 0:
		if legacyPath == "" {
			return fail(errors.New("allow_user is set: not socket-activated for it and no --socket given"))
		}
		ln, err := bindSocket(legacyPath)
		if err != nil {
			return fail(err)
		}
		out = append(out, ln)
	case 1:
		for _, ln := range inherited {
			out = append(out, ln)
		}
	default:
		return fail(fmt.Errorf("socket activation: %d descriptors name no principal; allow_user takes one", len(inherited)))
	}
	return out, systemdLn, nil
}

func bindSocket(path string) (net.Listener, error) {
	_ = os.Remove(path)
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	return ln, err
}

var credReadCode func(prompt string) (string, error)

func runCredLogin(cmd *cobra.Command, args []string) error {
	confPath, _ := cmd.Flags().GetString("config")
	stateDir, _ := cmd.Flags().GetString("state-dir")
	replace, _ := cmd.Flags().GetBool("replace")

	conf, err := credserve.LoadConfig(confPath)
	if err != nil {
		return err
	}
	if conf.Instances[args[0]].Kind == credserve.KindExec {
		return fmt.Errorf("%s is kind %q: it signs in through its own command, not hush", args[0], credserve.KindExec)
	}
	read := credReadCode
	if read == nil && conf.Instances[args[0]].Kind != credserve.KindChatGPT {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("stdin is not a terminal: the code is read from a terminal only")
		}
		read = readCodeFromTerminal
	}
	owner, err := credserve.LockState(stateDir)
	if err != nil {
		return err
	}
	defer owner.Close()
	l := &credserve.Login{
		Config:   conf,
		StateDir: stateDir,
		Name:     args[0],
		Replace:  replace,
		Client:   credserve.FencedClient(conf.EgressHosts(), nil),
		ReadCode: read,
		Out:      cmd.ErrOrStderr(),
	}
	return l.Run(cmd.Context())
}

func readCodeFromTerminal(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read code: %w", err)
	}
	return string(b), nil
}
