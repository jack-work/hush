//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"

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

func init() {
	credServeCmd.Flags().String("config", "/etc/hush-cred/config.toml", "instances, recipient and allowed user")
	credServeCmd.Flags().String("state-dir", "/var/lib/hush-cred", "where the encrypted token files live")
	credServeCmd.Flags().String("identity-file", "", "age identity file (default $"+credIdentityEnv+")")
	credServeCmd.Flags().String("socket", "", "bind this path when not socket-activated")
	credCmd.AddCommand(credServeCmd)
	rootCmd.AddCommand(credCmd)
}

func runCredServe(cmd *cobra.Command, _ []string) error {
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
	uid, err := lookupUID(conf.AllowUser)
	if err != nil {
		return err
	}

	ln, err := credListener(sockPath)
	if err != nil {
		return err
	}
	defer ln.Close()

	logger := log.New(os.Stderr, "", 0)
	mgr := oauth.NewManager(stateDir, ids, conf.RecipientKey(), logger)
	mgr.SetHTTPClient(credserve.FencedClient(conf.EgressHosts(), nil))
	if err := mgr.Start(); err != nil {
		return err
	}
	defer mgr.Stop()

	srv := credserve.NewServer(conf, mgr, uid, logger).HTTPServer()
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()
	logger.Printf("cred: serving %d instances to uid %d", len(conf.Instances), uid)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
