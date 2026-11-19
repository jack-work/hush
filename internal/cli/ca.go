//go:build linux

package cli

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/bundle"
	"github.com/jack-work/hush/ca"
	"github.com/jack-work/hush/internal/agent"
	"github.com/jack-work/hush/workload"
)

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "The troupe's certificate authority: root, node intermediates and keys",
	Long: `The root key is read on stdin and never from a file or argv; the troupe-root
hush command delivers it. Everything else is a file path, so systemd can hand
the keys in with LoadCredential=.`,
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
}

var caKeygenCmd = &cobra.Command{
	Use:   "keygen <out-file>",
	Short: "Write a new private key (0600) and print its public key",
	Args:  cobra.ExactArgs(1),
	RunE:  runCAKeygen,
}

var caRootCmd = &cobra.Command{
	Use:   "root <trust-domain>",
	Short: "Print the root certificate for the root key on stdin",
	Args:  cobra.ExactArgs(1),
	RunE:  runCARoot,
}

var caIntermediateCmd = &cobra.Command{
	Use:   "intermediate <trust-domain> <node>",
	Short: "Sign a node's intermediate with the root key on stdin",
	Args:  cobra.ExactArgs(2),
	RunE:  runCAIntermediate,
}

var workloadCmd = &cobra.Command{
	Use:               "workload",
	Short:             "The workload socket: SVIDs for attested local processes",
	PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
}

var workloadServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Issue X.509 and JWT SVIDs to the processes that connect",
	Args:  cobra.NoArgs,
	RunE:  runWorkloadServe,
}

var workloadJWTCmd = &cobra.Command{
	Use:   "jwt <audience>...",
	Short: "Print a JWT-SVID for this process",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runWorkloadJWT,
}

var workloadX509Cmd = &cobra.Command{
	Use:   "x509 <out-dir>",
	Short: "Write this process's X.509-SVID, key and bundle to a directory",
	Args:  cobra.ExactArgs(1),
	RunE:  runWorkloadX509,
}

func init() {
	caKeygenCmd.Flags().Bool("jwt", false, "an ECDSA P-256 key for JWT-SVIDs instead of Ed25519")
	caIntermediateCmd.Flags().String("public-key", "", "the node's public key, PEM (required)")
	caIntermediateCmd.Flags().Duration("ttl", ca.IntermediateTTL, "lifetime")
	caCmd.AddCommand(caKeygenCmd, caRootCmd, caIntermediateCmd)
	rootCmd.AddCommand(caCmd)

	f := workloadServeCmd.Flags()
	f.String("trust-domain", "", "the troupe (required)")
	f.String("node", "", "this node's name (required)")
	f.String("root-cert", "", "root certificate PEM (required)")
	f.String("intermediate-cert", "", "this node's intermediate PEM (required)")
	f.String("intermediate-key", "", "its private key PEM, e.g. under $CREDENTIALS_DIRECTORY (required)")
	f.String("jwt-key", "", "ECDSA P-256 key PEM for JWT-SVIDs (none: JWT-SVIDs are refused)")
	f.String("socket", "", "bind this path when not socket-activated")
	for _, c := range []*cobra.Command{workloadJWTCmd, workloadX509Cmd} {
		c.Flags().String("trust-domain", "", "the troupe (required)")
		c.Flags().String("socket", "", "the workload socket (default $"+workload.SocketEnv+", /run/hush/workload.sock, $XDG_RUNTIME_DIR/hush/workload.sock)")
	}
	workloadCmd.AddCommand(workloadServeCmd, workloadJWTCmd, workloadX509Cmd)
	rootCmd.AddCommand(workloadCmd)
}

func runCAKeygen(cmd *cobra.Command, args []string) error {
	jwt, _ := cmd.Flags().GetBool("jwt")
	var key crypto.Signer
	var err error
	if jwt {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	return pem.Encode(cmd.OutOrStdout(), &pem.Block{Type: "PUBLIC KEY", Bytes: pub})
}

func rootFromStdin(cmd *cobra.Command) (ed25519.PrivateKey, error) {
	raw, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64<<10))
	if err != nil {
		return nil, err
	}
	return ca.ParseRoot(raw)
}

func runCARoot(cmd *cobra.Command, args []string) error {
	key, err := rootFromStdin(cmd)
	if err != nil {
		return err
	}
	c, err := ca.RootCert(args[0], key)
	if err != nil {
		return err
	}
	return pem.Encode(cmd.OutOrStdout(), &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func runCAIntermediate(cmd *cobra.Command, args []string) error {
	pubPath, _ := cmd.Flags().GetString("public-key")
	ttl, _ := cmd.Flags().GetDuration("ttl")
	if pubPath == "" {
		return errors.New("--public-key is required")
	}
	pub, err := readPublicKey(pubPath)
	if err != nil {
		return err
	}
	key, err := rootFromStdin(cmd)
	if err != nil {
		return err
	}
	rc, err := ca.RootCert(args[0], key)
	if err != nil {
		return err
	}
	c, err := ca.IssueIntermediate(key, rc, args[0], args[1], pub, time.Now(), ttl)
	if err != nil {
		return err
	}
	return pem.Encode(cmd.OutOrStdout(), &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func readPEM(path, want string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != want {
		return nil, fmt.Errorf("%s: want a PEM %s", path, want)
	}
	return block.Bytes, nil
}

func readPublicKey(path string) (crypto.PublicKey, error) {
	der, err := readPEM(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	return x509.ParsePKIXPublicKey(der)
}

func readCert(path string) (*x509.Certificate, error) {
	der, err := readPEM(path, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func readKey(path string) (crypto.Signer, error) {
	der, err := readPEM(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", path)
	}
	return s, nil
}

func required(cmd *cobra.Command, names ...string) (map[string]string, error) {
	out := map[string]string{}
	for _, n := range names {
		v, _ := cmd.Flags().GetString(n)
		if v == "" {
			return nil, fmt.Errorf("--%s is required", n)
		}
		out[n] = v
	}
	return out, nil
}

func loadAuthority(cmd *cobra.Command) (workload.Authority, string, string, error) {
	v, err := required(cmd, "trust-domain", "node", "root-cert", "intermediate-cert", "intermediate-key")
	if err != nil {
		return workload.Authority{}, "", "", err
	}
	rc, err := readCert(v["root-cert"])
	if err != nil {
		return workload.Authority{}, "", "", err
	}
	ic, err := readCert(v["intermediate-cert"])
	if err != nil {
		return workload.Authority{}, "", "", err
	}
	ik, err := readKey(v["intermediate-key"])
	if err != nil {
		return workload.Authority{}, "", "", err
	}
	if pub, ok := ik.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(ic.PublicKey) {
		return workload.Authority{}, "", "", errors.New("the intermediate key does not match its certificate")
	}
	if err := ic.CheckSignatureFrom(rc); err != nil {
		return workload.Authority{}, "", "", fmt.Errorf("the intermediate is not signed by the root: %w", err)
	}
	if got := ca.IntermediateNode(ic); got != v["node"] {
		return workload.Authority{}, "", "", fmt.Errorf("the intermediate is node %q's, not %q's", got, v["node"])
	}
	a := workload.Authority{Intermediate: ik, IntermediateCert: ic,
		Bundle: &bundle.Bundle{TrustDomain: v["trust-domain"], Sequence: 1, X509Authorities: []*x509.Certificate{rc}, JWTAuthorities: map[string]crypto.PublicKey{}}}
	if p, _ := cmd.Flags().GetString("jwt-key"); p != "" {
		k, err := readKey(p)
		if err != nil {
			return workload.Authority{}, "", "", err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok || ek.Curve != elliptic.P256() {
			return workload.Authority{}, "", "", fmt.Errorf("%s: want an ECDSA P-256 key", p)
		}
		kid, err := ca.JWTKeyID(&ek.PublicKey)
		if err != nil {
			return workload.Authority{}, "", "", err
		}
		a.JWTKey, a.JWTKeyID = ek, kid
		a.Bundle.JWTAuthorities[kid] = &ek.PublicKey
	}
	return a, v["trust-domain"], v["node"], nil
}

func runWorkloadServe(cmd *cobra.Command, _ []string) error {
	auth, td, node, err := loadAuthority(cmd)
	if err != nil {
		return err
	}
	ln, err := agent.InheritedListener()
	if err != nil {
		return err
	}
	if ln == nil {
		path, _ := cmd.Flags().GetString("socket")
		if path == "" {
			return errors.New("not socket-activated and no --socket given")
		}
		_ = os.Remove(path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if ln, err = net.Listen("unix", path); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o666); err != nil {
			return err
		}
	}
	srv := workload.NewServer(workload.PeerAttestor, workload.NodePolicy(td, node), auth)
	srv.Log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	srv.Log.Info("workload socket serving", "trust_domain", td, "node", node, "intermediate_expires", auth.IntermediateCert.NotAfter)
	return srv.Serve(ctx, ln)
}

func workloadClient(cmd *cobra.Command) (*workload.Client, error) {
	v, err := required(cmd, "trust-domain")
	if err != nil {
		return nil, err
	}
	sock, _ := cmd.Flags().GetString("socket")
	if sock == "" {
		sock = workload.SocketPath()
	}
	return workload.NewClient(v["trust-domain"], sock), nil
}

func runWorkloadJWT(cmd *cobra.Command, args []string) error {
	c, err := workloadClient(cmd)
	if err != nil {
		return err
	}
	j, err := c.JWT(cmd.Context(), args...)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), j.Token)
	return err
}

func runWorkloadX509(cmd *cobra.Command, args []string) error {
	c, err := workloadClient(cmd)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	b, err := c.Bundle(ctx)
	if err != nil {
		return err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s, err := c.X509(ctx, key, b)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(args[0], 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	var chain []byte
	for _, cert := range s.Chain {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	rawBundle, err := b.Marshal()
	if err != nil {
		return err
	}
	for name, data := range map[string][]byte{
		"svid.key":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"svid.pem":    chain,
		"bundle.json": rawBundle,
	} {
		if err := os.WriteFile(filepath.Join(args[0], name), data, 0o600); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s until %s (renew after %s)\n", s.ID, s.Chain[0].NotAfter.Format(time.RFC3339), s.RenewAfter.Format(time.RFC3339))
	return err
}
