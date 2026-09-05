package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/internal/agent"
)

func init() {
	oauthCmd.AddCommand(oauthRegisterCmd)
	oauthCmd.AddCommand(oauthGetCmd)
	oauthCmd.AddCommand(oauthRefreshCmd)
	oauthCmd.AddCommand(oauthListCmd)
	oauthCmd.AddCommand(oauthDeleteCmd)
	rootCmd.AddCommand(oauthCmd)
}

var oauthCmd = &cobra.Command{
	Use:   "oauth",
	Short: "Manage OAuth credentials refreshed by the hush agent",
	Long: `The hush agent can hold an OAuth token pair (access + refresh) along
with the metadata needed to refresh it, refresh proactively before expiry,
and expose the current access token to other processes via the socket.

Subcommands talk to the running agent over the default socket.`,
}

var (
	oauthRegFlagAuthorizeURL string
	oauthRegFlagTokenURL     string
	oauthRegFlagRedirectURI  string
	oauthRegFlagClientID     string
	oauthRegFlagScopes       string
	oauthRegFlagExpiresIn    int
	oauthRegFlagGrant        string
)

func init() {
	f := oauthRegisterCmd.Flags()
	f.StringVar(&oauthRegFlagAuthorizeURL, "authorize-url", "", "OAuth authorize endpoint")
	f.StringVar(&oauthRegFlagTokenURL, "token-url", "", "OAuth token endpoint (required)")
	f.StringVar(&oauthRegFlagRedirectURI, "redirect-uri", "", "OAuth redirect URI")
	f.StringVar(&oauthRegFlagClientID, "client-id", "", "OAuth client ID (required)")
	f.StringVar(&oauthRegFlagScopes, "scopes", "", "OAuth scopes (space-separated)")
	f.IntVar(&oauthRegFlagExpiresIn, "expires-in", 0, "seconds until access token expires")
	f.StringVar(&oauthRegFlagGrant, "grant", "", "minting strategy: refresh_token (default) or copilot")
}

var oauthRegisterCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register or replace an OAuth credential",
	Long: `Hand a fresh OAuth credential to the agent. Required fields can be passed
via flags or will be prompted interactively. Access and refresh tokens are
always read interactively (hidden input).

Subsequent calls with the same name replace the existing entry.`,
	Args: cobra.ExactArgs(1),
	RunE: runOAuthRegister,
}

func runOAuthRegister(cmd *cobra.Command, args []string) error {
	name := args[0]
	c, err := connectAgent()
	if err != nil {
		return err
	}

	grant := oauthRegFlagGrant

	// An EXCHANGE grant derives its access token from a durable secret, so
	// registration needs only that secret and the endpoint: no client id,
	// no access token, no expiry. The agent mints the first session itself,
	// which also proves the credential works while someone is watching.
	if grant == "copilot" {
		return registerExchange(c, name, grant)
	}

	authURL := oauthRegFlagAuthorizeURL
	tokURL := oauthRegFlagTokenURL
	redirURI := oauthRegFlagRedirectURI
	clientID := oauthRegFlagClientID
	scopes := oauthRegFlagScopes
	expiresIn := oauthRegFlagExpiresIn

	reader := bufio.NewReader(os.Stdin)
	if authURL == "" {
		authURL = promptLine(reader, "authorize_url (optional): ")
	}
	if tokURL == "" {
		tokURL = promptLine(reader, "token_url: ")
	}
	if redirURI == "" {
		redirURI = promptLine(reader, "redirect_uri (optional): ")
	}
	if clientID == "" {
		clientID = promptLine(reader, "client_id: ")
	}
	if scopes == "" {
		scopes = promptLine(reader, "scopes (optional): ")
	}

	access, err := promptSecret("access_token: ")
	if err != nil {
		return err
	}
	refresh, err := promptSecret("refresh_token: ")
	if err != nil {
		return err
	}

	if expiresIn == 0 {
		s := promptLine(reader, "expires_in (seconds): ")
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("parse expires_in: %w", err)
		}
		expiresIn = n
	}

	if err := c.OAuthRegister(client.OAuthRegisterRequest{
		Name:         name,
		AuthorizeURL: authURL,
		TokenURL:     tokURL,
		RedirectURI:  redirURI,
		ClientID:     clientID,
		Scopes:       scopes,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    expiresIn,
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "registered oauth credential %q\n", name)
	return nil
}

// registerExchange handles the grants whose durable secret is the whole
// registration.
func registerExchange(c *client.Client, name, grant string) error {
	reader := bufio.NewReader(os.Stdin)
	tokURL := oauthRegFlagTokenURL
	if tokURL == "" {
		tokURL = promptLine(reader, "token_url (the exchange endpoint): ")
	}
	secret, err := promptSecret("durable secret (e.g. GitHub access token): ")
	if err != nil {
		return err
	}
	if err := c.OAuthRegister(client.OAuthRegisterRequest{
		Name:         name,
		TokenURL:     tokURL,
		Grant:        grant,
		RefreshToken: secret,
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "registered %s credential %q (first session minted)\n", grant, name)
	return nil
}

var oauthGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Print the cached access token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := connectAgent()
		if err != nil {
			return err
		}
		tok, err := c.OAuthGet(args[0])
		if err != nil {
			return formatOAuthErr(err)
		}
		fmt.Println(tok)
		return nil
	},
}

var oauthRefreshCmd = &cobra.Command{
	Use:   "refresh <name>",
	Short: "Force a refresh and print the new access token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := connectAgent()
		if err != nil {
			return err
		}
		tok, err := c.OAuthRefresh(args[0])
		if err != nil {
			return formatOAuthErr(err)
		}
		fmt.Println(tok)
		return nil
	},
}

var oauthListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered OAuth credential names",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := connectAgent()
		if err != nil {
			return err
		}
		names, err := c.OAuthList()
		if err != nil {
			return err
		}
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}

var oauthDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an OAuth credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := connectAgent()
		if err != nil {
			return err
		}
		return c.OAuthDelete(args[0])
	},
}

// connectAgent returns a client to a running agent, starting one if the TTL
// has lapsed since the last call.
//
// Telling the caller to run `hush up -d` is not good enough here. These
// commands are how a long-running service obtains its bearer token, and the
// agent's TTL is measured in minutes: a unit that starts healthy would fail a
// half hour later with advice nobody is present to take. The secrets path has
// always started the agent on demand; so must this one.
func connectAgent() (*client.Client, error) {
	c, err := client.New()
	if err != nil {
		return nil, err
	}
	if err := c.Ping(); err == nil {
		return c, nil
	}

	sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")

	// Only self-start when nothing is already listening on that path.
	//
	// If a systemd socket unit holds it, starting our own agent squats the
	// path: systemd later rebinds it, our agent survives on an orphaned inode
	// nobody can reach, and the activated agent cannot take the flock. Every
	// consumer on the box goes blind. A self-started agent also inherits the
	// CALLER's cgroup, so restarting one service would kill the credential
	// agent shared by all of them.
	//
	// SocketIsListening asks passively; dialing would start the very thing
	// being asked about.
	if agent.SocketIsListening(sockPath) {
		return nil, fmt.Errorf("hush agent socket at %s is held but not answering; "+
			"a socket unit is armed, so check: systemctl --user status hush-agent.service", sockPath)
	}
	if err := ensureAgent(sockPath); err != nil {
		return nil, fmt.Errorf("hush agent is not running and could not be started: %w", err)
	}
	c, err = client.New()
	if err != nil {
		return nil, err
	}
	if err := c.Ping(); err != nil {
		return nil, fmt.Errorf("hush agent did not answer after starting: %w", err)
	}
	return c, nil
}

func promptLine(r *bufio.Reader, prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// formatOAuthErr adds a hint when the refresh has failed permanently — the
// only recovery is re-running the OAuth login flow.
func formatOAuthErr(err error) error {
	if errors.Is(err, client.ErrOAuthRefreshPermanent) {
		return fmt.Errorf("%w\n\nRefresh token rejected. Re-run the OAuth login flow to obtain a new pair", err)
	}
	return err
}
