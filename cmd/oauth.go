package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jack-work/hush/client"
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
)

func init() {
	f := oauthRegisterCmd.Flags()
	f.StringVar(&oauthRegFlagAuthorizeURL, "authorize-url", "", "OAuth authorize endpoint")
	f.StringVar(&oauthRegFlagTokenURL, "token-url", "", "OAuth token endpoint (required)")
	f.StringVar(&oauthRegFlagRedirectURI, "redirect-uri", "", "OAuth redirect URI")
	f.StringVar(&oauthRegFlagClientID, "client-id", "", "OAuth client ID (required)")
	f.StringVar(&oauthRegFlagScopes, "scopes", "", "OAuth scopes (space-separated)")
	f.IntVar(&oauthRegFlagExpiresIn, "expires-in", 0, "seconds until access token expires")
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

func connectAgent() (*client.Client, error) {
	c, err := client.New()
	if err != nil {
		return nil, err
	}
	if err := c.Ping(); err != nil {
		return nil, fmt.Errorf("hush agent is not running. Start it: hush up -d")
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
