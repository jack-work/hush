package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/oauth"
)

func init() {
	f := oauthLoginCmd.Flags()
	f.String("authorize-url", "", "OAuth authorize endpoint (required)")
	f.String("token-url", "", "OAuth token endpoint (required)")
	f.String("redirect-uri", "", "OAuth redirect URI (required)")
	f.String("client-id", "", "OAuth client ID (required)")
	f.String("scopes", "", "OAuth scopes (space-separated)")
	oauthCmd.AddCommand(oauthLoginCmd)
}

var oauthLoginCmd = &cobra.Command{
	Use:   "login <name>",
	Short: "Run the OAuth authorization-code flow and register the result",
	Long: `Drive a full PKCE-based OAuth login: generate a verifier+challenge, open
the authorize URL in a browser, prompt for the authorization code, exchange
it at the token endpoint, and register the resulting tokens with the hush
agent.

After login, the agent owns the credential and will refresh it proactively.`,
	Args: cobra.ExactArgs(1),
	RunE: runOAuthLogin,
}

func runOAuthLogin(cmd *cobra.Command, args []string) error {
	name := args[0]

	authURL, _ := cmd.Flags().GetString("authorize-url")
	tokURL, _ := cmd.Flags().GetString("token-url")
	redirURI, _ := cmd.Flags().GetString("redirect-uri")
	clientID, _ := cmd.Flags().GetString("client-id")
	scopes, _ := cmd.Flags().GetString("scopes")

	reader := bufio.NewReader(os.Stdin)
	if authURL == "" {
		authURL = promptLine(reader, "authorize_url: ")
	}
	if tokURL == "" {
		tokURL = promptLine(reader, "token_url: ")
	}
	if redirURI == "" {
		redirURI = promptLine(reader, "redirect_uri: ")
	}
	if clientID == "" {
		clientID = promptLine(reader, "client_id: ")
	}
	if scopes == "" {
		scopes = promptLine(reader, "scopes (optional): ")
	}

	if authURL == "" || tokURL == "" || redirURI == "" || clientID == "" {
		return fmt.Errorf("authorize_url, token_url, redirect_uri, and client_id are all required")
	}

	c, err := connectAgent()
	if err != nil {
		return err
	}

	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		return fmt.Errorf("generate PKCE: %w", err)
	}

	params := url.Values{
		"code":                  {"true"},
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirURI},
		"scope":                 {scopes},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
		"state":                 {pkce.Verifier},
	}
	authorizeFullURL := authURL + "?" + params.Encode()

	fmt.Fprintln(os.Stderr, "Opening browser for login...")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  "+authorizeFullURL)
	fmt.Fprintln(os.Stderr)
	openBrowser(authorizeFullURL)

	fmt.Fprint(os.Stderr, "Paste the authorization code: ")
	codeInput, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read code: %w", err)
	}
	codeInput = strings.TrimSpace(codeInput)

	// Anthropic-style: the callback returns "code#state". Other providers
	// might return just the code — handle either.
	code := codeInput
	state := pkce.Verifier
	if parts := strings.SplitN(codeInput, "#", 2); len(parts) == 2 {
		code = parts[0]
		state = parts[1]
	}

	tokens, err := exchangeCode(tokURL, clientID, code, state, redirURI, pkce.Verifier)
	if err != nil {
		return err
	}

	if err := c.OAuthRegister(client.OAuthRegisterRequest{
		Name:         name,
		AuthorizeURL: authURL,
		TokenURL:     tokURL,
		RedirectURI:  redirURI,
		ClientID:     clientID,
		Scopes:       scopes,
		AccessToken:  tokens.access,
		RefreshToken: tokens.refresh,
		ExpiresIn:    tokens.expiresIn,
	}); err != nil {
		return fmt.Errorf("register with agent: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Logged in. Registered %q with the hush agent (access token expires in %d seconds).\n",
		name, tokens.expiresIn)
	return nil
}

type rawTokens struct {
	access    string
	refresh   string
	expiresIn int
}

func exchangeCode(tokenURL, clientID, code, state, redirectURI, verifier string) (rawTokens, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"code":          code,
		"state":         state,
		"redirect_uri":  redirectURI,
		"code_verifier": verifier,
	})

	httpClient := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(string(body)))
	if err != nil {
		return rawTokens{}, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return rawTokens{}, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return rawTokens{}, fmt.Errorf("token exchange failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var parsed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return rawTokens{}, fmt.Errorf("parse token response: %w", err)
	}
	if parsed.AccessToken == "" || parsed.RefreshToken == "" {
		return rawTokens{}, fmt.Errorf("token endpoint returned empty access or refresh token")
	}
	return rawTokens{
		access:    parsed.AccessToken,
		refresh:   parsed.RefreshToken,
		expiresIn: parsed.ExpiresIn,
	}, nil
}

func openBrowser(target string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	_ = cmd.Start()
}
