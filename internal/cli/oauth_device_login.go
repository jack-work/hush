package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/internal/oauth"
)

func init() {
	f := oauthDeviceLoginCmd.Flags()
	f.String("issuer", "", "OIDC issuer URL: endpoints are discovered from it (required)")
	f.String("client-id", "", "OAuth client ID (defaults to <name>)")
	f.String("scopes", "openid profile groups offline_access", "space-separated scopes")
	f.Bool("no-browser", false, "print the URL instead of opening a browser")
	oauthCmd.AddCommand(oauthDeviceLoginCmd)
}

var oauthDeviceLoginCmd = &cobra.Command{
	Use:   "device-login <name>",
	Short: "Log in with the device flow and register the tokens with the agent",
	Long: `Run the OAuth device authorization grant (RFC 8628) and hand the resulting
token pair to the hush agent, which then owns refresh.

Endpoints are DISCOVERED from the issuer, so this is all it takes:

    hush oauth device-login herald --issuer https://auth.kelliher.info

Device flow is the right shape for a command-line tool: there is no redirect
URI, no localhost listener and no port to bind, so it works unchanged over
SSH, on a headless machine, or in a container: none of which survive an
authorization-code redirect. You approve a short code on whatever device
already has a browser.

The credential name doubles as the default client_id, which is worth keeping
true: one name for the CLI, the OIDC client and the hush credential removes
a whole class of "which name goes where".`,
	Args: cobra.ExactArgs(1),
	RunE: runOAuthDeviceLogin,
}

func runOAuthDeviceLogin(cmd *cobra.Command, args []string) error {
	name := args[0]
	issuer, _ := cmd.Flags().GetString("issuer")
	clientID, _ := cmd.Flags().GetString("client-id")
	scopes, _ := cmd.Flags().GetString("scopes")
	noBrowser, _ := cmd.Flags().GetBool("no-browser")

	if issuer == "" {
		return fmt.Errorf("--issuer is required (e.g. --issuer https://auth.kelliher.info)")
	}
	if clientID == "" {
		clientID = name
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
	defer cancel()

	httpc := &http.Client{Timeout: 30 * time.Second}

	disco, err := oauth.Discover(ctx, httpc, issuer)
	if err != nil {
		return err
	}
	if !disco.SupportsDeviceFlow() {
		return fmt.Errorf("%s does not advertise a device_authorization_endpoint; "+
			"use `hush oauth login` (authorization code) instead", issuer)
	}

	da, err := oauth.RequestDeviceCode(ctx, httpc, disco.DeviceAuthorizationEndpoint, clientID, scopes)
	if err != nil {
		return err
	}

	target := da.VerificationURIComplete
	if target == "" {
		target = da.VerificationURI
	}
	fmt.Fprintf(os.Stderr, "\n  Open:  %s\n  Code:  %s\n\n", target, da.UserCode)
	if !noBrowser {
		openBrowser(target)
	}
	fmt.Fprintf(os.Stderr, "waiting for approval (expires %s)…\n",
		da.Expiry().Format(time.Kitchen))

	toks, err := oauth.PollDeviceToken(ctx, httpc, disco.TokenEndpoint, clientID, da)
	if err != nil {
		return err
	}

	c := client.NewWithSocket(filepath.Join(cfg.RuntimeDir, "agent.sock"))
	if err := c.OAuthRegister(client.OAuthRegisterRequest{
		Name:         name,
		TokenURL:     disco.TokenEndpoint,
		ClientID:     clientID,
		Scopes:       scopes,
		AccessToken:  toks.AccessToken,
		RefreshToken: toks.RefreshToken,
		ExpiresIn:    toks.ExpiresIn,
	}); err != nil {
		return fmt.Errorf("register with agent: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nregistered %q with the agent", name)
	if toks.RefreshToken == "" {
		// Worth saying plainly: without offline_access the credential dies
		// at the first expiry and the user must log in again.
		fmt.Fprintf(os.Stderr, "\n\nwarning: no refresh_token was issued: the credential cannot be\n"+
			"renewed and will stop working when the access token expires.\n"+
			"Request the offline_access scope if the provider supports it.")
	}
	fmt.Fprintln(os.Stderr)
	return nil
}
