//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/internal/credserve"
	"github.com/jack-work/hush/policy"
)

var credOverlayCmd = &cobra.Command{
	Use:   "overlay",
	Short: "Read or change the runtime overlay: temporary grants and suspensions",
	Long: `Talks to the overlay admin socket named in --config. Writes sign in
through the config's login gate first, when it has one.`,
}

var credOverlayLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List live grants and suspensions",
	Args:  cobra.NoArgs,
	RunE:  runOverlayLs,
}

var credOverlayGrantCmd = &cobra.Command{
	Use:   "grant <subject> <grant>",
	Short: "Grant a subject a temporary grant (expires; at most 30 days)",
	Args:  cobra.ExactArgs(2),
	RunE:  func(cmd *cobra.Command, args []string) error { return runOverlayAdd(cmd, "/v1/grants", args) },
}

var credOverlaySuspendCmd = &cobra.Command{
	Use:   "suspend <subject> <grant|*>",
	Short: "Deny a subject a grant (or every grant) until --for runs out or it is lifted",
	Args:  cobra.ExactArgs(2),
	RunE:  func(cmd *cobra.Command, args []string) error { return runOverlayAdd(cmd, "/v1/suspensions", args) },
}

var credOverlayRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Remove a temporary grant now",
	Args:  cobra.ExactArgs(1),
	RunE:  func(cmd *cobra.Command, args []string) error { return runOverlayDelete(cmd, "/v1/grants/", args[0]) },
}

var credOverlayLiftCmd = &cobra.Command{
	Use:   "lift <id>",
	Short: "Remove a suspension now",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runOverlayDelete(cmd, "/v1/suspensions/", args[0])
	},
}

func init() {
	credOverlayCmd.PersistentFlags().String("config", "/etc/hush-cred/config.toml", "the cred config naming the overlay admin socket and login gate")
	for _, c := range []*cobra.Command{credOverlayGrantCmd, credOverlaySuspendCmd} {
		c.Flags().Duration("for", 0, "how long it lasts (grants: required, at most 720h)")
		c.Flags().String("reason", "", "why (required; kept in the audit line)")
	}
	credOverlayCmd.AddCommand(credOverlayLsCmd, credOverlayGrantCmd, credOverlaySuspendCmd, credOverlayRevokeCmd, credOverlayLiftCmd)
	credCmd.AddCommand(credOverlayCmd)
}

// overlayClient is one admin socket session: its config and, after a sign-in,
// the bearer every write carries.
type overlayClient struct {
	conf   *credserve.Config
	http   *http.Client
	bearer string
}

func newOverlayClient(cmd *cobra.Command) (*overlayClient, error) {
	path, _ := cmd.Flags().GetString("config")
	conf, err := credserve.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	if conf.OverlayAdmin == nil {
		return nil, fmt.Errorf("%s has no overlay_admin socket", path)
	}
	sock := conf.OverlayAdmin.Socket
	return &overlayClient{conf: conf, http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}}, nil
}

// signIn runs the login gate, if the config has one, before a write.
func (o *overlayClient) signIn(cmd *cobra.Command) error {
	g := o.conf.LoginGate
	if g == nil {
		return nil
	}
	user, access, err := g.SignIn(cmd.Context(), credserve.FencedClient(o.conf.EgressHosts(), nil), cmd.ErrOrStderr(), 0)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s signed in (%s)\n", user, g.Group)
	o.bearer = access
	return nil
}

func (o *overlayClient) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://hush-cred"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if o.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+o.bearer)
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &e)
		return fmt.Errorf("%s %s: %d %s: %s", method, path, resp.StatusCode, e.Error, e.Reason)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func runOverlayLs(cmd *cobra.Command, _ []string) error {
	o, err := newOverlayClient(cmd)
	if err != nil {
		return err
	}
	var ov policy.Overlay
	if err := o.do(cmd.Context(), http.MethodGet, "/v1/overlay", nil, &ov); err != nil {
		return err
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tID\tSUBJECT\tGRANT\tEXPIRES\tBY\tREASON")
	for _, set := range []struct {
		kind    string
		entries []policy.Entry
	}{{"grant", ov.Grants}, {"suspension", ov.Suspensions}} {
		for _, e := range set.entries {
			exp := "until lifted"
			if !e.ExpiresAt.IsZero() {
				exp = e.ExpiresAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", set.kind, e.ID, e.Subject, e.Grant, exp, e.ApprovedBy, e.Reason)
		}
	}
	return w.Flush()
}

func runOverlayAdd(cmd *cobra.Command, path string, args []string) error {
	dur, _ := cmd.Flags().GetDuration("for")
	reason, _ := cmd.Flags().GetString("reason")
	if strings.TrimSpace(reason) == "" {
		return errors.New("--reason is required")
	}
	if dur < 0 || (path == "/v1/grants" && dur == 0) {
		return errors.New("--for must be positive (a grant always expires)")
	}
	o, err := newOverlayClient(cmd)
	if err != nil {
		return err
	}
	if err := o.signIn(cmd); err != nil {
		return err
	}
	req := map[string]any{"subject": args[0], "grant": args[1], "reason": reason}
	if dur > 0 {
		req["expires_at"] = time.Now().Add(dur).UTC()
	}
	var e policy.Entry
	if err := o.do(cmd.Context(), http.MethodPost, path, req, &e); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), e.ID)
	return nil
}

func runOverlayDelete(cmd *cobra.Command, prefix, id string) error {
	o, err := newOverlayClient(cmd)
	if err != nil {
		return err
	}
	if err := o.signIn(cmd); err != nil {
		return err
	}
	if err := o.do(cmd.Context(), http.MethodDelete, prefix+id, nil, nil); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "removed %s\n", id)
	return nil
}
