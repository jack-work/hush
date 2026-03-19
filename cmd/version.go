package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jack-work/hush/client"
	"github.com/jack-work/hush/version"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print hush CLI and agent version",
	RunE:  runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Printf("hush %s\n", version.Version)

	// Also try to query the running agent's version.
	if cfg != nil {
		sockPath := filepath.Join(cfg.RuntimeDir, "agent.sock")
		c := client.NewWithSocket(sockPath)
		if v, err := c.Version(); err == nil {
			fmt.Printf("agent %s\n", v)
		} else {
			fmt.Println("agent not running")
		}
	}

	return nil
}
