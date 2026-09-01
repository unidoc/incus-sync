package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
)

// fleetCmd runs another incus-sync subcommand once per configured
// remote. Replaces the SSH-based orchestrator.sh loop.
//
// Usage:
//
//	incus-sync fleet diff
//	incus-sync fleet diff --format=json
//	incus-sync fleet sync --apply --yes
//
// Under the hood: `incus-sync fleet CMD ARGS...` shell-loops
//
//	incus-sync --host <host> CMD ARGS...
//
// for every host with a hosts/<host>/remote.sops.yaml.
//
// Failures don't stop the loop — each host runs independently.
// Overall exit code is non-zero if any host errored.
func fleetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fleet <subcommand> [args...]",
		Short: "Run a subcommand across every configured remote host",
		Long: `Iterates every host under hosts/<h>/ that has a remote.sops.yaml
and invokes the subcommand once per host with --host set. Non-local
--host values automatically use HTTPS via hosts/<host>/remote.sops.yaml.

Examples:
  incus-sync fleet doctor
  incus-sync fleet diff
  incus-sync fleet diff --format=json
  incus-sync fleet sync --apply --yes`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true, // pass raw args through
		RunE: func(cmd *cobra.Command, args []string) error {
			hosts, err := config.ListRemotes(configDir)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				return fmt.Errorf("no remotes configured (no hosts/<h>/remote.sops.yaml found)")
			}
			// Reinvoke self, once per host.
			self, err := os.Executable()
			if err != nil {
				return err
			}
			var overallErr error
			for _, h := range hosts {
				fmt.Printf("\n== %s ==\n", h)
				invocation := []string{"--config-dir", configDir, "--host", h}
				invocation = append(invocation, args...)
				c := exec.Command(self, invocation...)
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "  (host %s failed: %v)\n", h, err)
					overallErr = fmt.Errorf("one or more hosts failed")
				}
			}
			return overallErr
		},
	}
	return cmd
}
