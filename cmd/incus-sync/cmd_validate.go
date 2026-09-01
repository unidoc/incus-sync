package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
)

func validateCmd() *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Parse and semantically check the fleet repo",
		Long: `Loads shared/ and hosts/<host>/ YAML and runs three layers of checks:

  1. Structural — YAML parses, filename matches declared name,
     no duplicate names across scopes.
  2. Referential — every @alias, $address-set, and ACL reference resolves.
  3. Semantic — actions, protocols, ports, addresses, and default actions
     match what Incus is documented to accept, so sync will not surprise you.

Default (no --host): every host under hosts/ is validated in turn. If
any fails, the whole command exits non-zero after the summary.

Read-only. Safe to run as a pre-commit hook or in CI.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host != "" {
				return validateOne(host)
			}
			hosts, err := config.ListHosts(fleetPath)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				return fmt.Errorf("no hosts under %s/hosts/", fleetPath)
			}
			var failed []string
			for _, h := range hosts {
				fmt.Printf("== %s ==\n", h)
				if err := validateOne(h); err != nil {
					fmt.Fprintf(os.Stderr, "  %s: %v\n", h, err)
					failed = append(failed, h)
				}
				fmt.Println()
			}
			if len(failed) > 0 {
				return fmt.Errorf("validate failed for %d host(s): %s", len(failed), strings.Join(failed, ", "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Scope to one host. Default: validate every host.")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	return cmd
}

func validateOne(host string) error {
	fleet, err := config.Load(fleetPath, host)
	if err != nil {
		return err
	}
	if err := fleet.ValidateSemantic(); err != nil {
		return err
	}
	fmt.Printf("Host: %s\n", fleet.Host)
	fmt.Printf("  aliases:      %d\n", len(fleet.Aliases))
	fmt.Printf("  address sets: %d\n", len(fleet.AddressSets))
	fmt.Printf("  ACLs:         %d\n", len(fleet.ACLs))
	fmt.Printf("  instances:    %d\n", len(fleet.Instances))
	fmt.Printf("  policies:     %d\n", len(fleet.Policies))
	fmt.Printf("  templates:    %d\n", len(fleet.Templates))
	if len(fleet.Warnings) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, w := range fleet.Warnings {
			fmt.Fprintln(os.Stderr, w)
		}
	}
	return nil
}
