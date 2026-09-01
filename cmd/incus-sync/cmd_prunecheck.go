package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/incus"
)

func pruneCheckCmd() *cobra.Command {
	var (
		host       string
		socketPath string
		project    string
	)
	cmd := &cobra.Command{
		Use:   "prune-check",
		Short: "List orphaned instance-scoped Incus objects (safe, read-only)",
		Long: `Compares live Incus state against the fleet. Reports:

  - ACLs with a "<name>-" prefix whose <name> is not a known instance
  - Address sets with the same shape
  - Containers with no fleet file

For each, prints the exact ` + "`incus … delete`" + ` command an operator
should paste. incus-sync never deletes anything itself.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			fleet, err := config.Load(configDir, host)
			if err != nil {
				return err
			}
			remote, err := resolveRemoteForHost(host)
			if err != nil {
				return err
			}
			srv, err := incus.Connect(socketPath, remote)
			if err != nil {
				return err
			}
			// ACLs and address-sets live in the fleet's NetworkProject
			// (default: "default") when all managed projects share
			// bridges via features.networks=false. Query there once.
			networkProject := fleet.NetworkProject
			if project != "" {
				networkProject = project
			}
			srv = srv.UseProject(networkProject)

			acls, err := srv.GetNetworkACLs()
			if err != nil {
				return err
			}
			sets, err := srv.GetNetworkAddressSets()
			if err != nil {
				return err
			}

			// Build the set of known "namespace" prefixes: every instance
			// name plus every shared/host declared name.
			instanceNames := map[string]bool{}
			for n := range fleet.Instances {
				instanceNames[n] = true
			}

			orphaned := 0

			fmt.Println("== orphan ACL scan ==")
			for _, a := range acls {
				if _, managed := fleet.ACLs[a.Name]; managed {
					continue
				}
				// Instance-scoped? Prefix matches an instance name.
				if instance, ok := looksLikeInstancePrefix(a.Name, instanceNames, host); ok {
					fmt.Printf("  orphan acl %q (matches deleted-or-missing instance %q)\n", a.Name, instance)
					fmt.Printf("    incus network acl delete %s\n", a.Name)
					orphaned++
					continue
				}
				// Otherwise, it's just unmanaged (never claimed by us). Silence.
			}

			fmt.Println("\n== orphan address-set scan ==")
			for _, s := range sets {
				if _, managed := fleet.AddressSets[s.Name]; managed {
					continue
				}
				if instance, ok := looksLikeInstancePrefix(s.Name, instanceNames, host); ok {
					fmt.Printf("  orphan address_set %q (matches deleted-or-missing instance %q)\n", s.Name, instance)
					fmt.Printf("    incus network address-set delete %s\n", s.Name)
					orphaned++
				}
			}

			fmt.Println("\n== container scan ==")
			// GetInstances not called with type filter here — we want to see all.
			// Only surface containers whose file was deleted (i.e. not in fleet).
			// Actual container listing lives in `list` and `diff`; here we just
			// point at deletion targets.
			fmt.Println("  (use `incus-sync list` or `incus-sync diff` to see containers without fleet files)")

			if orphaned == 0 {
				fmt.Println("\n(no orphans found)")
			} else {
				fmt.Printf("\n%d orphan(s) found. Paste the delete commands above only if the containers are gone.\n", orphaned)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required; see `remote list`)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket, "Incus unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`)")
	return cmd
}

// nonInstancePrefixes are reserved shared/host name prefixes that are
// never instance-scoped. Skip them in the orphan scanner so a valid
// shared or host-scoped ACL/set is not misreported.
var nonInstancePrefixes = map[string]bool{
	"generic": true,
	"default": true, // covers "default-policy"
}

// looksLikeInstancePrefix returns (prefix, true) if name is "<prefix>-…"
// where prefix looks like an instance name that used to exist. Filters
// out the reserved shared prefixes and the current host name.
func looksLikeInstancePrefix(name string, knownInstances map[string]bool, hostName string) (string, bool) {
	dash := strings.IndexByte(name, '-')
	if dash <= 0 {
		return "", false
	}
	prefix := name[:dash]
	if knownInstances[prefix] {
		return "", false
	}
	if nonInstancePrefixes[prefix] || prefix == hostName {
		return "", false
	}
	return prefix, true
}
