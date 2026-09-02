package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/incus"
)

// refreshNftCmd works around an Incus behaviour where the kernel
// nftables sets that back network address-sets can be evicted when all
// referencing containers stop. The next container start then fails with
// a message like:
//
//	Failed to run: nft -f -: ... @secure-servers_ipv4 ...
//	No such file or directory
//
// The fix is to make Incus emit a CHANGED event for each address-set,
// which triggers server-side regeneration of the kernel nft state. The
// address-set contents themselves are not modified — this is a no-op
// from a config perspective, only a state-machine kick.
//
// Interactive equivalent is `incus network address-set edit <name>`
// followed by "save without changes"; refresh-nft does that for every
// managed address-set on the host in one shot.
func refreshNftCmd() *cobra.Command {
	var host string
	var socketPath string
	cmd := &cobra.Command{
		Use:   "refresh-nft",
		Short: "Force Incus to re-emit nftables state for every address-set on a host",
		Long: `Works around an Incus quirk where nftables sets backing network
address-sets can be evicted (typically after all referencing containers
stop). The next container that tries to start fails at
"nft -f -: @<set> No such file or directory".

For every address-set in the network project, refresh-nft reads the
current spec and PUTs it back unchanged. Incus emits a CHANGED event
and regenerates the kernel nft state. Address-set contents are not
modified.

Idempotent. Safe to run as a pre-start hook, from a systemd oneshot on
incusd startup, or manually when a container refuses to boot with the
symptom above.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			return runRefreshNft(host, socketPath)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Target host (required).")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket,
		"Path to the local Incus unix socket (ignored for remote hosts).")
	return cmd
}

func runRefreshNft(host, socketPath string) error {
	remote, err := resolveRemoteForHost(host)
	if err != nil {
		return err
	}
	srv, err := incus.Connect(socketPath, remote)
	if err != nil {
		return err
	}

	meta, err := config.LoadFleetMeta(fleetPath)
	if err != nil {
		return err
	}

	// Address-sets and ACLs live in the network project (features.networks=false
	// on managed projects means they share default's network namespace).
	netSrv := srv.UseProject(meta.NetworkProject)

	sets, err := netSrv.GetNetworkAddressSets()
	if err != nil {
		return fmt.Errorf("list address-sets in project %q: %w", meta.NetworkProject, err)
	}
	if len(sets) == 0 {
		fmt.Printf("no address-sets in project %q — nothing to refresh\n", meta.NetworkProject)
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS-SET\tSTATUS")
	failed := 0
	for _, as := range sets {
		// Re-fetch to get a fresh ETag (list results don't include it).
		current, etag, err := netSrv.GetNetworkAddressSet(as.Name)
		if err != nil {
			fmt.Fprintf(tw, "%s\tGET failed: %v\n", as.Name, err)
			failed++
			continue
		}
		// PUT with identical body. On the server side this still runs
		// through the address-set update path and re-emits nft rules —
		// that's what we want. If a future Incus release short-circuits
		// no-op PUTs, switch to a description toggle here.
		if err := netSrv.UpdateNetworkAddressSet(as.Name, current.Writable(), etag); err != nil {
			fmt.Fprintf(tw, "%s\tUPDATE failed: %v\n", as.Name, err)
			failed++
			continue
		}
		fmt.Fprintf(tw, "%s\ttouched\n", as.Name)
	}
	_ = tw.Flush()

	if failed > 0 {
		return fmt.Errorf("%d/%d address-set refreshes failed", failed, len(sets))
	}
	return nil
}
