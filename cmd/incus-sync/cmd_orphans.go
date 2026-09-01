package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/lxc/incus/v7/shared/api"
	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/incus"
)

// orphansCmd lists containers that exist on a host but do NOT have an
// instance directory in the fleet. Companion to `import` — first find,
// then bring under control.
//
// This is a strictly read-only report; no state on the daemon or in the
// fleet is mutated. Safe to run in CI as a drift check.
func orphansCmd() *cobra.Command {
	var (
		host       string
		socketPath string
		project    string
	)
	cmd := &cobra.Command{
		Use:   "orphans",
		Short: "List containers on the host that are not in the fleet",
		Long: `Lists every container Incus knows about on <host> that does not
have a matching hosts/<host>/instances/<name>/ directory in the fleet.

For each orphan, prints:
  - status (running / stopped)
  - image source (if declared)
  - IPs currently assigned
  - security.acls currently attached

Emits the exact ` + "`incus-sync import`" + ` command to pull each one
under fleet control. Nothing is mutated.`,
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
			// Sweep every managed project; unmanaged containers can
			// live in any of them. --project narrows scope.
			var live []api.InstanceFull
			for _, p := range fleet.Projects {
				if project != "" && project != p {
					continue
				}
				scoped := srv.UseProject(p)
				got, err := scoped.GetInstancesFull(api.InstanceTypeAny)
				if err != nil {
					return fmt.Errorf("list %q: %w", p, err)
				}
				live = append(live, got...)
			}
			return runOrphans(fleet, live, host)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required; see `remote list`)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket, "Incus unix socket path (local target only)")
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`)")
	return cmd
}

func runOrphans(fleet *config.Fleet, live []api.InstanceFull, host string) error {
	managed := map[string]bool{}
	for name := range fleet.Instances {
		managed[name] = true
	}

	var orphans []api.InstanceFull
	for _, l := range live {
		if !managed[l.Name] {
			orphans = append(orphans, l)
		}
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Name < orphans[j].Name })

	if len(orphans) == 0 {
		fmt.Printf("No orphans on %s — every container is under fleet control.\n", host)
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATUS\tIMAGE\tACLS\tIPS")
	for _, o := range orphans {
		image := "-"
		if src, ok := o.Config["image.description"]; ok && src != "" {
			image = src
		} else if src, ok := o.Config["volatile.base_image"]; ok && src != "" {
			image = shortHash(src)
		}
		acls := "-"
		if eth0, ok := o.ExpandedDevices["eth0"]; ok {
			if v := eth0["security.acls"]; v != "" {
				acls = v
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			o.Name, strings.ToUpper(o.Status), image, acls,
			strings.Join(instanceIPs(o), " "))
	}
	tw.Flush()

	fmt.Println()
	fmt.Printf("%d orphan(s) on %s. Bring each under fleet control with:\n", len(orphans), host)
	for _, o := range orphans {
		fmt.Printf("  incus-sync import %s --host %s\n", o.Name, host)
	}
	return nil
}

// shortHash trims a 64-char image fingerprint to the first 12 for tabular
// display. Left untouched if it does not look like a hash.
func shortHash(s string) string {
	if len(s) >= 64 && !strings.ContainsAny(s, ":/ ") {
		return s[:12]
	}
	return s
}
