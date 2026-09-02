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

func listCmd() *cobra.Command {
	var (
		host       string
		socketPath string
		project    string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List managed instances with live status",
		Long: `Loads the fleet, fetches live state from Incus, and prints one
line per managed instance: status, image, tags, IPs. Instances present
in Incus but not in the fleet are shown as "unmanaged".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			fleet, err := config.Load(fleetPath, host)
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
			// Iterate every managed project; live containers may live
			// in any of them. --project filter narrows the output.
			var liveInsts []api.InstanceFull
			for _, p := range fleet.Projects {
				if project != "" && project != p {
					continue
				}
				scoped := srv.UseProject(p)
				got, err := scoped.GetInstancesFull(api.InstanceTypeAny)
				if err != nil {
					return fmt.Errorf("list instances in %q: %w", p, err)
				}
				liveInsts = append(liveInsts, got...)
			}
			return runList(fleet, liveInsts)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required; see `remote list`)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket, "Incus unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`)")
	return cmd
}

func runList(fleet *config.Fleet, live []api.InstanceFull) error {
	liveByName := map[string]api.InstanceFull{}
	for _, l := range live {
		liveByName[l.Name] = l
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTATUS\tIMAGE\tTAGS\tIPS")

	managed := map[string]bool{}
	names := make([]string, 0, len(fleet.Instances))
	for n := range fleet.Instances {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		inst := fleet.Instances[name]
		managed[name] = true
		status := "MISSING"
		ips := ""
		if l, ok := liveByName[name]; ok {
			status = strings.ToUpper(l.Status)
			ips = strings.Join(instanceIPs(l), " ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			name, status, inst.OriginalImage, strings.Join(inst.Tags, ","), ips)
	}

	for _, l := range live {
		if managed[l.Name] {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			l.Name, strings.ToUpper(l.Status)+"(unmanaged)", "-", "-", strings.Join(instanceIPs(l), " "))
	}
	return tw.Flush()
}

func instanceIPs(l api.InstanceFull) []string {
	if l.State == nil || l.State.Network == nil {
		return nil
	}
	var out []string
	// Iterate deterministically.
	names := make([]string, 0, len(l.State.Network))
	for n := range l.State.Network {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		net := l.State.Network[n]
		for _, addr := range net.Addresses {
			if addr.Scope == "link" || addr.Scope == "local" {
				continue
			}
			out = append(out, addr.Address)
		}
	}
	return out
}
