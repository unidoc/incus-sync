package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lxc/incus/v7/shared/api"
	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/incus"
	"github.com/unidoc/incus-sync/internal/model"
)

// importCmd pulls one live container into the fleet as
// hosts/<host>/instances/<name>/instance.yaml. Companion to `orphans` —
// first find, then bring under control.
//
// Never mutates Incus state. Never overwrites an existing instance file
// without --force.
func importCmd() *cobra.Command {
	var (
		host       string
		socketPath string
		project    string
		force      bool
	)
	cmd := &cobra.Command{
		Use:   "import <instance>",
		Short: "Import an existing container from a host into the fleet",
		Long: `Reads the live container's Incus config and writes
hosts/<host>/instances/<name>/instance.yaml.

Fields imported:
  - description
  - ip4 / ip6           from the eth0 device (or ExpandedDevices)
  - acls                whatever is currently in security.acls
  - ingress-default     from security.acls.default.ingress.action
  - egress-default      from security.acls.default.egress.action

Fields NOT imported (unknowable post-hoc):
  - original_image      the launch-time image is not preserved by Incus
  - provision           this container was not provisioned by incus-sync
  - tags                Incus does not model tags; a fleet-repo concept only

After import, edit the file to add missing metadata, then run
` + "`incus-sync diff --host <host>`" + ` to confirm no drift.

Warnings are printed for any attached ACL that does not exist in the
fleet — you probably want ` + "`incus-sync adopt --host <host>`" + `
to pull those definitions in as well.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			remote, err := resolveRemoteForHost(host)
			if err != nil {
				return err
			}
			srv, err := incus.Connect(socketPath, remote)
			if err != nil {
				return err
			}
			proj, err := resolveProject(project)
			if err != nil {
				return err
			}
			project = proj
			srv = srv.UseProject(project)
			fleet, err := config.Load(fleetPath, host)
			if err != nil {
				return err
			}
			return runImport(srv, fleet, host, name, force)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required; see `remote list`)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket, "Incus unix socket path (local target only)")
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing instance.yaml")
	return cmd
}

func runImport(srv incusServer, fleet *config.Fleet, host, name string, force bool) error {
	live, _, err := srv.GetInstance(name)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", name, err)
	}
	obj := model.InstanceFromAPI(*live)

	instDir := filepath.Join(fleetPath, "hosts", host, "instances", name)
	path := filepath.Join(instDir, "instance.yaml")
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists — pass --force to overwrite", path)
	}
	if err := os.MkdirAll(instDir, 0o755); err != nil {
		return err
	}
	if err := writeYAML(path, obj, instanceHeader); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", path)

	// Warn on ACLs referenced by this container but missing from fleet.
	missing := missingACLs(obj, fleet)
	if len(missing) > 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "warning: %d attached ACL(s) not in fleet: %s\n",
			len(missing), strings.Join(missing, ", "))
		fmt.Fprintf(os.Stderr, "  Import them alongside with: incus-sync adopt --host %s\n", host)
		fmt.Fprintln(os.Stderr, "  (adopt dumps ALL live state; then review + git add only what you want)")
	}
	fmt.Println("Next steps:")
	fmt.Printf("  1. Edit %s (original_image, tags, provision if you want re-create semantics)\n", path)
	fmt.Printf("  2. incus-sync diff --host %s   # confirm no drift\n", host)
	return nil
}

// missingACLs returns the sorted set of ACL names referenced by the
// instance's device that are not defined in the fleet.
func missingACLs(inst model.Instance, fleet *config.Fleet) []string {
	seen := map[string]bool{}
	for _, dev := range inst.EffectiveDevices() {
		if dev == nil {
			continue
		}
		for _, name := range dev.SecurityACLs {
			if _, ok := fleet.ACLs[name]; !ok {
				seen[name] = true
			}
		}
	}
	for _, name := range inst.AttachedACLs {
		if _, ok := fleet.ACLs[name]; !ok {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// incusServer is the minimal subset of incusclient.InstanceServer this
// command needs. Declared as a local interface so tests can stub it
// without pulling in the full Incus client.
type incusServer interface {
	GetInstance(name string) (*api.Instance, string, error)
}
