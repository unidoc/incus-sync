package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/unidoc/incus-sync/internal/incus"
	"github.com/unidoc/incus-sync/internal/model"
)

func adoptCmd() *cobra.Command {
	var (
		host       string
		outDir     string
		socketPath string
		project    string
	)

	cmd := &cobra.Command{
		Use:   "adopt",
		Short: "Read live Incus state into per-object YAML files (safe, read-only)",
		Long: `Connects to the local Incus daemon via unix socket, reads all
network address sets, network ACLs, and instance eth0 device config, then
writes them as one-object-per-file YAML into hosts/<host>/.

Output layout:
  hosts/<host>/address-sets/<name>.yaml    # one address set per file
  hosts/<host>/acls/<name>.yaml            # one ACL per file
  hosts/<host>/instances/<name>/instance.yaml   # one dir per container
                                             (includes managed eth0 device keys)

Comments on individual addresses are always empty after adopt — Incus does
not store them. Fill them in manually.

adopt is read-only; it never mutates Incus state. Existing files are
overwritten only if they differ.`,
		Example: `  incus-sync adopt                             # host = hostname -s
  incus-sync adopt --host web1
  incus-sync adopt --host web1 --out /tmp/scratch`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			if outDir == "" {
				outDir = filepath.Join(configDir, "hosts", host)
			}
			return runAdopt(host, outDir, socketPath, project)
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "Host name (required); write under hosts/<name>/")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&outDir, "out", "", "Output directory (default: <config-dir>/hosts/<host>)")
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket, "Incus unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`) to read from")

	return cmd
}

func runAdopt(host, outDir, socketPath, project string) error {
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

	nSets, err := dumpAddressSets(srv, outDir)
	if err != nil {
		return fmt.Errorf("address sets: %w", err)
	}

	nACLs, err := dumpACLs(srv, outDir)
	if err != nil {
		return fmt.Errorf("acls: %w", err)
	}

	nInstances, err := dumpInstances(srv, outDir)
	if err != nil {
		return fmt.Errorf("instances: %w", err)
	}

	fmt.Printf("Adopted from host %q (project %q):\n", host, project)
	fmt.Printf("  %3d address sets → %s/address-sets/\n", nSets, outDir)
	fmt.Printf("  %3d ACLs         → %s/acls/\n", nACLs, outDir)
	fmt.Printf("  %3d instances    → %s/instances/\n", nInstances, outDir)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  - Review the generated YAML")
	fmt.Println("  - Add comments to addresses (they don't exist in Incus)")
	fmt.Println("  - Move fleet-wide objects into ../../shared/{address-sets,acls}/")
	fmt.Println("  - Move instance-scoped ACLs into instances/<name>/instance.yaml alongside")
	fmt.Println("    the device block, so each container is one file to review.")
	return nil
}

func dumpAddressSets(srv incusclient.InstanceServer, outDir string) (int, error) {
	sets, err := srv.GetNetworkAddressSets()
	if err != nil {
		return 0, err
	}
	dir := filepath.Join(outDir, "address-sets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	for _, s := range sets {
		s.Normalise()
		obj := model.AddressSetFromAPI(s)
		path := filepath.Join(dir, obj.Name+".yaml")
		if err := writeYAML(path, obj, addressSetHeader); err != nil {
			return 0, err
		}
	}
	return len(sets), nil
}

func dumpACLs(srv incusclient.InstanceServer, outDir string) (int, error) {
	acls, err := srv.GetNetworkACLs()
	if err != nil {
		return 0, err
	}
	dir := filepath.Join(outDir, "acls")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	for _, a := range acls {
		obj := model.ACLFromAPI(a)
		path := filepath.Join(dir, obj.Name+".yaml")
		if err := writeYAML(path, obj, aclHeader); err != nil {
			return 0, err
		}
	}
	return len(acls), nil
}

func dumpInstances(srv incusclient.InstanceServer, outDir string) (int, error) {
	instances, err := srv.GetInstances(api.InstanceTypeAny)
	if err != nil {
		return 0, err
	}
	base := filepath.Join(outDir, "instances")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return 0, err
	}
	written := 0
	for _, inst := range instances {
		obj := model.InstanceFromAPI(inst)
		// Skip instances that have no managed state at all.
		if obj.EffectiveDevices() == nil {
			continue
		}
		instDir := filepath.Join(base, obj.Name)
		if err := os.MkdirAll(instDir, 0o755); err != nil {
			return 0, err
		}
		path := filepath.Join(instDir, "instance.yaml")
		if err := writeYAML(path, obj, instanceHeader); err != nil {
			return 0, err
		}
		written++
	}
	return written, nil
}

// writeYAML marshals v with a leading header comment, writing atomically.
// Overwrite is skipped when the file exists with identical content — keeps
// mtimes stable for repeated adopt runs and avoids noisy git diffs.
func writeYAML(path string, v any, header string) error {
	var buf bytes.Buffer
	if header != "" {
		buf.WriteString(header)
	}
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	newContent := buf.Bytes()

	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, newContent) {
		return nil
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, newContent, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

const addressSetHeader = `# incus-sync address set
#
# Each entry may use either form:
#   - 203.0.113.10                                    # plain string
#   - address: 198.51.100.20                           # with human comment
#     comment: bogor v4 — AlbaHost Tirana
#
# Comments live only in git — Incus stores addresses as plain strings.

`

const aclHeader = `# incus-sync network ACL
#
# Schema matches Incus's own ` + "`incus network acl show <name> --format=yaml`" + `.
# See linuxcontainers.org/incus/docs/main/howto/network_acls/ for field semantics.

`

const instanceHeader = `# incus-sync instance
#
# This file describes the network policy for a single container:
#   - device:       eth0 device keys this tool reconciles (static IPs,
#                   attached ACLs). Other device keys are left alone.
#   - acls:         ACLs owned by this instance (name must start with <instance>-).
#   - address_sets: address sets scoped to this instance (name must start with
#                   <instance>-). Rare — most sets belong in shared/.

`
