package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/lxc/incus/v7/shared/api"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/model"
)

func renderCmd() *cobra.Command {
	var host string
	var kind string
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Print fully-resolved fleet state for a host as YAML",
		Long: `Loads shared/ and hosts/<host>/, expands @aliases, and prints the
concrete objects that would be pushed to Incus on sync.

Uses the tool's own model types (YAML-tagged) so output round-trips
through validate.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch kind {
			case "all", "address-sets", "acls", "instances":
			default:
				return fmt.Errorf("unknown --kind %q (want all, address-sets, acls, instances)", kind)
			}
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			fleet, err := config.Load(configDir, host)
			if err != nil {
				return err
			}
			if err := fleet.ValidateSemantic(); err != nil {
				return err
			}
			return runRender(fleet, kind)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&kind, "kind", "all", "Object kind: all, address-sets, acls, instances")
	return cmd
}

// renderedInstance is the shape sync would PATCH onto the live instance —
// only managed device keys, effective ACL list resolved. Uses YAML tags
// consistent with the rest of the repo.
type renderedInstance struct {
	Name          string                       `yaml:"name"`
	Description   string                       `yaml:"description,omitempty"`
	OriginalImage string                       `yaml:"original_image,omitempty"`
	Tags          []string                     `yaml:"tags,omitempty"`
	Devices       map[string]map[string]string `yaml:"devices,omitempty"`
}

// resolvedAddressSet mirrors model.AddressSet's YAML shape but takes
// pre-resolved literal addresses (no @refs).
type resolvedAddressSet struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Addresses   []string          `yaml:"addresses"`
	Config      map[string]string `yaml:"config,omitempty"`
}

// resolvedACL mirrors model.ACL's YAML shape but with @refs pre-expanded
// in rule source/destination fields.
type resolvedACL struct {
	Name        string               `yaml:"name"`
	Description string               `yaml:"description,omitempty"`
	Ingress     []api.NetworkACLRule `yaml:"ingress,omitempty"`
	Egress      []api.NetworkACLRule `yaml:"egress,omitempty"`
	Config      map[string]string    `yaml:"config,omitempty"`
}

func runRender(fleet *config.Fleet, kind string) error {
	out := struct {
		AddressSets []resolvedAddressSet `yaml:"address_sets,omitempty"`
		ACLs        []resolvedACL        `yaml:"acls,omitempty"`
		Instances   []renderedInstance   `yaml:"instances,omitempty"`
	}{}

	if kind == "all" || kind == "address-sets" {
		for _, n := range sortedKeys(fleet.AddressSets) {
			s := fleet.AddressSets[n]
			resolved, err := fleet.ResolveAddresses(s.RawAddresses())
			if err != nil {
				return err
			}
			out.AddressSets = append(out.AddressSets, resolvedAddressSet{
				Name:        s.Name,
				Description: s.Description,
				Addresses:   resolved,
				Config:      s.Config,
			})
		}
	}

	if kind == "all" || kind == "acls" {
		for _, n := range sortedKeys(fleet.ACLs) {
			a := fleet.ACLs[n]
			ingress, err := resolveRules(fleet, a.Ingress)
			if err != nil {
				return err
			}
			egress, err := resolveRules(fleet, a.Egress)
			if err != nil {
				return err
			}
			out.ACLs = append(out.ACLs, resolvedACL{
				Name:        a.Name,
				Description: a.Description,
				Ingress:     ingress,
				Egress:      egress,
				Config:      a.Config,
			})
		}
	}

	if kind == "all" || kind == "instances" {
		for _, n := range sortedKeys(fleet.Instances) {
			inst := fleet.Instances[n]
			devMap := map[string]map[string]string{}
			effDevs := inst.EffectiveDevices()
			devNames := make([]string, 0, len(effDevs))
			for d := range effDevs {
				devNames = append(devNames, d)
			}
			sort.Strings(devNames)
			for _, d := range devNames {
				dev := effDevs[d]
				m := dev.ToDeviceMap()
				effective, _ := fleet.EffectiveACLs(inst, d)
				if len(effective) > 0 {
					m["security.acls"] = strings.Join(effective, ",")
				}
				devMap[d] = m
			}
			out.Instances = append(out.Instances, renderedInstance{
				Name:          inst.Name,
				Description:   inst.Description,
				OriginalImage: inst.OriginalImage,
				Tags:          inst.Tags,
				Devices:       devMap,
			})
		}
	}

	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	return enc.Encode(out)
}

func resolveRules(fleet *config.Fleet, rules []api.NetworkACLRule) ([]api.NetworkACLRule, error) {
	out := make([]api.NetworkACLRule, 0, len(rules))
	for _, r := range rules {
		var err error
		r.Source, err = fleet.ResolveField(r.Source)
		if err != nil {
			return nil, err
		}
		r.Destination, err = fleet.ResolveField(r.Destination)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = model.AliasRef
