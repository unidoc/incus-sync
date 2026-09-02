package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
)

func explainCmd() *cobra.Command {
	var host, instance, device string
	cmd := &cobra.Command{
		Use:   "explain <instance>",
		Short: "Explain why each ACL is attached to an instance",
		Long: `Prints the effective ACLs on the instance's device and, for each,
whether it came from the instance file, a matching policy, or both.

Use this to answer "why does webapp have this rule?" without grepping.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if instance == "" && len(args) != 1 {
				return fmt.Errorf("pass instance name as arg or via --instance")
			}
			return nil
		},
		ValidArgsFunction: instanceCompleter,
		RunE: func(cmd *cobra.Command, args []string) error {
			if instance == "" {
				instance = args[0]
			}
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			fleet, err := config.Load(fleetPath, host)
			if err != nil {
				return err
			}
			return runExplain(fleet, instance, device)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&instance, "instance", "", "Instance to explain (alternative to positional arg)")
	cmd.Flags().StringVar(&device, "device", "eth0", "Device to explain")
	return cmd
}

func runExplain(fleet *config.Fleet, instanceName, deviceName string) error {
	inst, ok := fleet.Instances[instanceName]
	if !ok {
		return fmt.Errorf("no instance %q defined for host %q", instanceName, fleet.Host)
	}

	fmt.Printf("Instance: %s\n", inst.Name)
	if inst.Description != "" {
		fmt.Printf("  description: %s\n", inst.Description)
	}
	if len(inst.Tags) > 0 {
		fmt.Printf("  tags: %s\n", strings.Join(inst.Tags, ", "))
	}
	fmt.Printf("  device: %s\n\n", deviceName)

	names, sources := fleet.EffectiveACLs(inst, deviceName)

	// Exclusions surface separately: they explain why an ACL that
	// would otherwise be policy-attached is missing from the effective set.
	var excluded []string
	for n, s := range sources {
		if s.Excluded {
			excluded = append(excluded, n)
		}
	}
	sort.Strings(excluded)

	if len(names) == 0 && len(excluded) == 0 {
		fmt.Println("No ACLs attached.")
		return nil
	}

	if len(names) > 0 {
		fmt.Println("Effective security.acls (sorted, deduped):")
	}
	for _, n := range names {
		s := sources[n]
		origin := []string{}
		if s.FromDevice {
			origin = append(origin, "device")
		}
		for _, p := range s.FromPolicy {
			origin = append(origin, "policy "+p)
		}
		fmt.Printf("  - %s\n", n)
		fmt.Printf("      from: %s\n", strings.Join(origin, ", "))
		if acl, ok := fleet.ACLs[n]; ok && acl.Description != "" {
			fmt.Printf("      what: %s\n", acl.Description)
		}
	}

	if len(excluded) > 0 {
		fmt.Println("\nExcluded (would attach, but instance opts out via acls-exclude):")
		for _, n := range excluded {
			s := sources[n]
			from := "policy " + strings.Join(s.FromPolicy, ", policy ")
			fmt.Printf("  - %s\n      would-attach: %s\n", n, from)
		}
	}

	if len(fleet.Policies) > 0 {
		fmt.Println("\nPolicies evaluated:")
		polNames := make([]string, 0, len(fleet.Policies))
		for n := range fleet.Policies {
			polNames = append(polNames, n)
		}
		sort.Strings(polNames)
		for _, n := range polNames {
			p := fleet.Policies[n]
			verdict := "MATCH"
			if !p.Matches(inst.Tags) {
				verdict = "no match"
			}
			fmt.Printf("  %-30s selector.tags=%v  → %s\n", n, p.Selector.Tags, verdict)
		}
	}
	return nil
}
