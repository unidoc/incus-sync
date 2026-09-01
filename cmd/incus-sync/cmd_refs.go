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
)

func refsCmd() *cobra.Command {
	var host string
	var all bool
	var rename string
	cmd := &cobra.Command{
		Use:   "refs <name>",
		Short: "List every place that references an alias, address set, ACL, or instance",
		Long: `Answers "what breaks if I rename or delete this?" — the exact
question a reviewer asks before approving a rename PR.

Default scope is the current host. --all iterates every host under
hosts/, so a rename PR knows the full fleet-wide impact.

With --rename NEW, prints the exact shell commands (git mv + sed) to
perform the rename cleanly. The tool never executes; the operator
pastes what looks right.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: objectCompleter,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if rename != "" {
				return runRefsRename(name, rename)
			}
			if all {
				return runRefsAll(name)
			}
			if host == "" {
				return fmt.Errorf("pass --host <name> (or --all to search every host)")
			}
			fleet, err := config.Load(configDir, host)
			if err != nil {
				return err
			}
			return runRefs(fleet, name)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required unless --all)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().BoolVar(&all, "all", false, "Iterate every host under hosts/ (fleet-wide blast radius)")
	cmd.Flags().StringVar(&rename, "rename", "", "Emit git mv + sed commands to rename to NEW-name across the fleet")
	return cmd
}

// runRefsRename walks every host, finds every file that mentions the
// old name, and prints paste-ready shell commands to perform the rename
// cleanly across the fleet. It does NOT execute the commands.
func runRefsRename(oldName, newName string) error {
	entries, err := os.ReadDir(filepath.Join(configDir, "hosts"))
	if err != nil {
		return fmt.Errorf("read hosts/: %w", err)
	}
	// The defining file is host-scope-agnostic — take the first hit.
	var definingPath, definingKind string
	// Collect every file that mentions the old name across every host load.
	referrers := map[string]struct{}{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fleet, err := config.Load(configDir, e.Name())
		if err != nil {
			continue
		}
		if definingPath == "" {
			for _, k := range []string{"alias", "address-set", "acl", "instance", "policy"} {
				if p := fleet.OriginOf(k, oldName); p != "" {
					definingPath = p
					definingKind = k
					break
				}
			}
		}
		collectReferrers(fleet, oldName, referrers)
	}

	fmt.Printf("# Rename plan: %q → %q\n", oldName, newName)
	fmt.Println("# Uses portable sed idioms (BSD/macOS/GNU compatible). Safe to run on the FreeBSD bastion.")
	fmt.Println()
	if definingPath != "" {
		newBase := filepath.Join(filepath.Dir(definingPath), newName+".yaml")
		fmt.Printf("# 1. Move the defining file (%s):\n", definingKind)
		fmt.Printf("git mv %s %s\n\n", definingPath, newBase)
		fmt.Printf("# 2. Update the name inside the moved file:\n")
		fmt.Printf("sed -i.bak 's|^%s: %s$|%s: %s|' %s && rm %s.bak\n\n",
			kindKey(definingKind), oldName, kindKey(definingKind), newName, newBase, newBase)
	} else {
		fmt.Printf("# (no defining file found for %q — check --all output first)\n\n", oldName)
	}
	if len(referrers) == 0 {
		fmt.Println("# No referring files found.")
		return nil
	}
	// Boundary via negative character class instead of \b (GNU only):
	//   trailing char must not be a valid name char [a-z0-9-].
	// This still catches @foo.ip6 (dot is not in the class).
	fmt.Println("# 3. Update every referrer (portable sed; boundary via [^a-z0-9-]):")
	paths := make([]string, 0, len(referrers))
	for p := range referrers {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if p == definingPath {
			continue
		}
		// End-of-line handled by an alternate expression per delimiter.
		fmt.Printf("sed -i.bak -E 's|@%s([^a-z0-9-]\\|$)|@%s\\1|g; s|\\$%s([^a-z0-9-]\\|$)|\\$%s\\1|g' %s && rm %s.bak\n",
			oldName, newName, oldName, newName, p, p)
	}
	fmt.Println()
	fmt.Println("# Then: validate + commit atomically.")
	fmt.Println("incus-sync validate")
	fmt.Println("git add -u && git commit -m 'rename " + oldName + " to " + newName + "'")
	return nil
}

// collectReferrers walks the fleet and adds every file that mentions the
// name to referrers. Best-effort — uses origins for aliases/sets/ACLs
// where declared; walks instance files by scanning inline lists.
func collectReferrers(fleet *config.Fleet, name string, referrers map[string]struct{}) {
	// Alias bodies referencing @name or @name.field
	for aName, alias := range fleet.Aliases {
		for _, addr := range alias.Addresses {
			if refMatchesName(addr, name) {
				if p := fleet.OriginOf("alias", aName); p != "" {
					referrers[p] = struct{}{}
				}
			}
		}
	}
	// Address sets referencing @name
	for sName, set := range fleet.AddressSets {
		for _, addr := range set.RawAddresses() {
			if refMatchesName(addr, name) {
				if p := fleet.OriginOf("address-set", sName); p != "" {
					referrers[p] = struct{}{}
				}
			}
		}
	}
	// ACL rules referencing @name or $name
	for aName, acl := range fleet.ACLs {
		hit := false
		for _, r := range append(append([]any{}, ruleFieldsFor(acl.Ingress)...), ruleFieldsFor(acl.Egress)...) {
			fields := r.([2]string)
			if refInField(fields[0], name) || refInField(fields[1], name) {
				hit = true
				break
			}
		}
		if hit {
			if p := fleet.OriginOf("acl", aName); p != "" {
				referrers[p] = struct{}{}
			}
		}
	}
	// Instances with the name in security.acls
	for iName, inst := range fleet.Instances {
		for _, dev := range inst.EffectiveDevices() {
			if dev == nil {
				continue
			}
			for _, n := range dev.SecurityACLs {
				if n == name {
					if p := fleet.OriginOf("instance", iName); p != "" {
						referrers[p] = struct{}{}
					}
				}
			}
		}
	}
	// Policies attaching the name
	for pName, pol := range fleet.Policies {
		for _, n := range pol.Attach.SecurityACLs {
			if n == name {
				if p := fleet.OriginOf("policy", pName); p != "" {
					referrers[p] = struct{}{}
				}
			}
		}
	}
}

// kindKey returns the YAML top-level key for the given object kind.
func kindKey(kind string) string {
	switch kind {
	case "alias":
		return "alias"
	case "address-set":
		return "name"
	case "acl":
		return "name"
	case "instance":
		return "instance"
	case "policy":
		return "policy"
	}
	return "name"
}

// runRefsAll walks every hosts/<h>/ and prints refs per host. Not found
// on individual host is silent — the object might exist only on some.
func runRefsAll(name string) error {
	entries, err := os.ReadDir(filepath.Join(configDir, "hosts"))
	if err != nil {
		return fmt.Errorf("read hosts/: %w", err)
	}
	found := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fleet, err := config.Load(configDir, e.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", e.Name(), err)
			continue
		}
		if !objectExistsIn(fleet, name) {
			continue
		}
		fmt.Printf("== host: %s ==\n", e.Name())
		if err := runRefs(fleet, name); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", e.Name(), err)
			continue
		}
		found = true
	}
	if !found {
		return fmt.Errorf("no object named %q in any host under %s/hosts/", name, configDir)
	}
	return nil
}

func objectExistsIn(f *config.Fleet, name string) bool {
	_, isA := f.Aliases[name]
	_, isS := f.AddressSets[name]
	_, isL := f.ACLs[name]
	_, isI := f.Instances[name]
	_, isP := f.Policies[name]
	return isA || isS || isL || isI || isP
}

func runRefs(fleet *config.Fleet, name string) error {
	// Refuse silent-success on typos. If the name isn't defined anywhere in
	// the fleet, tell the operator instead of pretending it's just unused.
	_, isAlias := fleet.Aliases[name]
	_, isSet := fleet.AddressSets[name]
	_, isACL := fleet.ACLs[name]
	_, isInst := fleet.Instances[name]
	_, isPol := fleet.Policies[name]
	if !isAlias && !isSet && !isACL && !isInst && !isPol {
		return fmt.Errorf("no object named %q in fleet (checked aliases, address_sets, acls, instances, policies)", name)
	}

	// Show where the object itself is defined so a rename PR knows the file to edit.
	fmt.Printf("References to %q on host %q:\n", name, fleet.Host)
	for _, kind := range []string{"alias", "address-set", "acl", "instance", "policy"} {
		if p := fleet.OriginOf(kind, name); p != "" {
			fmt.Printf("  (defined in %s as %s)\n", p, kind)
			break
		}
	}
	fmt.Println()

	found := false

	// Aliases whose body contains @name or @name.field
	var aliasRefs []string
	for aName, alias := range fleet.Aliases {
		for _, addr := range alias.Addresses {
			if refMatchesName(addr, name) {
				aliasRefs = append(aliasRefs, aName)
				break
			}
		}
	}
	if len(aliasRefs) > 0 {
		found = true
		sort.Strings(aliasRefs)
		fmt.Println("Aliases:")
		for _, r := range aliasRefs {
			fmt.Printf("  @%s\n", r)
		}
		fmt.Println()
	}

	// Address sets that include @name
	var setRefs []string
	for sName, s := range fleet.AddressSets {
		for _, addr := range s.RawAddresses() {
			if refMatchesName(addr, name) {
				setRefs = append(setRefs, sName)
				break
			}
		}
	}
	if len(setRefs) > 0 {
		found = true
		sort.Strings(setRefs)
		fmt.Println("Address sets:")
		for _, r := range setRefs {
			fmt.Printf("  %s\n", r)
		}
		fmt.Println()
	}

	// ACLs whose rules include @name, $name in source/destination
	var aclRefs []string
	for aName, a := range fleet.ACLs {
		hit := false
		for _, r := range append(append([]any{}, ruleFieldsFor(a.Ingress)...), ruleFieldsFor(a.Egress)...) {
			fields := r.([2]string)
			if refInField(fields[0], name) || refInField(fields[1], name) {
				hit = true
				break
			}
		}
		if hit {
			aclRefs = append(aclRefs, aName)
		}
	}
	if len(aclRefs) > 0 {
		found = true
		sort.Strings(aclRefs)
		fmt.Println("ACLs:")
		for _, r := range aclRefs {
			fmt.Printf("  %s\n", r)
		}
		fmt.Println()
	}

	// Instances whose device.security.acls (or attached list) contain this ACL name
	var instRefs []string
	for iName, inst := range fleet.Instances {
		for _, dev := range inst.EffectiveDevices() {
			if dev == nil {
				continue
			}
			for _, n := range dev.SecurityACLs {
				if n == name {
					instRefs = append(instRefs, iName)
					break
				}
			}
		}
	}
	if len(instRefs) > 0 {
		found = true
		sort.Strings(instRefs)
		fmt.Println("Instances (device.security.acls):")
		for _, r := range instRefs {
			fmt.Printf("  %s\n", r)
		}
		fmt.Println()
	}

	// Policies that attach this ACL
	var polRefs []string
	for pName, p := range fleet.Policies {
		for _, n := range p.Attach.SecurityACLs {
			if n == name {
				polRefs = append(polRefs, pName)
				break
			}
		}
	}
	if len(polRefs) > 0 {
		found = true
		sort.Strings(polRefs)
		fmt.Println("Policies (attach.security.acls):")
		for _, r := range polRefs {
			fmt.Printf("  %s\n", r)
		}
		fmt.Println()
	}

	if !found {
		fmt.Println("(no references found)")
	}
	return nil
}

// refMatchesName reports whether tok is "@name" or "@name.<something>".
func refMatchesName(tok, name string) bool {
	tok = strings.TrimSpace(tok)
	if !strings.HasPrefix(tok, "@") {
		return false
	}
	body := tok[1:]
	if body == name {
		return true
	}
	if strings.HasPrefix(body, name+".") {
		return true
	}
	return false
}

// refInField checks whether name appears as an @-ref or $-ref in a
// comma-separated field. Applies to both alias/instance and address-set names.
func refInField(field, name string) bool {
	for _, tok := range strings.Split(field, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "$"+name {
			return true
		}
		if refMatchesName(tok, name) {
			return true
		}
	}
	return false
}

// ruleFieldsFor extracts (source, destination) pairs for each rule.
func ruleFieldsFor(rules []api.NetworkACLRule) []any {
	out := make([]any, len(rules))
	for i, r := range rules {
		out[i] = [2]string{r.Source, r.Destination}
	}
	return out
}
