package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/unidoc/incus-sync/internal/model"
)

// ACLSource records why a particular ACL is attached to an instance —
// or, in the Excluded case, why it is not. `explain` uses these to
// trace ownership.
type ACLSource struct {
	Name       string
	FromDevice bool     // instance file device.security.acls
	FromPolicy []string // policy names whose selector matched
	Excluded   bool     // instance's acls-exclude removed this ACL
}

// EffectiveACLs computes the sorted, deduplicated list of ACLs that
// should end up on inst's given device after merging its own
// device.security.acls with every matching policy's attach.security.acls.
//
// Policies attach ONLY to eth0. Attaching a web-tier policy's ACLs to
// a Wireguard or storage NIC would silently open or reconfigure the
// operator's private interfaces — the exact "left alone" guarantee
// the tool advertises for unmanaged device keys. Explicit multi-NIC
// devices (eth1+) get only what the instance file lists.
//
// The returned map keyed by ACL name records origin so callers can
// produce human explanations.
func (f *Fleet) EffectiveACLs(inst model.Instance, deviceName string) ([]string, map[string]ACLSource) {
	sources := map[string]ACLSource{}

	if dev, ok := inst.EffectiveDevices()[deviceName]; ok && dev != nil {
		for _, name := range dev.SecurityACLs {
			s := sources[name]
			s.Name = name
			s.FromDevice = true
			sources[name] = s
		}
	}

	// Only apply tag policies to eth0. See package doc above.
	if deviceName == "eth0" {
		polNames := make([]string, 0, len(f.Policies))
		for n := range f.Policies {
			polNames = append(polNames, n)
		}
		sort.Strings(polNames)
		for _, n := range polNames {
			p := f.Policies[n]
			if !p.Matches(inst.Tags) {
				continue
			}
			for _, aclName := range p.Attach.SecurityACLs {
				s := sources[aclName]
				s.Name = aclName
				s.FromPolicy = append(s.FromPolicy, p.Name)
				sources[aclName] = s
			}
		}
	}

	// Apply instance-level exclusions. Only affects eth0 (where policy
	// attachments happen). Excluded ACLs are removed from the effective
	// list but preserved in the sources map so `explain` can show them.
	if deviceName == "eth0" {
		for _, excluded := range inst.ExcludedACLs {
			if s, ok := sources[excluded]; ok {
				s.Excluded = true
				sources[excluded] = s
			}
		}
	}

	names := make([]string, 0, len(sources))
	for n, s := range sources {
		if s.Excluded {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, sources
}

// ResolveAddresses expands @alias and @instance.field references in the
// given list to their literal contents. Non-@ tokens (literal IPs,
// CIDRs, $address-set references) pass through unchanged. Aliases are
// recursive; cycles are hard errors with the full path in the message.
//
// Dispatch on presence of `.` in the name:
//
//	@lupin         -> alias lupin (recursive expansion)
//	@webapp.ip6    -> instance webapp's ip6 field (single literal)
//
// Alias names cannot contain `.` (base name rule), so this is unambiguous.
// Alias / instance name overlap is caught in Load post-check.
func (f *Fleet) ResolveAddresses(input []string) ([]string, error) {
	var out []string
	for _, tok := range input {
		if name, ok := model.AliasRef(tok); ok {
			expanded, err := f.resolveAtRef(name, nil)
			if err != nil {
				return nil, err
			}
			out = append(out, expanded...)
		} else {
			out = append(out, strings.TrimSpace(tok))
		}
	}
	return out, nil
}

// resolveAtRef dispatches between alias expansion and instance field lookup.
// Incus's built-in subject keywords (@internal, @external) pass through
// unchanged — Incus itself resolves them at rule eval time.
func (f *Fleet) resolveAtRef(name string, stack []string) ([]string, error) {
	if reservedIncusSubjects[name] {
		return []string{"@" + name}, nil
	}
	if dot := strings.IndexByte(name, '.'); dot > 0 {
		return f.resolveInstanceField(name[:dot], name[dot+1:])
	}
	return f.expandAlias(name, stack)
}

// resolveInstanceField returns the requested field of an instance as a
// single-element list. Supported fields: ip4, ip6.
//
// Reads instance-level ip4/ip6 (source of truth in the fleet YAML — the
// tool never syncs these to Incus's device keys).
func (f *Fleet) resolveInstanceField(instanceName, field string) ([]string, error) {
	inst, ok := f.Instances[instanceName]
	if !ok {
		return nil, fmt.Errorf("unknown instance @%s.%s", instanceName, field)
	}
	switch field {
	case "ip4":
		if inst.IP4 == "" {
			return nil, fmt.Errorf("instance %q has no ip4 declared", instanceName)
		}
		return []string{inst.IP4}, nil
	case "ip6":
		if inst.IP6 == "" {
			return nil, fmt.Errorf("instance %q has no ip6 declared", instanceName)
		}
		return []string{inst.IP6}, nil
	default:
		return nil, fmt.Errorf("unknown instance field @%s.%s (only ip4, ip6 supported)",
			instanceName, field)
	}
}

// ResolveField expands @refs in a comma-separated ACL field (source or
// destination). Returns a comma-joined string suitable for Incus. $refs
// are preserved verbatim.
func (f *Fleet) ResolveField(input string) (string, error) {
	if input == "" {
		return "", nil
	}
	var out []string
	for _, tok := range strings.Split(input, ",") {
		tok = strings.TrimSpace(tok)
		if name, ok := model.AliasRef(tok); ok {
			expanded, err := f.resolveAtRef(name, nil)
			if err != nil {
				return "", err
			}
			out = append(out, expanded...)
		} else {
			out = append(out, tok)
		}
	}
	return strings.Join(out, ","), nil
}

// expandAlias returns the flat list of literal addresses reachable from
// name, following @refs recursively. stack is the recursion path used to
// build helpful cycle messages.
func (f *Fleet) expandAlias(name string, stack []string) ([]string, error) {
	for _, s := range stack {
		if s == name {
			path := append(append([]string(nil), stack...), name)
			return nil, fmt.Errorf("alias cycle: %s", strings.Join(path, " -> "))
		}
	}
	a, ok := f.Aliases[name]
	if !ok {
		return nil, fmt.Errorf("unknown alias @%s", name)
	}
	nextStack := append(stack, name)
	var out []string
	for _, addr := range a.Addresses {
		if inner, ok := model.AliasRef(addr); ok {
			expanded, err := f.resolveAtRef(inner, nextStack)
			if err != nil {
				return nil, err
			}
			out = append(out, expanded...)
		} else {
			out = append(out, strings.TrimSpace(addr))
		}
	}
	return out, nil
}
