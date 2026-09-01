package model

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lxc/incus/v7/shared/api"
)

// Instance describes the network policy for one container. It lives at
// hosts/<host>/instances/<name>/instance.yaml. One directory per
// container is the primary scaling unit.
//
// Two forms describe eth0's Incus device policy:
//
//	Flat (common case, ~99%):
//	  acls, ingress-default, egress-default
//
//	Explicit (multi-NIC or non-eth0 overrides):
//	  devices: { eth0: { ... }, eth1: { ... } }
//
// IP addresses (ip4, ip6) live at instance top-level as metadata — they
// are the source of truth for ACL cross-refs like @webapp.ip6, and are
// baked into network config INSIDE the container by the interface
// provision template. They are NOT reconciled to Incus's device keys;
// bridged networks without DHCP reject `ipv6.address` on the device.
//
// The two device forms are mutually exclusive.
//
// Inline definitions of ACLs owned by this instance live under `defines:`
// and MUST use the `<instance>-` prefix.
type Instance struct {
	Name        string `yaml:"instance"`
	Description string `yaml:"description,omitempty"`
	// Project is the Incus project this instance belongs to. Optional
	// in YAML; the loader defaults to the fleet's default_project when
	// omitted. Different projects on the same host give logical
	// separation with the operator's own cert scoped to all of them.
	Project string `yaml:"project,omitempty"`
	// OriginalImage is the launch-time image (e.g. "images:alpine/3.24").
	// Container filesystems drift from the image immediately after apk
	// upgrade / apt install / etc., so this field is deliberately named
	// to signal "what we launched from, once", not "what the container
	// currently is". Only consulted on create; edits after launch have no effect.
	OriginalImage string   `yaml:"original_image,omitempty"`
	Profiles      []string `yaml:"profiles,omitempty"`
	Tags          []string `yaml:"tags,omitempty"`
	Start         *bool    `yaml:"start,omitempty"`

	// Flat eth0 form.
	IP4 string `yaml:"ip4,omitempty"`
	IP6 string `yaml:"ip6,omitempty"`
	// IP6PrefixLength defaults to 80 at render time (a common convention
	// are /80). Override only for non-standard networks.
	IP6PrefixLength int `yaml:"ip6_prefix_length,omitempty"`
	// IP6Gateway defaults to <network>::1 at render time (derived from
	// ip6 + prefix). Override only when the gateway is not ::1.
	IP6Gateway   string   `yaml:"ip6_gateway,omitempty"`
	AttachedACLs []string `yaml:"acls,omitempty"`
	// ExcludedACLs subtracts from the effective set — used to opt out
	// of a tag-attached policy ACL for one specific instance without
	// dropping the tag entirely.
	ExcludedACLs   []string `yaml:"acls-exclude,omitempty"`
	IngressDefault string   `yaml:"ingress-default,omitempty"`
	EgressDefault  string   `yaml:"egress-default,omitempty"`

	// Explicit form. Mutually exclusive with flat.
	Devices map[string]*InstanceDevice `yaml:"devices,omitempty"`

	// Owned inline definitions.
	Defines *InstanceDefines `yaml:"defines,omitempty"`

	// Provision runs ONCE at container create time. Never re-run by
	// sync — if you change it and want to re-apply, delete the container
	// and let sync recreate.
	Provision *ProvisionSpec `yaml:"provision,omitempty"`

	// SourceDir is the on-disk directory holding this instance —
	// hosts/<host>/instances/<name>/. Populated by the loader (not read
	// from YAML). Instance-specific provisioning content lives under it:
	//   files/    — tar-pushed into the container after named templates
	//   after.sh  — runs after files/ is deployed
	// Same shape as templates/<name>/, scoped to one container instead
	// of being reusable.
	SourceDir string `yaml:"-"`
}

// ProvisionSpec describes container-side bootstrap. Kept small: interface
// template picker + list of reusable named templates. Instance-specific
// files and post-hook live in the instance's own directory (files/ and
// after.sh), not in this struct — a role's config is a tree of real
// files with syntax highlighting, not YAML string blobs.
type ProvisionSpec struct {
	// Interface selects a built-in network template that generates the
	// distro's networking file from the instance's ip4/ip6 fields.
	// Values: "alpine", "debian-networkd", "debian-interfaces".
	Interface string `yaml:"interface,omitempty"`

	// Templates names bastille-style bundles from <fleet-repo>/templates/.
	// Applied in list order. Each pushes its files/ tree then runs its
	// after.sh. Reusable across many containers — write once, apply many.
	Templates []string `yaml:"templates,omitempty"`
}

// InstanceDefines wraps inline objects owned by this instance. Names
// MUST start with "<instance>-" (enforced by the loader).
type InstanceDefines struct {
	ACLs        []ACL        `yaml:"acls,omitempty"`
	AddressSets []AddressSet `yaml:"address_sets,omitempty"`
}

// InstanceDevice is the subset of a device's config this tool manages.
// Only listed keys are reconciled; every other key on the device is left
// alone. New managed keys must be added here explicitly — never accept an
// untyped escape hatch.
//
// IP addresses (ipv4.address, ipv6.address) are deliberately absent —
// Incus rejects them on bridged networks without DHCP, and forcing DHCP
// just to satisfy Incus's device validator makes little sense when
// static IPs belong inside the container's /etc/network/interfaces.
// Typical flow: fleet YAML declares ip4/ip6 at instance level, the
// interface provision template writes them inside the container.
type InstanceDevice struct {
	SecurityACLs   []string `yaml:"security.acls,omitempty"`
	IngressDefault string   `yaml:"security.acls.default.ingress.action,omitempty"`
	EgressDefault  string   `yaml:"security.acls.default.egress.action,omitempty"`
}

// ToDeviceMap flattens managed fields into Incus's device key/value map.
// security.acls is canonically sorted so lexical reorder does not cause
// sync churn.
func (d *InstanceDevice) ToDeviceMap() map[string]string {
	m := map[string]string{}
	if d == nil {
		return m
	}
	if len(d.SecurityACLs) > 0 {
		sorted := append([]string(nil), d.SecurityACLs...)
		sort.Strings(sorted)
		m["security.acls"] = strings.Join(sorted, ",")
	}
	if d.IngressDefault != "" {
		m["security.acls.default.ingress.action"] = d.IngressDefault
	}
	if d.EgressDefault != "" {
		m["security.acls.default.egress.action"] = d.EgressDefault
	}
	return m
}

// ManagedDeviceKeys returns the set of Incus device keys this tool
// writes. Used by sync to distinguish "our" keys from profile-provided
// ones we must not overwrite.
func ManagedDeviceKeys() []string {
	return []string{
		"security.acls",
		"security.acls.default.ingress.action",
		"security.acls.default.egress.action",
	}
}

// InstanceDeviceFromMap reads managed keys from a live device map.
// Unmanaged keys are dropped. Returns nil when nothing managed present.
func InstanceDeviceFromMap(m map[string]string) *InstanceDevice {
	if len(m) == 0 {
		return nil
	}
	d := &InstanceDevice{
		IngressDefault: m["security.acls.default.ingress.action"],
		EgressDefault:  m["security.acls.default.egress.action"],
	}
	if v := m["security.acls"]; v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				d.SecurityACLs = append(d.SecurityACLs, s)
			}
		}
		sort.Strings(d.SecurityACLs)
	}
	empty := d.IngressDefault == "" && d.EgressDefault == "" &&
		len(d.SecurityACLs) == 0
	if empty {
		return nil
	}
	return d
}

// EffectiveDevices returns the device map to reconcile.
// If the explicit `devices:` block is present, that wins.
// Otherwise, flat eth0 fields are folded into an implicit eth0 map.
// Returns nil when the instance declares no policy state at all
// (identity-only files, valid).
//
// IP4/IP6 are NOT included — they are provisioned inside the container
// by the interface template, not written to Incus's device keys.
func (i *Instance) EffectiveDevices() map[string]*InstanceDevice {
	if len(i.Devices) > 0 {
		return i.Devices
	}
	flatEmpty := len(i.AttachedACLs) == 0 &&
		i.IngressDefault == "" && i.EgressDefault == ""
	if flatEmpty {
		return nil
	}
	return map[string]*InstanceDevice{
		"eth0": {
			SecurityACLs:   i.AttachedACLs,
			IngressDefault: i.IngressDefault,
			EgressDefault:  i.EgressDefault,
		},
	}
}

// InstanceFromAPI extracts managed device state from a live Incus instance.
// Reads ExpandedDevices (post-profile-inheritance) so eth0 provided by
// the managed profile is visible. Emits the flat form when only eth0 is
// managed — matches how humans write these files.
func InstanceFromAPI(inst api.Instance) Instance {
	out := Instance{
		Name:        inst.Name,
		Description: inst.Description,
	}

	// Union of profile-provided and local devices, local override wins.
	all := map[string]map[string]string{}
	for k, v := range inst.ExpandedDevices {
		all[k] = v
	}
	for k, v := range inst.Devices {
		all[k] = v
	}

	// Preserve any IPs currently on eth0 so adopt round-trips them into
	// the instance-level ip4/ip6 fields. Sync will not push them back —
	// they are metadata only now — but losing them on adopt would be
	// destructive.
	if eth0, ok := all["eth0"]; ok {
		out.IP4 = eth0["ipv4.address"]
		out.IP6 = eth0["ipv6.address"]
	}
	if len(all) == 1 {
		if eth0, ok := all["eth0"]; ok {
			if d := InstanceDeviceFromMap(eth0); d != nil {
				out.AttachedACLs = d.SecurityACLs
				out.IngressDefault = d.IngressDefault
				out.EgressDefault = d.EgressDefault
			}
			return out
		}
	}
	// Multi-device: explicit form.
	out.Devices = map[string]*InstanceDevice{}
	for name, m := range all {
		if d := InstanceDeviceFromMap(m); d != nil {
			out.Devices[name] = d
		}
	}
	if len(out.Devices) == 0 {
		out.Devices = nil
	}
	return out
}

// Validate enforces cross-field rules.
func (i *Instance) Validate() error {
	if i.Name == "" {
		return fmt.Errorf("instance file missing 'instance' name")
	}

	flatSet := len(i.AttachedACLs) > 0 ||
		i.IngressDefault != "" || i.EgressDefault != ""
	if flatSet && len(i.Devices) > 0 {
		return fmt.Errorf("instance %q: flat form (acls/ingress-default/egress-default) is mutually exclusive with explicit devices: block",
			i.Name)
	}

	prefix := i.Name + "-"

	if i.Defines != nil {
		for _, a := range i.Defines.ACLs {
			if !strings.HasPrefix(a.Name, prefix) {
				return fmt.Errorf("instance %q defines acl %q which does not start with %q",
					i.Name, a.Name, prefix)
			}
		}
		for _, s := range i.Defines.AddressSets {
			if !strings.HasPrefix(s.Name, prefix) {
				return fmt.Errorf("instance %q defines address_set %q which does not start with %q",
					i.Name, s.Name, prefix)
			}
		}
	}

	for devName, dev := range i.EffectiveDevices() {
		if dev == nil {
			continue
		}
		for _, name := range dev.SecurityACLs {
			if strings.ContainsAny(name, ", ") {
				return fmt.Errorf("instance %q device %q: security.acls entry %q contains illegal char",
					i.Name, devName, name)
			}
		}
	}
	return nil
}
