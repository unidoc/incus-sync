package config

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/model"
)

// Semantic validation — checks that the YAML, after alias resolution,
// would produce objects Incus is prepared to accept. This catches
// mistakes before commit rather than at sync time.
//
// Enums here mirror Incus's own accepted values (see upstream network
// ACL docs). Where Incus's own validator exists inside the daemon's
// internal package (not exported), we duplicate the check offline. Drift
// is unlikely in practice — these enums have been stable for years.

var (
	validACLActions   = map[string]bool{"allow": true, "reject": true, "drop": true}
	validACLProtocols = map[string]bool{"": true, "tcp": true, "udp": true, "icmp4": true, "icmp6": true}
	validACLStates    = map[string]bool{"": true, "enabled": true, "disabled": true, "logged": true}
	validDefActions   = map[string]bool{"": true, "allow": true, "reject": true, "drop": true}

	// Port list: N or N-N; comma-separated.
	portListRe = regexp.MustCompile(`^(\d{1,5}(-\d{1,5})?)(,\d{1,5}(-\d{1,5})?)*$`)
)

// ValidateSemantic checks resolved-content correctness. Assumes Load has
// already returned successfully (structural checks + cross-refs).
func (f *Fleet) ValidateSemantic() error {
	if err := f.validateAliases(); err != nil {
		return err
	}
	if err := f.validateAddressSets(); err != nil {
		return err
	}
	if err := f.validateACLs(); err != nil {
		return err
	}
	if err := f.validateInstances(); err != nil {
		return err
	}
	if err := f.validateTemplateSecrets(); err != nil {
		return err
	}
	f.detectRiskyPatterns()
	return nil
}

// validateTemplateSecrets cross-checks every template's declared
// `secrets: - from: <path>` against the KEY STRUCTURE of
// shared/secrets.sops.yaml. Runs without decrypting anything — the
// vault stays locked, `validate` remains a cheap read-only check.
//
// Only templates USED by a live instance are checked. An unused
// template with a missing secret reference is not a sync-blocker.
func (f *Fleet) validateTemplateSecrets() error {
	// Collect the templates actually referenced by an instance.
	used := map[string]bool{}
	for _, inst := range f.Instances {
		if inst.Provision == nil {
			continue
		}
		for _, name := range inst.Provision.Templates {
			used[name] = true
		}
	}
	if len(used) == 0 {
		return nil
	}
	// Build the "which secret paths are declared" list from used
	// templates.
	type ref struct {
		template string
		env      string
		from     string
	}
	var refs []ref
	for name, t := range f.Templates {
		if !used[name] {
			continue
		}
		for _, s := range t.Secrets {
			if s.From == "" || s.Env == "" {
				return fmt.Errorf("template %q: secret entry missing env or from", name)
			}
			refs = append(refs, ref{template: name, env: s.Env, from: s.From})
		}
	}
	if len(refs) == 0 {
		return nil
	}
	// Load the encrypted secrets file's KEY structure (no decrypt).
	structure, err := LoadSecretsStructure(f.configDir)
	if err != nil {
		return err
	}
	for _, r := range refs {
		if !SecretPathExists(structure, r.from) {
			return fmt.Errorf(
				"template %q declares secret env %s from path %q "+
					"but that path is not present in shared/secrets.sops.yaml. "+
					"Add it with: sops shared/secrets.sops.yaml",
				r.template, r.env, r.from)
		}
	}
	return nil
}

// detectRiskyPatterns emits warnings for policy-relevant configurations
// that pass structural validation but are dangerous:
//   - ingress-default: allow (opens the container)
//   - allow rule with empty source (world-open)
//   - instance with tags but zero effective ACLs (silently unprotected)
//   - instance with no ACLs attached at all
//
// Warnings are added to f.Warnings; the caller decides whether to fail.
// `validate` prints them; `sync --apply` surfaces them in the confirmation.
func (f *Fleet) detectRiskyPatterns() {
	for name, inst := range f.Instances {
		for devName, dev := range inst.EffectiveDevices() {
			if dev == nil {
				continue
			}
			if dev.IngressDefault == "allow" {
				if !hasAck(inst.Description, "ingress-default-allow") {
					f.Warnings = append(f.Warnings, fmt.Sprintf(
						"RISK: instance %q device %q has ingress-default: allow (world-open) — "+
							"add (ack ingress-default-allow) to the instance description if intentional",
						name, devName))
				}
			}
			effective, _ := f.EffectiveACLs(inst, devName)
			if len(inst.Tags) > 0 && len(effective) == 0 {
				f.Warnings = append(f.Warnings, fmt.Sprintf(
					"RISK: instance %q has tags %v but no ACL matched — no policy attaches to any of these tags",
					name, inst.Tags))
			}
		}
	}
	for name, acl := range f.ACLs {
		for i, r := range acl.Ingress {
			// ICMP is convention-allowed everywhere (RFC 4890 baseline).
			// Skip the world-open warning for icmp4/icmp6 to keep the
			// signal-to-noise ratio useful.
			if r.Protocol == "icmp4" || r.Protocol == "icmp6" {
				continue
			}
			if r.Action == "allow" && r.Source == "" && r.Destination == "" {
				// Silence when the operator has explicitly acknowledged
				// the world-open exposure — on the rule OR on the parent
				// ACL, so generic-web-in etc. can carry the ack once at
				// the ACL level and cover every rule underneath.
				if hasAck(r.Description, "world-open") || hasAck(acl.Description, "world-open") {
					continue
				}
				f.Warnings = append(f.Warnings, fmt.Sprintf(
					"RISK: acl %q ingress[%d] is allow with empty source (world-open on %s/%s) — "+
						"add (ack world-open) to the rule or ACL description if intentional",
					name, i, r.Protocol, r.DestinationPort))
			}
		}
	}
}

func (f *Fleet) validateAliases() error {
	for name, a := range f.Aliases {
		where := f.OriginOf("alias", name)
		if len(a.Addresses) == 0 {
			return fmt.Errorf("%s: alias %q has no addresses", where, name)
		}
		resolved, err := f.ResolveAddresses(a.Addresses)
		if err != nil {
			return fmt.Errorf("%s: alias %q: %w", where, name, err)
		}
		for _, addr := range resolved {
			if err := checkAddress(addr); err != nil {
				return fmt.Errorf("%s: alias %q: %w", where, name, err)
			}
		}
	}
	return nil
}

func (f *Fleet) validateAddressSets() error {
	for name, set := range f.AddressSets {
		where := f.OriginOf("address-set", name)
		if len(set.Addresses) == 0 {
			return fmt.Errorf("%s: address_set %q has no addresses", where, name)
		}
		resolved, err := f.ResolveAddresses(set.RawAddresses())
		if err != nil {
			return fmt.Errorf("%s: address_set %q: %w", where, name, err)
		}
		for _, addr := range resolved {
			if err := checkAddress(addr); err != nil {
				return fmt.Errorf("%s: address_set %q: %w", where, name, err)
			}
		}
	}
	return nil
}

func (f *Fleet) validateACLs() error {
	for name, acl := range f.ACLs {
		for i, r := range acl.Ingress {
			if err := f.validateACLRule(r); err != nil {
				return fmt.Errorf("acl %q ingress[%d]: %w", name, i, err)
			}
		}
		for i, r := range acl.Egress {
			if err := f.validateACLRule(r); err != nil {
				return fmt.Errorf("acl %q egress[%d]: %w", name, i, err)
			}
		}
	}
	return nil
}

func (f *Fleet) validateACLRule(r api.NetworkACLRule) error {
	if !validACLActions[r.Action] {
		return fmt.Errorf("action %q invalid (want allow, reject, drop)", r.Action)
	}
	if !validACLProtocols[r.Protocol] {
		return fmt.Errorf("protocol %q invalid (want tcp, udp, icmp4, icmp6, or empty)", r.Protocol)
	}
	if !validACLStates[r.State] {
		return fmt.Errorf("state %q invalid (want enabled, disabled, logged, or empty)", r.State)
	}
	if r.SourcePort != "" {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("source_port set but protocol is %q (need tcp or udp)", r.Protocol)
		}
		if !portListRe.MatchString(r.SourcePort) {
			return fmt.Errorf("source_port %q malformed (want \"N\" or \"N-N\", comma-separated)", r.SourcePort)
		}
	}
	if r.DestinationPort != "" {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("destination_port set but protocol is %q (need tcp or udp)", r.Protocol)
		}
		if !portListRe.MatchString(r.DestinationPort) {
			return fmt.Errorf("destination_port %q malformed", r.DestinationPort)
		}
	}
	if (r.ICMPType != "" || r.ICMPCode != "") && r.Protocol != "icmp4" && r.Protocol != "icmp6" {
		return fmt.Errorf("icmp_type/icmp_code set but protocol is %q (need icmp4 or icmp6)", r.Protocol)
	}
	if err := f.checkResolvedField(r.Source, "source"); err != nil {
		return err
	}
	if err := f.checkResolvedField(r.Destination, "destination"); err != nil {
		return err
	}
	return nil
}

// checkResolvedField resolves @refs in the field and verifies every
// literal token is either a valid address or a valid $address-set ref
// or an Incus built-in subject (@internal, @external — leading @ but no
// alias by that name).
func (f *Fleet) checkResolvedField(field, label string) error {
	if field == "" {
		return nil
	}
	resolved, err := f.ResolveField(field)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	for _, tok := range strings.Split(resolved, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(tok, "$") {
			// $address-set reference (Incus resolves at eval)
			continue
		}
		if strings.HasPrefix(tok, "@") {
			// Incus subject keyword like @internal / @external — assume
			// operator knows what they're doing. Custom @aliases were
			// already resolved above, so any @foo remaining is upstream.
			continue
		}
		if err := checkAddress(tok); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	return nil
}

func (f *Fleet) validateInstances() error {
	for name, inst := range f.Instances {
		if inst.IP4 != "" {
			if _, err := netip.ParseAddr(inst.IP4); err != nil {
				return fmt.Errorf("instance %q: invalid ip4 %q", name, inst.IP4)
			}
			// Static IPv4 needs a prefix length and gateway to actually
			// work once rendered into the container's network config —
			// unlike ip6, there's no safe default to guess (subnet size
			// varies per deployment). Require both explicitly rather
			// than emit a static address with no netmask.
			if inst.IP4PrefixLength == 0 {
				return fmt.Errorf("instance %q: ip4 set but ip4_prefix_length is missing (required — no safe default for IPv4)", name)
			}
			if inst.IP4PrefixLength < 0 || inst.IP4PrefixLength > 32 {
				return fmt.Errorf("instance %q: ip4_prefix_length %d out of range (0-32)", name, inst.IP4PrefixLength)
			}
			if inst.IP4Gateway == "" {
				return fmt.Errorf("instance %q: ip4 set but ip4_gateway is missing (required — no safe default for IPv4)", name)
			}
			if _, err := netip.ParseAddr(inst.IP4Gateway); err != nil {
				return fmt.Errorf("instance %q: invalid ip4_gateway %q", name, inst.IP4Gateway)
			}
		}
		if inst.IP6 != "" {
			if _, err := netip.ParseAddr(inst.IP6); err != nil {
				return fmt.Errorf("instance %q: invalid ip6 %q", name, inst.IP6)
			}
		}
		for devName, dev := range inst.EffectiveDevices() {
			if dev == nil {
				continue
			}
			if !validDefActions[dev.IngressDefault] {
				return fmt.Errorf("instance %q device %q: invalid ingress default action %q", name, devName, dev.IngressDefault)
			}
			if !validDefActions[dev.EgressDefault] {
				return fmt.Errorf("instance %q device %q: invalid egress default action %q", name, devName, dev.EgressDefault)
			}
		}
	}
	return nil
}

// checkAddress accepts an IPv4/IPv6 address or a CIDR prefix, matching
// what Incus accepts in address-set members and ACL source/destination.
func checkAddress(s string) error {
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	return fmt.Errorf("%q is not a valid IP or CIDR", s)
}

// Ensure the model import stays live once we lean on it more heavily
// (e.g. tags, additional resolvers).
var _ = model.AliasRef
