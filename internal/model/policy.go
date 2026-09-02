package model

import (
	"fmt"
	"strings"
)

// Policy attaches ACLs (and later maybe other device keys) to instances
// that match a tag selector. Inspired by Hetzner firewall tags: label a
// container "web" and every web-tier ACL flows in.
//
// Selector semantics are AND: an instance matches only if it has every
// tag listed. Empty selector matches every instance (rarely useful; a
// fleet-wide default belongs in shared/acls/default-policy.yaml instead).
type Policy struct {
	Name        string         `yaml:"policy"`
	Description string         `yaml:"description,omitempty"`
	Selector    PolicySelector `yaml:"selector"`
	Attach      PolicyAttach   `yaml:"attach"`
}

type PolicySelector struct {
	Tags []string `yaml:"tags,omitempty"`
}

type PolicyAttach struct {
	SecurityACLs []string `yaml:"security.acls,omitempty"`
}

// Matches reports whether the instance's tag set satisfies the selector.
func (p Policy) Matches(instanceTags []string) bool {
	if len(p.Selector.Tags) == 0 {
		return true
	}
	have := map[string]struct{}{}
	for _, t := range instanceTags {
		have[t] = struct{}{}
	}
	for _, need := range p.Selector.Tags {
		if _, ok := have[need]; !ok {
			return false
		}
	}
	return true
}

// Validate runs basic structural checks. Full cross-ref (does every
// attached ACL exist?) happens in the loader.
func (p *Policy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("policy file missing 'policy' name")
	}
	if len(p.Attach.SecurityACLs) == 0 {
		return fmt.Errorf("policy %q attaches nothing (add security.acls entries)", p.Name)
	}
	for _, name := range p.Attach.SecurityACLs {
		if strings.ContainsAny(name, ", ") {
			return fmt.Errorf("policy %q: security.acls entry %q contains illegal char", p.Name, name)
		}
	}
	return nil
}
