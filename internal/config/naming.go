package config

import (
	"fmt"
	"regexp"
	"strings"
)

// Naming conventions are opinionated and strictly enforced by the loader.
// A misnamed file fails validate and therefore fails any pre-commit hook
// or CI check that runs validate. Renames are the only fix.
//
// Base rule (nameRe): lowercase letters/digits/hyphens; start with letter;
// no leading/trailing/consecutive hyphens; 1..60 chars. This matches what
// Incus accepts and what humans grep for.
//
// Scope rules:
//
//   shared/aliases/<name>.yaml         — name matches base rule
//   shared/address-sets/<name>.yaml    — name matches base rule
//   shared/acls/<name>.yaml            — "default-policy" OR "generic-<...>"
//   shared/policies/<name>.yaml        — name matches base rule
//   hosts/<h>/aliases/<name>.yaml      — name starts with "<h>-"
//   hosts/<h>/address-sets/<name>.yaml — name starts with "<h>-"
//   hosts/<h>/acls/<name>.yaml         — name starts with "<h>-"
//   hosts/<h>/instances/<i>/instance.yaml — directory name == name; inline ACLs and
//                                        address sets start with "<i>-"
//
// The "generic-" prefix rule on shared ACLs is the key insight: ACLs get
// referenced from many instance files, so their origin should be obvious
// at reference sites. Address sets and aliases are consumed via $/@
// references where a prefix would be pure noise, so they stay freeform.
// Promoting an instance ACL to shared requires renaming to "generic-*",
// which forces the operator to consider whether it is truly generic.

var (
	nameRe = regexp.MustCompile(`^[a-z]([a-z0-9]+(-[a-z0-9]+)*)?$`)

	reservedSharedACLs = map[string]bool{
		"default-policy": true,
	}
)

// checkBaseName enforces the common character rules used by every kind.
func checkBaseName(kind, name string) error {
	if name == "" {
		return fmt.Errorf("%s name is empty", kind)
	}
	if len(name) > 60 {
		return fmt.Errorf("%s name %q longer than 60 chars", kind, name)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf(
			"%s name %q must match [a-z][a-z0-9-]*, start with letter, no consecutive/trailing hyphens",
			kind, name)
	}
	return nil
}

// checkSharedACLName enforces the generic-prefix rule.
func checkSharedACLName(name string) error {
	if err := checkBaseName("acl", name); err != nil {
		return err
	}
	if reservedSharedACLs[name] {
		return nil
	}
	if !strings.HasPrefix(name, "generic-") {
		return fmt.Errorf(
			`shared acl %q must be "default-policy" or start with "generic-" (rename if truly generic; else move to hosts/<h>/acls/ or an instance file)`,
			name)
	}
	return nil
}

// checkHostScopedName enforces the "<host>-" prefix on host-scoped
// aliases, address sets, and ACLs.
func checkHostScopedName(kind, host, name string) error {
	if err := checkBaseName(kind, name); err != nil {
		return err
	}
	prefix := host + "-"
	if !strings.HasPrefix(name, prefix) {
		return fmt.Errorf("%s %q under hosts/%s/ must start with %q", kind, name, host, prefix)
	}
	return nil
}

// checkInstanceScopedName enforces the "<instance>-" prefix for inline
// ACLs and address sets declared inside an instance file.
func checkInstanceScopedName(kind, instance, name string) error {
	if err := checkBaseName(kind, name); err != nil {
		return err
	}
	prefix := instance + "-"
	if !strings.HasPrefix(name, prefix) {
		return fmt.Errorf("instance %q %s %q must start with %q", instance, kind, name, prefix)
	}
	return nil
}

// checkTagName enforces the base rule on a tag string.
func checkTagName(tag string) error {
	return checkBaseName("tag", tag)
}
