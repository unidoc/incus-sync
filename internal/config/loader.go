// Package config loads and merges YAML config from a fleet
// repository. File-per-object layout, one directory per instance —
// no legacy fallbacks, no silent defaults, no deprecated shapes.
//
// The loader is opinionated about naming (see naming.go) and about
// explicitness: every instance MUST declare `project:`, and every
// project must appear in the fleet-level `projects:` list.
//
// Merge order:
//
//  1. shared/aliases/*.yaml
//  2. hosts/<host>/aliases/*.yaml
//  3. shared/address-sets/*.yaml
//  4. shared/acls/*.yaml
//  5. shared/policies/*.yaml
//  6. hosts/<host>/address-sets/*.yaml
//  7. hosts/<host>/acls/*.yaml
//  8. hosts/<host>/instances/<name>/instance.yaml
//  9. templates/<name>/manifest.yaml
//
// After load, cross-references are validated.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/unidoc/incus-sync/internal/model"
)

// Fleet is the merged, resolved state for one host.
type Fleet struct {
	Host string
	// Projects is the list of Incus projects this fleet manages
	// (from fleet.yaml.projects). Populated by the loader. Every
	// managed instance's project field must be in this list.
	Projects []string
	// NetworkProject is where ACLs + address-sets live (defaults to
	// "default"). With features.networks=false on all managed projects,
	// every project sees the same shared bridge/ACL/address-set
	// namespace located here.
	NetworkProject string
	Aliases        map[string]model.Alias
	AddressSets    map[string]model.AddressSet
	ACLs           map[string]model.ACL
	Instances      map[string]model.Instance
	Policies       map[string]model.Policy
	// Templates are bastille-style provisioning bundles: name → on-disk
	// path (<fleet-repo>/templates/<name>/). Applied at container
	// create time in the order the instance lists them.
	Templates map[string]model.Template

	// Secrets is the pre-decrypted content of shared/secrets.sops.yaml,
	// populated lazily by LoadSecretsInto (only when a caller needs them,
	// so read-only commands don't need the vault unlocked).
	Secrets map[string]any

	// configDir remembers where the fleet was loaded from, so semantic
	// validation can cross-check secret path references against the
	// encrypted secrets file structure without needing a second lookup.
	configDir string

	origins  map[string]string
	Warnings []string
}

// Scope tells scope-aware loaders whether they're reading shared or a
// specific host's directory, and lets them dispatch to the right name
// check.
type Scope struct {
	Kind string // "shared" or "host"
	Host string // empty for shared
}

func (s Scope) checkName(kind, name string) error {
	switch s.Kind {
	case "shared":
		if kind == "acl" {
			return checkSharedACLName(name)
		}
		return checkBaseName(kind, name)
	case "host":
		return checkHostScopedName(kind, s.Host, name)
	default:
		return fmt.Errorf("internal: unknown scope %q", s.Kind)
	}
}

// Load reads all YAML from configDir for the given host, merges,
// validates, and returns the resolved fleet state.
func Load(configDir, host string) (*Fleet, error) {
	meta, err := LoadFleetMeta(configDir)
	if err != nil {
		return nil, err
	}
	f := &Fleet{
		Host:           host,
		Projects:       meta.Projects,
		NetworkProject: meta.NetworkProject,
		Aliases:        map[string]model.Alias{},
		AddressSets:    map[string]model.AddressSet{},
		ACLs:           map[string]model.ACL{},
		Instances:      map[string]model.Instance{},
		Policies:       map[string]model.Policy{},
		Templates:      map[string]model.Template{},
		configDir:      configDir,
		origins:        map[string]string{},
	}

	sharedDir := filepath.Join(configDir, "shared")
	hostDir := filepath.Join(configDir, "hosts", host)
	if _, err := os.Stat(hostDir); err != nil {
		return nil, fmt.Errorf("host %q not found: no %s", host, hostDir)
	}
	sharedScope := Scope{Kind: "shared"}
	hostScope := Scope{Kind: "host", Host: host}

	steps := []struct {
		label string
		fn    func() error
	}{
		{"shared aliases", func() error { return f.loadAliasDir(filepath.Join(sharedDir, "aliases"), sharedScope) }},
		{"host aliases", func() error { return f.loadAliasDir(filepath.Join(hostDir, "aliases"), hostScope) }},
		{"shared address-sets", func() error { return f.loadAddressSetDir(filepath.Join(sharedDir, "address-sets"), sharedScope) }},
		{"shared acls", func() error { return f.loadACLDir(filepath.Join(sharedDir, "acls"), sharedScope) }},
		{"shared policies", func() error { return f.loadPolicyDir(filepath.Join(sharedDir, "policies"), sharedScope) }},
		{"shared instances disallowed", func() error {
			p := filepath.Join(sharedDir, "instances")
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("shared/instances/ is not permitted — instances are host-scoped only")
			}
			return nil
		}},
		{"host address-sets", func() error { return f.loadAddressSetDir(filepath.Join(hostDir, "address-sets"), hostScope) }},
		{"host acls", func() error { return f.loadACLDir(filepath.Join(hostDir, "acls"), hostScope) }},
		{"host policies", func() error { return f.loadPolicyDir(filepath.Join(hostDir, "policies"), hostScope) }},
		{"host instances", func() error { return f.loadInstanceDir(filepath.Join(hostDir, "instances")) }},
		{"templates", func() error { return f.loadTemplates(filepath.Join(configDir, "templates")) }},
	}

	for _, step := range steps {
		if err := step.fn(); err != nil {
			return nil, fmt.Errorf("%s: %w", step.label, err)
		}
	}

	if err := f.checkNameOverlap(); err != nil {
		return nil, err
	}
	if err := f.validateReferences(); err != nil {
		return nil, err
	}

	return f, nil
}

// LoadSecretsInto decrypts shared/secrets.sops.yaml and attaches the
// result to f.Secrets. Requires the vault to be unlocked (SOPS_AGE_KEY
// populated). Called by sync just before provisioning — read-only
// commands skip this and pay no SOPS cost.
func (f *Fleet) LoadSecretsInto(configDir string) error {
	s, err := LoadSecrets(configDir)
	if err != nil {
		return err
	}
	f.Secrets = s
	return nil
}

// checkNameOverlap enforces that alias names and instance names are
// disjoint. Both share the "@name" reference syntax, so overlap makes
// "@X" and "@X.field" mean two different things — a footgun.
func (f *Fleet) checkNameOverlap() error {
	for name := range f.Aliases {
		if _, dup := f.Instances[name]; dup {
			return fmt.Errorf(
				"name collision: %q is both an alias and an instance — @%s would be ambiguous with @%s.<field>",
				name, name, name)
		}
	}
	return nil
}

func (f *Fleet) claim(kind, name, path string) error {
	key := kind + ":" + name
	if prev, dup := f.origins[key]; dup {
		return fmt.Errorf("duplicate %s %q: defined in %s AND %s", kind, name, prev, path)
	}
	f.origins[key] = path
	return nil
}

// OriginOf returns the path where kind:name was declared, or "" if unknown.
// Callers (validate error messages) use this to include a file path in
// errors that would otherwise only reference the object by name.
func (f *Fleet) OriginOf(kind, name string) string {
	return f.origins[kind+":"+name]
}

func (f *Fleet) loadAliasDir(dir string, scope Scope) error {
	files, err := listYAMLFiles(dir)
	if err != nil {
		return err
	}
	for _, path := range files {
		var a model.Alias
		if err := readYAMLFile(path, &a); err != nil {
			return err
		}
		if a.Name == "" {
			return fmt.Errorf("%s: alias file missing 'alias' name", path)
		}
		if err := checkFilenameMatches(path, a.Name); err != nil {
			return err
		}
		if err := scope.checkName("alias", a.Name); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := f.claim("alias", a.Name, path); err != nil {
			return err
		}
		f.Aliases[a.Name] = a
	}
	return nil
}

func (f *Fleet) loadAddressSetDir(dir string, scope Scope) error {
	files, err := listYAMLFiles(dir)
	if err != nil {
		return err
	}
	for _, path := range files {
		var set model.AddressSet
		if err := readYAMLFile(path, &set); err != nil {
			return err
		}
		if err := checkFilenameMatches(path, set.Name); err != nil {
			return err
		}
		if err := scope.checkName("address_set", set.Name); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := f.claim("address-set", set.Name, path); err != nil {
			return err
		}
		f.AddressSets[set.Name] = set
	}
	return nil
}

func (f *Fleet) loadACLDir(dir string, scope Scope) error {
	files, err := listYAMLFiles(dir)
	if err != nil {
		return err
	}
	for _, path := range files {
		var acl model.ACL
		if err := readYAMLFile(path, &acl); err != nil {
			return err
		}
		if err := checkFilenameMatches(path, acl.Name); err != nil {
			return err
		}
		if err := scope.checkName("acl", acl.Name); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := f.claim("acl", acl.Name, path); err != nil {
			return err
		}
		f.ACLs[acl.Name] = acl
	}
	return nil
}

func (f *Fleet) loadPolicyDir(dir string, scope Scope) error {
	files, err := listYAMLFiles(dir)
	if err != nil {
		return err
	}
	for _, path := range files {
		var p model.Policy
		if err := readYAMLFile(path, &p); err != nil {
			return err
		}
		if err := p.Validate(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := checkFilenameMatches(path, p.Name); err != nil {
			return err
		}
		if err := scope.checkName("policy", p.Name); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, t := range p.Selector.Tags {
			if err := checkTagName(t); err != nil {
				return fmt.Errorf("%s: selector: %w", path, err)
			}
		}
		if err := f.claim("policy", p.Name, path); err != nil {
			return err
		}
		f.Policies[p.Name] = p
	}
	return nil
}

// loadInstanceDir walks each subdirectory of hosts/<h>/instances/ and
// reads its instance.yaml. Directory name MUST equal the declared
// instance name — grep for an instance name hits both the dir and the
// YAML.
//
// The old flat form (hosts/<h>/instances/<name>.yaml) is not supported.
// An instance is a directory now, holding instance.yaml plus optional
// files/ and after.sh — see docs/schema.md.
func (f *Fleet) loadInstanceDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			return fmt.Errorf("%s: instances/ must contain only per-instance directories now — found flat file %q. "+
				"Move it into %s/instance.yaml (see docs/schema.md).",
				dir, e.Name(), filepath.Join(dir, strings.TrimSuffix(e.Name(), ".yaml")))
		}
		instDir := filepath.Join(dir, e.Name())
		path := filepath.Join(instDir, "instance.yaml")
		if _, statErr := os.Stat(path); statErr != nil {
			return fmt.Errorf("%s: missing instance.yaml", instDir)
		}
		var inst model.Instance
		if err := readYAMLFile(path, &inst); err != nil {
			return err
		}
		if inst.Name != e.Name() {
			return fmt.Errorf("%s: instance name %q does not match directory name %q",
				path, inst.Name, e.Name())
		}
		if err := checkBaseName("instance", inst.Name); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, t := range inst.Tags {
			if err := checkTagName(t); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		}
		if err := inst.Validate(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := f.claim("instance", inst.Name, path); err != nil {
			return err
		}
		inst.SourceDir = instDir
		// project: field is REQUIRED. No silent fallback — the fleet's
		// convention is that every instance declares its Incus project
		// explicitly, so `grep project:` gives a complete accounting.
		if inst.Project == "" {
			return fmt.Errorf(
				"%s: instance %q missing required `project:` field "+
					"(must be one of %v)",
				path, inst.Name, f.Projects)
		}
		// Enforce project allowlist.
		ok := false
		for _, p := range f.Projects {
			if p == inst.Project {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf(
				"%s: instance %q project %q not in fleet.yaml projects list %v",
				path, inst.Name, inst.Project, f.Projects)
		}
		if inst.Defines != nil {
			for _, acl := range inst.Defines.ACLs {
				if err := checkInstanceScopedName("acl", inst.Name, acl.Name); err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				if err := f.claim("acl", acl.Name, path); err != nil {
					return err
				}
				f.ACLs[acl.Name] = acl
			}
			for _, set := range inst.Defines.AddressSets {
				if err := checkInstanceScopedName("address_set", inst.Name, set.Name); err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				if err := f.claim("address-set", set.Name, path); err != nil {
					return err
				}
				f.AddressSets[set.Name] = set
			}
		}
		f.Instances[inst.Name] = inst
	}
	return nil
}

// loadTemplates walks <fleet-repo>/templates/*/ and registers each as
// a named provisioning bundle. A template directory must contain at
// least one of files/ or after.sh — otherwise it is silently skipped
// (WIP-friendly).
func (f *Fleet) loadTemplates(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		var t model.Template
		manifest := filepath.Join(path, "manifest.yaml")
		if data, err := os.ReadFile(manifest); err == nil {
			if err := yaml.Unmarshal(data, &t); err != nil {
				return fmt.Errorf("parse %s: %w", manifest, err)
			}
		}
		if t.Name == "" {
			t.Name = e.Name()
		}
		if t.Name != e.Name() {
			return fmt.Errorf("template dir %q has manifest name %q — must match", e.Name(), t.Name)
		}
		if err := checkBaseName("template", t.Name); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		_, filesErr := os.Stat(filepath.Join(path, "files"))
		_, afterErr := os.Stat(filepath.Join(path, "after.sh"))
		if filesErr != nil && afterErr != nil {
			continue // empty template dir; ignore
		}
		t.Path = path
		f.Templates[t.Name] = t
	}
	return nil
}

// validateReferences walks every instance, every alias body, every
// address-set entry, and every ACL rule for @/$ references. Collects
// ALL unresolved references in one pass and returns them joined — so
// a rename PR can be fixed in one shot instead of iteratively re-running.
func (f *Fleet) validateReferences() error {
	var errs []error

	for _, inst := range f.Instances {
		for devName, dev := range inst.EffectiveDevices() {
			if dev == nil {
				continue
			}
			for _, aclName := range dev.SecurityACLs {
				if _, ok := f.ACLs[aclName]; !ok {
					errs = append(errs, fmt.Errorf("instance %q device %q references unknown acl %q",
						inst.Name, devName, aclName))
				}
			}
		}
		// acls-exclude names must resolve to a known ACL. Silent no-op
		// on a typo would let an operator believe they had opted out
		// when they had not.
		for _, aclName := range inst.ExcludedACLs {
			if _, ok := f.ACLs[aclName]; !ok {
				errs = append(errs, fmt.Errorf("instance %q acls-exclude references unknown acl %q",
					inst.Name, aclName))
			}
		}
		// Provision templates must resolve. Silent skip on typo would
		// leave a container half-provisioned.
		if inst.Provision != nil {
			for _, tName := range inst.Provision.Templates {
				if _, ok := f.Templates[tName]; !ok {
					errs = append(errs, fmt.Errorf("instance %q provision references unknown template %q",
						inst.Name, tName))
				}
			}
		}
		// Detecting acls + acls-exclude on the same name is a copy-paste
		// bug — the acl-exclude wins and silently strips.
		attached := map[string]bool{}
		for _, n := range inst.AttachedACLs {
			attached[n] = true
		}
		for _, n := range inst.ExcludedACLs {
			if attached[n] {
				errs = append(errs, fmt.Errorf(
					"instance %q lists %q in both acls and acls-exclude — exclude would strip it silently",
					inst.Name, n))
			}
		}
	}
	for name, alias := range f.Aliases {
		for _, addr := range alias.Addresses {
			if ref, ok := model.AliasRef(addr); ok {
				if err := f.checkAtRef(ref, "alias "+name); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	for name, set := range f.AddressSets {
		for _, addr := range set.RawAddresses() {
			if ref, ok := model.AliasRef(addr); ok {
				if err := f.checkAtRef(ref, "address_set "+name); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	for _, acl := range f.ACLs {
		for _, r := range acl.Ingress {
			errs = append(errs, f.collectRuleRefs(acl.Name, "ingress", r.Source, r.Destination)...)
		}
		for _, r := range acl.Egress {
			errs = append(errs, f.collectRuleRefs(acl.Name, "egress", r.Source, r.Destination)...)
		}
	}
	for name, p := range f.Policies {
		for _, aclName := range p.Attach.SecurityACLs {
			if _, ok := f.ACLs[aclName]; !ok {
				errs = append(errs, fmt.Errorf("policy %q attaches unknown acl %q", name, aclName))
			}
		}
	}
	return errors.Join(errs...)
}

// collectRuleRefs returns all unresolved refs in one ACL rule's source
// and destination. Multi-error friendly.
func (f *Fleet) collectRuleRefs(aclName, dir, source, dest string) []error {
	var errs []error
	for _, field := range []struct{ name, val string }{{"source", source}, {"destination", dest}} {
		for _, tok := range strings.Split(field.val, ",") {
			tok = strings.TrimSpace(tok)
			if strings.HasPrefix(tok, "$") && len(tok) > 1 {
				name := tok[1:]
				if _, ok := f.AddressSets[name]; !ok {
					errs = append(errs, fmt.Errorf(
						"acl %q %s rule %s references unknown address_set %q",
						aclName, dir, field.name, name))
				}
				continue
			}
			if ref, ok := model.AliasRef(tok); ok {
				where := fmt.Sprintf("acl %q %s rule %s", aclName, dir, field.name)
				if err := f.checkAtRef(ref, where); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errs
}

// reservedIncusSubjects lists Incus's built-in ACL subject keywords.
// They pass through to Incus unchanged — never resolved by this tool.
// Documented in docs/schema.md.
var reservedIncusSubjects = map[string]bool{
	"internal": true,
	"external": true,
}

// checkAtRef validates one @-reference (alias or instance field) resolves.
// Called wherever @refs may appear. Message includes the referring
// context so operators can jump straight to the file.
func (f *Fleet) checkAtRef(ref, where string) error {
	if reservedIncusSubjects[ref] {
		return nil
	}
	if dot := strings.IndexByte(ref, '.'); dot > 0 {
		instName := ref[:dot]
		field := ref[dot+1:]
		inst, ok := f.Instances[instName]
		if !ok {
			return fmt.Errorf("%s references unknown instance @%s.%s", where, instName, field)
		}
		switch field {
		case "ip4":
			if inst.IP4 == "" {
				return fmt.Errorf("%s references @%s.ip4 but that instance has no ip4 declared",
					where, instName)
			}
		case "ip6":
			if inst.IP6 == "" {
				return fmt.Errorf("%s references @%s.ip6 but that instance has no ip6 declared",
					where, instName)
			}
		default:
			return fmt.Errorf("%s references @%s.%s but only ip4, ip6 are supported",
				where, instName, field)
		}
		return nil
	}
	if _, ok := f.Aliases[ref]; !ok {
		return fmt.Errorf("%s references unknown alias @%s", where, ref)
	}
	return nil
}

// ListHosts returns the sorted list of directories under configDir/hosts/.
// Public so callers (like `validate` with no --host) can iterate every host.
func ListHosts(configDir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(configDir, "hosts"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func listYAMLFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			out = append(out, filepath.Join(dir, name))
		}
	}
	return out, nil
}

func readYAMLFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func checkFilenameMatches(path, name string) error {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext != ".yaml" && ext != ".yml" {
		return fmt.Errorf("file %s: unexpected extension %q", path, ext)
	}
	base = strings.TrimSuffix(base, ext)
	if base != name {
		return fmt.Errorf("file %s declares name %q but filename says %q",
			path, name, base)
	}
	return nil
}
