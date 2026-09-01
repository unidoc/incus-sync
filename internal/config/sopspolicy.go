package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SopsPolicyFilename is the SOPS encryption-policy file at the fleet
// repo root. incus-sync edits it directly via yaml.Node — preserving
// comments, anchors, and the operator's own structure — rather than
// through the sops CLI, which has no "add/remove recipient"
// subcommand of its own, only `updatekeys` (re-wrap files against
// whatever .sops.yaml already says).
const SopsPolicyFilename = ".sops.yaml"

// agePubKeyRe matches an age X25519 recipient's bech32 encoding.
// age1 + at least 50 lowercase-bech32 chars is generous on length
// (real keys are a fixed 58 chars after the prefix) but strict on
// alphabet and prefix — good enough to catch a pasted SSH key, an
// age *identity* (AGE-SECRET-KEY-1... / AGE-PLUGIN-*) or plain typos
// before they land in a committed policy file.
var agePubKeyRe = regexp.MustCompile(`^age1[023456789acdefghjklmnpqrstuvwxyz]{50,}$`)

// anchorNameRe matches a valid, readable YAML anchor name. Kept
// restrictive (no spaces/punctuation beyond - and _) since the anchor
// doubles as the recipient's short label wherever it's referenced.
var anchorNameRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

// SopsPolicy is .sops.yaml loaded as an editable node tree.
type SopsPolicy struct {
	path string
	doc  yaml.Node // Kind == yaml.DocumentNode
	root *yaml.Node
}

// SopsRecipient is one entry in .sops.yaml's `keys:` list, resolved
// against every creation_rule that references it.
type SopsRecipient struct {
	Anchor  string   // YAML anchor name — the label, e.g. "ahall_laptop"
	Comment string   // free-text HeadComment directly above the entry, if any
	PubKey  string   // age1... recipient
	Rules   []string // path_regex of every creation_rule wired to this recipient
}

// LoadSopsPolicy reads and parses fleetPath's .sops.yaml.
func LoadSopsPolicy(fleetPath string) (*SopsPolicy, error) {
	path := filepath.Join(fleetPath, SopsPolicyFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected a top-level mapping (keys:, creation_rules:)", path)
	}
	return &SopsPolicy{path: path, doc: doc, root: doc.Content[0]}, nil
}

// Save writes the policy back to disk atomically, mode 0644 (this
// file holds no secret — only public keys and path patterns).
func (p *SopsPolicy) Save() error {
	out, err := yaml.Marshal(&p.doc)
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// mapGet returns the value node for key in mapping node m, or nil.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// keysNode returns (creating if absent) the `keys:` sequence node.
func (p *SopsPolicy) keysNode(create bool) *yaml.Node {
	if n := mapGet(p.root, "keys"); n != nil {
		return n
	}
	if !create {
		return nil
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "keys"}
	seqNode := &yaml.Node{Kind: yaml.SequenceNode}
	p.root.Content = append([]*yaml.Node{keyNode, seqNode}, p.root.Content...)
	return seqNode
}

// creationRules returns every creation_rules[i] mapping node, each
// alongside its resolved path_regex string.
type creationRule struct {
	pathRegex string
	node      *yaml.Node // the rule's mapping node
}

func (p *SopsPolicy) creationRules() []creationRule {
	rulesNode := mapGet(p.root, "creation_rules")
	if rulesNode == nil || rulesNode.Kind != yaml.SequenceNode {
		return nil
	}
	var out []creationRule
	for _, rule := range rulesNode.Content {
		pr := mapGet(rule, "path_regex")
		if pr == nil {
			continue
		}
		out = append(out, creationRule{pathRegex: pr.Value, node: rule})
	}
	return out
}

// ageListsIn returns every key_groups[].age sequence node inside one
// creation_rule mapping (almost always exactly one key_group).
func ageListsIn(rule *yaml.Node) []*yaml.Node {
	kg := mapGet(rule, "key_groups")
	if kg == nil || kg.Kind != yaml.SequenceNode {
		return nil
	}
	var out []*yaml.Node
	for _, group := range kg.Content {
		if age := mapGet(group, "age"); age != nil && age.Kind == yaml.SequenceNode {
			out = append(out, age)
		}
	}
	return out
}

// findKeyEntry returns the `keys:` sequence entry whose Anchor or
// Value matches identifier, or nil.
func (p *SopsPolicy) findKeyEntry(identifier string) *yaml.Node {
	seq := p.keysNode(false)
	if seq == nil {
		return nil
	}
	for _, k := range seq.Content {
		if k.Anchor == identifier || k.Value == identifier {
			return k
		}
	}
	return nil
}

// ListRecipients returns every entry in `keys:`, each resolved
// against every creation_rule that references it by anchor.
func (p *SopsPolicy) ListRecipients() []SopsRecipient {
	seq := p.keysNode(false)
	if seq == nil {
		return nil
	}
	rules := p.creationRules()
	var out []SopsRecipient
	for _, k := range seq.Content {
		r := SopsRecipient{Anchor: k.Anchor, Comment: cleanComment(k.HeadComment), PubKey: k.Value}
		for _, rule := range rules {
			for _, ageList := range ageListsIn(rule.node) {
				for _, entry := range ageList.Content {
					if entry.Kind == yaml.AliasNode && entry.Value == k.Anchor && k.Anchor != "" {
						r.Rules = append(r.Rules, rule.pathRegex)
					}
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// AddRecipientOptions controls which creation_rules a new recipient
// is wired into. Empty Rules means "every creation_rule" — the
// default, matching how a fleet's operators typically all need access
// to everything the fleet encrypts.
type AddRecipientOptions struct {
	// Rules, if non-empty, restricts the new recipient to
	// creation_rules whose path_regex exactly matches one of these
	// strings. Empty = every creation_rule.
	Rules []string
}

// AddRecipient adds a new age public key to `keys:` under the given
// anchor (also its label), with an optional human-readable comment,
// and wires it into every matching creation_rule's key_groups[].age
// list. Does not touch already-encrypted files — see
// cmd_vault.go's addRecipientCmd for the accompanying `sops
// updatekeys` step.
func (p *SopsPolicy) AddRecipient(anchor, pubkey, comment string, opts AddRecipientOptions) error {
	if !anchorNameRe.MatchString(anchor) {
		return fmt.Errorf("invalid anchor %q — use letters, digits, - and _, starting with a letter", anchor)
	}
	if !agePubKeyRe.MatchString(pubkey) {
		return fmt.Errorf("%q does not look like an age public key (expected age1...)", pubkey)
	}
	if e := p.findKeyEntry(anchor); e != nil {
		return fmt.Errorf("anchor %q already exists (pubkey %s)", anchor, e.Value)
	}
	if e := p.findKeyEntry(pubkey); e != nil {
		return fmt.Errorf("pubkey already present under anchor %q", e.Anchor)
	}

	entry := &yaml.Node{
		Kind:   yaml.ScalarNode,
		Value:  pubkey,
		Anchor: anchor,
	}
	if comment != "" {
		entry.HeadComment = comment
	}
	seq := p.keysNode(true)
	seq.Content = append(seq.Content, entry)

	rules := p.creationRules()
	if len(rules) == 0 {
		return fmt.Errorf("%s has no creation_rules to attach the recipient to", p.path)
	}
	matched := 0
	for _, rule := range rules {
		if len(opts.Rules) > 0 && !containsString(opts.Rules, rule.pathRegex) {
			continue
		}
		ageLists := ageListsIn(rule.node)
		if len(ageLists) == 0 {
			return fmt.Errorf("creation_rule %q has no key_groups[].age list to attach to", rule.pathRegex)
		}
		for _, ageList := range ageLists {
			ageList.Content = append(ageList.Content, &yaml.Node{Kind: yaml.AliasNode, Value: anchor})
		}
		matched++
	}
	if matched == 0 {
		return fmt.Errorf("no creation_rule matched %v", opts.Rules)
	}
	return nil
}

// RemoveRecipient removes the `keys:` entry matching identifier
// (anchor name or literal pubkey) and every alias reference to it.
// Refuses to leave any creation_rule with zero age recipients — that
// would make its files permanently undecryptable, not revoke access.
func (p *SopsPolicy) RemoveRecipient(identifier string) (anchor string, err error) {
	entry := p.findKeyEntry(identifier)
	if entry == nil {
		return "", fmt.Errorf("no recipient matching %q", identifier)
	}
	anchor = entry.Anchor

	rules := p.creationRules()
	for _, rule := range rules {
		for _, ageList := range ageListsIn(rule.node) {
			remaining := 0
			for _, e := range ageList.Content {
				if !(e.Kind == yaml.AliasNode && e.Value == anchor) {
					remaining++
				}
			}
			if remaining == 0 {
				return "", fmt.Errorf(
					"refusing: %q is the only recipient in creation_rule %q — "+
						"removing it would make those files permanently undecryptable",
					anchor, rule.pathRegex)
			}
		}
	}

	// Second pass: now that we know every rule keeps at least one
	// recipient, actually drop the alias references.
	for _, rule := range rules {
		for _, ageList := range ageListsIn(rule.node) {
			kept := ageList.Content[:0]
			for _, e := range ageList.Content {
				if !(e.Kind == yaml.AliasNode && e.Value == anchor) {
					kept = append(kept, e)
				}
			}
			ageList.Content = kept
		}
	}

	seq := p.keysNode(false)
	kept := seq.Content[:0]
	for _, k := range seq.Content {
		if k != entry {
			kept = append(kept, k)
		}
	}
	seq.Content = kept
	return anchor, nil
}

// AffectedFiles returns every already-encrypted file under fleetPath
// whose relative path matches one of the given creation_rule
// path_regex patterns. Used to find which existing *.sops.yaml files
// need `sops updatekeys` after a recipient change. "Already
// encrypted" is detected the same way LoadSecrets/LoadRemote do — a
// top-level `sops:` block — so a not-yet-encrypted scaffold file is
// correctly skipped (nothing to re-wrap).
func AffectedFiles(fleetPath string, pathRegexes []string) ([]string, error) {
	var patterns []*regexp.Regexp
	for _, pr := range pathRegexes {
		re, err := regexp.Compile(pr)
		if err != nil {
			return nil, fmt.Errorf("creation_rule path_regex %q: %w", pr, err)
		}
		patterns = append(patterns, re)
	}
	var out []string
	err := filepath.WalkDir(fleetPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(fleetPath, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		matched := false
		for _, re := range patterns {
			if re.MatchString(rel) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), "\nsops:\n") || strings.HasPrefix(string(raw), "sops:\n") {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// cleanComment strips the leading "# " (and any bare "#") the yaml.v3
// emitter adds to every HeadComment line back out again, so
// ListRecipients returns the same plain text AddRecipient was given.
func cleanComment(raw string) string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "#")
		lines = append(lines, strings.TrimSpace(line))
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
