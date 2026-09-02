package config

import (
	"bytes"
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
	path         string
	doc          yaml.Node // Kind == yaml.DocumentNode
	root         *yaml.Node
	hadDocMarker bool // source file started with "---"; restored on Save
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
	hadDocMarker := bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), []byte("---"))
	return &SopsPolicy{path: path, doc: doc, root: doc.Content[0], hadDocMarker: hadDocMarker}, nil
}

// Save writes the policy back to disk atomically, mode 0644 (this
// file holds no secret — only public keys and path patterns).
//
// yaml.v3 does not preserve the source file's exact formatting when
// re-encoding a Node tree: this uses a 2-space indent (the convention
// every .sops.yaml in this project actually uses, vs. yaml.Marshal's
// 4-space default) and restores a leading "---" if the source had
// one, but blank lines between sections are NOT preserved — that's a
// known yaml.v3 limitation (blank lines aren't part of its Node
// model, only comments are). Comments and anchors DO survive. The
// practical effect: the first Save() on a hand-formatted file
// produces a real reformatting diff alongside the semantic change —
// expected, not a bug, but worth knowing before reviewing that diff.
func (p *SopsPolicy) Save() error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&p.doc); err != nil {
		_ = enc.Close()
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	out := buf.Bytes()
	if p.hadDocMarker && !bytes.HasPrefix(out, []byte("---")) {
		out = append([]byte("---\n"), out...)
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

// ageListsIn returns every mutable age-recipient sequence node this
// creation_rule uses: key_groups[].age (the long form) if present,
// else the rule's own bare `age:` field. SOPS itself accepts both —
// the long form is what multi-key-type (age+pgp+kms in one group)
// setups need, but the short form is what SOPS's own docs lead with
// and what `sops -e` writes by default, so only supporting
// key_groups made add-recipient/list-recipients unusable against a
// very common real policy shape.
//
// Per SOPS's real schema (creationRule.Age is `interface{}`: string or
// []string — see github.com/getsops/sops/v3/config), a bare `age:`
// can be a comma-separated scalar string OR already a sequence. A
// scalar is normalized into a sequence of literal entries in place —
// there is no way to embed a YAML alias inside a comma string, so
// existing values become plain scalars, not anchored — the moment
// this function is called, including from the read-only
// ListRecipients: harmless, since nothing here calls Save() unless a
// real edit follows, and the semantic recipient set is unchanged.
func ageListsIn(rule *yaml.Node) []*yaml.Node {
	if kg := mapGet(rule, "key_groups"); kg != nil && kg.Kind == yaml.SequenceNode {
		var out []*yaml.Node
		for _, group := range kg.Content {
			if age := mapGet(group, "age"); age != nil && age.Kind == yaml.SequenceNode {
				out = append(out, age)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	age := mapGet(rule, "age")
	if age == nil {
		return nil
	}
	if age.Kind == yaml.ScalarNode {
		normalizeScalarAgeField(age)
	}
	if age.Kind != yaml.SequenceNode {
		return nil
	}
	return []*yaml.Node{age}
}

// normalizeScalarAgeField converts a bare `age: key1,key2` scalar
// node into an equivalent sequence node IN PLACE — same object
// identity, so the parent mapping's reference to it stays valid.
// Empty entries from stray commas are dropped, matching SOPS's own
// parseKeyField behavior.
func normalizeScalarAgeField(age *yaml.Node) {
	var items []string
	for _, part := range strings.Split(age.Value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			items = append(items, part)
		}
	}
	age.Kind = yaml.SequenceNode
	age.Tag = "!!seq"
	age.Value = ""
	age.Style = 0
	age.Content = make([]*yaml.Node, len(items))
	for i, v := range items {
		age.Content[i] = &yaml.Node{Kind: yaml.ScalarNode, Value: v}
	}
}

// entryMatchesRecipient reports whether one age-list entry refers to
// the given recipient — either an alias to their `keys:` anchor, or a
// literal copy of their pubkey. SOPS accepts pubkeys pasted directly
// into an age list with no `keys:`/anchor involved at all (that's
// exactly what `sops updatekeys` itself writes, and what a
// hand-maintained short-form policy typically has) — matching only
// aliases silently ignores every such entry: list-recipients would
// report it with no rules, and remove-recipient would "succeed"
// without touching it, leaving the key still able to decrypt
// everything.
func entryMatchesRecipient(entry *yaml.Node, anchor, pubkey string) bool {
	if entry.Kind == yaml.AliasNode && anchor != "" && entry.Value == anchor {
		return true
	}
	if entry.Kind == yaml.ScalarNode && entry.Value == pubkey {
		return true
	}
	return false
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
// against every creation_rule that references it — by anchor alias OR
// by a literal copy of its pubkey (see entryMatchesRecipient).
//
// Known boundary, found while verifying the fix above rather than
// something this round was scoped to close: a recipient that exists
// ONLY as a literal pubkey in some rule's age list, with NO
// corresponding `keys:` entry at all (a valid SOPS shape — `keys:` /
// anchors are an incus-sync labeling convention, not something SOPS
// itself requires), is invisible to this function and to
// RemoveRecipient. Such a recipient can currently only be reported or
// revoked by editing .sops.yaml directly.
func (p *SopsPolicy) ListRecipients() []SopsRecipient {
	seq := p.keysNode(false)
	if seq == nil {
		return nil
	}
	rules := p.creationRules()
	var out []SopsRecipient
	for _, k := range seq.Content {
		r := SopsRecipient{Anchor: k.Anchor, Comment: cleanComment(k.HeadComment), PubKey: k.Value}
		seen := map[string]bool{}
		for _, rule := range rules {
			for _, ageList := range ageListsIn(rule.node) {
				for _, entry := range ageList.Content {
					if entryMatchesRecipient(entry, k.Anchor, k.Value) && !seen[rule.pathRegex] {
						r.Rules = append(r.Rules, rule.pathRegex)
						seen[rule.pathRegex] = true
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
//
// Validates everything BEFORE mutating anything: a returned error
// guarantees the policy's in-memory tree (and therefore whatever a
// caller might Save()) is byte-for-byte what it was before this call
// — mirrors RemoveRecipient's validate-then-mutate structure.
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

	rules := p.creationRules()
	if len(rules) == 0 {
		return fmt.Errorf("%s has no creation_rules to attach the recipient to", p.path)
	}

	// Validate-only pass: resolve exactly which age lists will receive
	// the new recipient, and confirm every requested --rule filter
	// actually matched something — no mutation happens here.
	var targets []*yaml.Node
	matchedFilters := map[string]bool{}
	for _, rule := range rules {
		if len(opts.Rules) > 0 && !containsString(opts.Rules, rule.pathRegex) {
			continue
		}
		ageLists := ageListsIn(rule.node)
		if len(ageLists) == 0 {
			return fmt.Errorf("creation_rule %q has no key_groups[].age list to attach to", rule.pathRegex)
		}
		targets = append(targets, ageLists...)
		matchedFilters[rule.pathRegex] = true
	}
	if len(targets) == 0 {
		return fmt.Errorf("no creation_rule matched %v", opts.Rules)
	}
	if len(opts.Rules) > 0 {
		var unmatched []string
		for _, want := range opts.Rules {
			if !matchedFilters[want] {
				unmatched = append(unmatched, want)
			}
		}
		if len(unmatched) > 0 {
			return fmt.Errorf("--rule value(s) matched no creation_rule: %v", unmatched)
		}
	}

	// Mutate pass: every check above passed.
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
	for _, ageList := range targets {
		ageList.Content = append(ageList.Content, &yaml.Node{Kind: yaml.AliasNode, Value: anchor})
	}
	return nil
}

// RemoveRecipient removes the `keys:` entry matching identifier
// (anchor name or literal pubkey) and every age-list entry that
// refers to it — alias OR literal (see entryMatchesRecipient).
// Refuses to leave any creation_rule that currently includes this
// recipient with zero age recipients afterward — that would make its
// files permanently undecryptable, not revoke access. A rule that
// never referenced this recipient in the first place (including one
// whose age list happens to already be empty) is unaffected by that
// check — it has nothing to do with this removal.
//
// Requires identifier to have a `keys:` entry — see ListRecipients'
// doc for the known boundary around literal-pubkey-only recipients
// with no `keys:` entry at all; those can't be named here either.
func (p *SopsPolicy) RemoveRecipient(identifier string) (anchor string, err error) {
	entry := p.findKeyEntry(identifier)
	if entry == nil {
		return "", fmt.Errorf("no recipient matching %q", identifier)
	}
	anchor = entry.Anchor
	pubkey := entry.Value

	rules := p.creationRules()
	for _, rule := range rules {
		for _, ageList := range ageListsIn(rule.node) {
			matchCount, remaining := 0, 0
			for _, e := range ageList.Content {
				if entryMatchesRecipient(e, anchor, pubkey) {
					matchCount++
				} else {
					remaining++
				}
			}
			if matchCount > 0 && remaining == 0 {
				return "", fmt.Errorf(
					"refusing: removing %q would leave creation_rule %q with zero recipients — "+
						"its files would become permanently undecryptable",
					identifier, rule.pathRegex)
			}
		}
	}

	// Second pass: now that we know every affected rule keeps at
	// least one recipient, actually drop the matching entries.
	for _, rule := range rules {
		for _, ageList := range ageListsIn(rule.node) {
			kept := ageList.Content[:0]
			for _, e := range ageList.Content {
				if !entryMatchesRecipient(e, anchor, pubkey) {
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
