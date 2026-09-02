package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const fixturePolicy = `---
keys:
  # atljump.example.com (bastion)
  - &atljump age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm

creation_rules:
  - path_regex: hosts/.*/remote\.sops\.yaml$
    encrypted_regex: '^(client_key|client_cert)$'
    key_groups:
      - age:
          - *atljump

  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - *atljump
`

func writeFixture(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, SopsPolicyFilename), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSopsPolicyListRecipients(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)

	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	recipients := p.ListRecipients()
	if len(recipients) != 1 {
		t.Fatalf("got %d recipients, want 1", len(recipients))
	}
	r := recipients[0]
	if r.Anchor != "atljump" {
		t.Errorf("Anchor = %q, want atljump", r.Anchor)
	}
	if r.PubKey != "age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm" {
		t.Errorf("PubKey = %q", r.PubKey)
	}
	if r.Comment != "atljump.example.com (bastion)" {
		t.Errorf("Comment = %q", r.Comment)
	}
	if len(r.Rules) != 2 {
		t.Errorf("Rules = %v, want 2 entries", r.Rules)
	}
}

func TestSopsPolicyAddRecipientDefaultAllRules(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)

	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	if err := p.AddRecipient("ahall_laptop", newKey, "ahall's laptop key", AddRecipientOptions{}); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}
	if err := p.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Round-trip: re-load from disk and verify structure survived.
	p2, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	recipients := p2.ListRecipients()
	if len(recipients) != 2 {
		t.Fatalf("got %d recipients after add, want 2", len(recipients))
	}
	var added *SopsRecipient
	for i := range recipients {
		if recipients[i].Anchor == "ahall_laptop" {
			added = &recipients[i]
		}
	}
	if added == nil {
		t.Fatal("new recipient not found after reload")
	}
	if added.PubKey != newKey {
		t.Errorf("PubKey = %q, want %q", added.PubKey, newKey)
	}
	if added.Comment != "ahall's laptop key" {
		t.Errorf("Comment = %q", added.Comment)
	}
	if len(added.Rules) != 2 {
		t.Errorf("new recipient wired into %d rules, want 2 (default = all)", len(added.Rules))
	}

	// Also confirm the file itself still parses as plain YAML (sanity
	// that Save() didn't emit anything malformed).
	raw, err := os.ReadFile(filepath.Join(dir, SopsPolicyFilename))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("saved .sops.yaml does not parse: %v\n%s", err, raw)
	}
}

func TestSopsPolicyAddRecipientScopedToOneRule(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)

	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	scoped := AddRecipientOptions{Rules: []string{`hosts/.*/remote\.sops\.yaml$`}}
	if err := p.AddRecipient("ci_runner", newKey, "", scoped); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}
	recipients := p.ListRecipients()
	for _, r := range recipients {
		if r.Anchor == "ci_runner" {
			if len(r.Rules) != 1 {
				t.Errorf("scoped recipient wired into %d rules, want 1", len(r.Rules))
			}
		}
	}
}

func TestSopsPolicyAddRecipientRejectsDuplicateAnchor(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	err = p.AddRecipient("atljump", "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc", "", AddRecipientOptions{})
	if err == nil {
		t.Fatal("expected error adding duplicate anchor")
	}
}

func TestSopsPolicyAddRecipientRejectsBadPubkey(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	for _, bad := range []string{
		"not-a-key",
		"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA",
		"",
	} {
		if err := p.AddRecipient("x", bad, "", AddRecipientOptions{}); err == nil {
			t.Errorf("AddRecipient with pubkey %q: expected error, got nil", bad)
		}
	}
}

func TestSopsPolicyAddRecipientRejectsDuplicatePubkeyUnderNewAnchor(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	existingPubkey := "age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm"
	if err := p.AddRecipient("second_anchor", existingPubkey, "", AddRecipientOptions{}); err == nil {
		t.Fatal("expected error adding a pubkey that's already present under a different anchor")
	}
}

func TestSopsPolicyAddRecipientNoCreationRules(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, `keys:
  - &atljump age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm
`)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	if err := p.AddRecipient("ahall_laptop", newKey, "", AddRecipientOptions{}); err == nil {
		t.Fatal("expected error adding a recipient with zero creation_rules to attach to")
	}
	if len(p.ListRecipients()) != 1 {
		t.Fatal("policy was mutated despite the refused add")
	}
}

func TestSopsPolicyAddRecipientRuleWithNoAgeList(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, `keys:
  - &atljump age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm

creation_rules:
  - path_regex: no-key-groups\.yaml$
    key_groups: []
`)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	if err := p.AddRecipient("ahall_laptop", newKey, "", AddRecipientOptions{}); err == nil {
		t.Fatal("expected error when the only creation_rule has no key_groups[].age list")
	}
}

// TestSopsPolicyAddRecipientRejectsUnmatchedRuleFilter covers a typo'd
// --rule value: previously this was silently ignored as long as at
// least one OTHER --rule value matched something.
func TestSopsPolicyAddRecipientRejectsUnmatchedRuleFilter(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	opts := AddRecipientOptions{Rules: []string{`hosts/.*/remote\.sops\.yaml$`, "this-matches-nothing"}}
	if err := p.AddRecipient("ahall_laptop", newKey, "", opts); err == nil {
		t.Fatal("expected error when one of several --rule values matches no creation_rule")
	}
	// Confirm nothing was mutated — the one real match must not have
	// been applied just because the typo'd one was silently dropped.
	if len(p.ListRecipients()) != 1 {
		t.Fatalf("policy was mutated despite the refused add: %+v", p.ListRecipients())
	}
	for _, rule := range p.creationRules() {
		for _, ageList := range ageListsIn(rule.node) {
			if len(ageList.Content) != 1 {
				t.Errorf("rule %q age list has %d entries after refused add, want 1", rule.pathRegex, len(ageList.Content))
			}
		}
	}
}

// TestSopsPolicyAddRecipientAtomicOnFailure is AddRecipient's
// counterpart to TestSopsPolicyRemoveRecipientRefusesLastOne: a
// multi-rule add where a LATER rule fails validation must not leave
// an EARLIER rule (or the keys: list) partially mutated.
func TestSopsPolicyAddRecipientAtomicOnFailure(t *testing.T) {
	dir := t.TempDir()
	// Second rule has no key_groups[].age — AddRecipient's default
	// (no --rule filter, i.e. "every rule") must fail on it, and must
	// not have already mutated the first rule or keys: by that point.
	writeFixture(t, dir, `keys:
  - &atljump age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm

creation_rules:
  - path_regex: hosts/.*/remote\.sops\.yaml$
    key_groups:
      - age:
          - *atljump
  - path_regex: no-key-groups\.yaml$
    key_groups: []
`)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	if err := p.AddRecipient("ahall_laptop", newKey, "", AddRecipientOptions{}); err == nil {
		t.Fatal("expected error — second rule has no key_groups[].age")
	}
	if len(p.ListRecipients()) != 1 {
		t.Fatalf("keys: was mutated despite the refused add: %+v", p.ListRecipients())
	}
	rules := p.creationRules()
	if len(ageListsIn(rules[0].node)[0].Content) != 1 {
		t.Error("first rule's age list was mutated despite the second rule failing validation")
	}
}

func TestSopsPolicyRemoveRecipient(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	if err := p.AddRecipient("ahall_laptop", newKey, "", AddRecipientOptions{}); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	// Now two recipients on every rule — removing one must succeed.
	anchor, err := p.RemoveRecipient("ahall_laptop")
	if err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}
	if anchor != "ahall_laptop" {
		t.Errorf("anchor = %q", anchor)
	}
	recipients := p.ListRecipients()
	if len(recipients) != 1 {
		t.Fatalf("got %d recipients after remove, want 1", len(recipients))
	}
	if recipients[0].Anchor != "atljump" {
		t.Errorf("remaining recipient = %q, want atljump", recipients[0].Anchor)
	}
}

func TestSopsPolicyRemoveRecipientByPubkey(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	if err := p.AddRecipient("ahall_laptop", newKey, "", AddRecipientOptions{}); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}
	anchor, err := p.RemoveRecipient(newKey)
	if err != nil {
		t.Fatalf("RemoveRecipient by pubkey: %v", err)
	}
	if anchor != "ahall_laptop" {
		t.Errorf("anchor = %q, want ahall_laptop", anchor)
	}
}

// TestSopsPolicyRemoveRecipientRefusesLastOne is the critical safety
// check: removing the sole recipient of any creation_rule would make
// its files permanently undecryptable (not "revoked" — gone), so it
// must be refused, atomically (nothing partially mutated).
func TestSopsPolicyRemoveRecipientRefusesLastOne(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	if _, err := p.RemoveRecipient("atljump"); err == nil {
		t.Fatal("expected error removing the sole recipient")
	}
	// Confirm nothing was mutated by the failed attempt.
	recipients := p.ListRecipients()
	if len(recipients) != 1 || recipients[0].Anchor != "atljump" {
		t.Fatalf("policy was mutated despite refused removal: %+v", recipients)
	}
	for _, rule := range p.creationRules() {
		for _, ageList := range ageListsIn(rule.node) {
			if len(ageList.Content) != 1 {
				t.Errorf("rule %q age list has %d entries after refused removal, want 1", rule.pathRegex, len(ageList.Content))
			}
		}
	}
}

func TestSopsPolicyRemoveRecipientUnknown(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	if _, err := p.RemoveRecipient("nonexistent"); err == nil {
		t.Fatal("expected error removing an unknown recipient")
	}
}

func TestAffectedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "hosts", "web1"), 0o755); err != nil {
		t.Fatal(err)
	}
	encrypted := "url: https://web1\nclient_cert: ENC[...]\nsops:\n    version: 3.13.3\n"
	plain := "url: https://web2\nclient_cert: not-yet-encrypted\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts", "web1", "remote.sops.yaml"), []byte(encrypted), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "hosts", "web2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts", "web2", "remote.sops.yaml"), []byte(plain), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fleet.yaml"), []byte("projects: [default]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := AffectedFiles(dir, []string{`hosts/.*/remote\.sops\.yaml$`})
	if err != nil {
		t.Fatalf("AffectedFiles: %v", err)
	}
	if len(got) != 1 || got[0] != filepath.FromSlash("hosts/web1/remote.sops.yaml") {
		t.Fatalf("got %v, want exactly [hosts/web1/remote.sops.yaml] (web2 unencrypted, fleet.yaml unmatched)", got)
	}
}

// TestSopsPolicySavePreservesConventionalStyle guards against Save()
// regressing to yaml.Marshal's 4-space-indent, no-document-marker
// default, which would turn every real edit into a full-file
// reformat diff on top of the actual change. Blank-line preservation
// is NOT covered here — that's a documented yaml.v3 limitation Save's
// doc comment accepts, not something this test can hold the line on.
func TestSopsPolicySavePreservesConventionalStyle(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixturePolicy) // starts with "---", 2-space indent
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	if err := p.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, SopsPolicyFilename))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "---") {
		t.Errorf("Save() dropped the leading --- document marker:\n%s", raw)
	}
	// Check the indent of the line directly under "keys:" — the first
	// nesting level, so its indent is unambiguous regardless of how
	// deep other structures nest.
	idx := strings.Index(string(raw), "keys:\n")
	if idx < 0 {
		t.Fatalf("no keys: line found:\n%s", raw)
	}
	rest := string(raw)[idx+len("keys:\n"):]
	nextLine := strings.SplitN(rest, "\n", 2)[0]
	if strings.HasPrefix(nextLine, "    ") {
		t.Errorf("Save() used 4-space indent (yaml.Marshal's default) instead of the source's 2-space convention: %q", nextLine)
	}
	if !strings.HasPrefix(nextLine, "  ") || strings.HasPrefix(nextLine, "   ") {
		t.Errorf("expected exactly 2-space indent under keys:, got %q", nextLine)
	}
}

// fixtureLiteralPolicy has "alice" wired into her rule as a literal
// pubkey copy, not a `*alice` alias — the exact shape review finding
// F1 identified as invisible to ListRecipients/RemoveRecipient. "bob"
// is aliased normally, as a control.
const fixtureLiteralPolicy = `keys:
  - &bob age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc
  - &alice age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm

creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - *bob
          - age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm
`

// TestSopsPolicyListRecipientsResolvesLiteralEntries is F1: a
// recipient referenced by a literal pubkey copy (not a YAML alias)
// must still resolve to the rule that references it, exactly like the
// aliased case does.
func TestSopsPolicyListRecipientsResolvesLiteralEntries(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixtureLiteralPolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	recipients := p.ListRecipients()
	byAnchor := map[string]SopsRecipient{}
	for _, r := range recipients {
		byAnchor[r.Anchor] = r
	}
	if len(byAnchor["alice"].Rules) != 1 {
		t.Errorf("alice (literal entry) resolved to %d rules, want 1: %+v", len(byAnchor["alice"].Rules), byAnchor["alice"])
	}
	if len(byAnchor["bob"].Rules) != 1 {
		t.Errorf("bob (aliased control) resolved to %d rules, want 1: %+v", len(byAnchor["bob"].Rules), byAnchor["bob"])
	}
}

// TestSopsPolicyRemoveRecipientRemovesLiteralEntry is F1's other half:
// removing a literally-referenced recipient must actually drop that
// literal entry and be refused if it's the rule's last recipient —
// not silently "succeed" while leaving the pubkey fully able to
// decrypt (and still listed as a recipient for future files).
func TestSopsPolicyRemoveRecipientRemovesLiteralEntry(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixtureLiteralPolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	if _, err := p.RemoveRecipient("alice"); err != nil {
		t.Fatalf("RemoveRecipient(alice): %v", err)
	}
	rules := p.creationRules()
	ageList := ageListsIn(rules[0].node)[0]
	for _, e := range ageList.Content {
		if e.Kind == yaml.ScalarNode && e.Value == "age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm" {
			t.Error("alice's literal pubkey entry is still in the age list after removal")
		}
	}
	// bob is now the sole recipient — removing him must be refused.
	if _, err := p.RemoveRecipient("bob"); err == nil {
		t.Error("expected error removing bob, now the sole recipient after alice's removal")
	}
}

// fixtureShortFormPolicy uses a bare `age:` scalar directly on the
// creation_rule — the form SOPS's own docs lead with and `sops -e`
// writes by default — with no `key_groups:` at all. Review finding F2.
const fixtureShortFormPolicy = `creation_rules:
  - path_regex: \.sops\.ya?ml$
    age: age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm
`

func TestSopsPolicyAgeListsInHandlesShortForm(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, fixtureShortFormPolicy)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	newKey := "age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc"
	if err := p.AddRecipient("second", newKey, "", AddRecipientOptions{}); err != nil {
		t.Fatalf("AddRecipient against short-form age: %v", err)
	}
	recipients := p.ListRecipients()
	if len(recipients) != 1 || recipients[0].Anchor != "second" {
		t.Fatalf("got %+v, want exactly [second]", recipients)
	}
	if len(recipients[0].Rules) != 1 {
		t.Errorf("new recipient resolved to %d rules, want 1", len(recipients[0].Rules))
	}
}

// TestSopsPolicyAgeListsInHandlesShortFormCommaList covers SOPS's own
// comma-separated-string convention for multiple recipients in the
// short form (config.parseKeyField in the vendored sops source).
func TestSopsPolicyAgeListsInHandlesShortFormCommaList(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, `creation_rules:
  - path_regex: \.sops\.ya?ml$
    age: age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm, age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc
`)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	rules := p.creationRules()
	ageLists := ageListsIn(rules[0].node)
	if len(ageLists) != 1 || len(ageLists[0].Content) != 2 {
		t.Fatalf("got %d age lists, want 1 with 2 entries", len(ageLists))
	}
	if ageLists[0].Content[0].Kind != yaml.ScalarNode || ageLists[0].Content[1].Kind != yaml.ScalarNode {
		t.Errorf("comma-split entries should be plain scalars: %+v", ageLists[0].Content)
	}
}

// TestSopsPolicyRemoveRecipientRefusesEmptyUnrelatedRule is F6: a
// creation_rule whose age list is already empty — unrelated to the
// recipient being removed — must not cause a false "is the only
// recipient" refusal for THAT recipient's actual, populated rule.
func TestSopsPolicyRemoveRecipientRefusesEmptyUnrelatedRule(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, `keys:
  - &alice age1eeun8x8xcetyknpx44a92vnf5tn9m7ukf5w8ex65xckyjuyenakqfvzztm
  - &bob age1u2fys28yezr6l0mh4ptuh2np5wl6zvu0en4ad4mx4tk59gy94a8q42qtfc

creation_rules:
  - path_regex: hosts/.*/remote\.sops\.yaml$
    key_groups:
      - age:
          - *alice
          - *bob
  - path_regex: unrelated-empty\.yaml$
    key_groups:
      - age: []
`)
	p, err := LoadSopsPolicy(dir)
	if err != nil {
		t.Fatalf("LoadSopsPolicy: %v", err)
	}
	// alice has a co-recipient (bob) in her only real rule — must
	// succeed despite the unrelated rule's already-empty age list.
	if _, err := p.RemoveRecipient("alice"); err != nil {
		t.Fatalf("RemoveRecipient(alice): unexpected error (unrelated empty rule should not block this): %v", err)
	}
}
