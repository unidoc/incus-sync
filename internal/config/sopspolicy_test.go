package config

import (
	"os"
	"path/filepath"
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
