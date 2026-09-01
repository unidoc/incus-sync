package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidNameRejectsInjectionShapes(t *testing.T) {
	bad := []string{
		"", "..", ".", "a/b", "a\\b",
		"a$(touch pwned)", "a`touch pwned`", "a;rm -rf",
		"UPPER", "-leading", "trailing-", "a--b", "1leading",
		strings.Repeat("a", 61),
	}
	for _, name := range bad {
		if err := validName(name); err == nil {
			t.Errorf("validName(%q) = nil, want error", name)
		}
	}
}

func TestValidNameAcceptsRealNames(t *testing.T) {
	good := []string{"unidoc-fleet", "custody-fleet", "a", "web1"}
	for _, name := range good {
		if err := validName(name); err != nil {
			t.Errorf("validName(%q) = %v, want nil", name, err)
		}
	}
}

// setupIsolatedEnv points every vault path function at a fresh temp
// dir for the duration of the test, and clears every env-based backend
// so EnsureUnlocked actually exercises the named-vault file backend
// instead of short-circuiting on SOPS_AGE_KEY etc.
func setupIsolatedEnv(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(tmp, "runtime"))
	t.Setenv("HOME", tmp)
	for _, e := range []string{envSopsAgeKey, envSopsAgeKeyFile, EnvKeyCmd, EnvOnePasswordRef} {
		t.Setenv(e, "")
		os.Unsetenv(e)
	}
}

// TestVaultsAreIsolatedByName is the isolation test the PR description
// claimed existed but didn't (caught in code review) — two named
// vaults, on the same machine, must never share a passphrase, a
// decrypted-cache file, or a lock() blast radius. This is the entire
// point of naming vaults per fleet.yaml — see the package doc.
func TestVaultsAreIsolatedByName(t *testing.T) {
	setupIsolatedEnv(t)
	tmp := t.TempDir()

	custodyKeyPath := filepath.Join(tmp, "custody-plain.txt")
	unidocKeyPath := filepath.Join(tmp, "unidoc-plain.txt")
	if err := os.WriteFile(custodyKeyPath, []byte("AGE-SECRET-KEY-1CUSTODYFAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unidocKeyPath, []byte("AGE-SECRET-KEY-1UNIDOCFAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Init("custody", custodyKeyPath, "custody-pass-123"); err != nil {
		t.Fatalf("Init(custody): %v", err)
	}
	if err := Init("unidoc", unidocKeyPath, "unidoc-pass-456"); err != nil {
		t.Fatalf("Init(unidoc): %v", err)
	}

	// 1. Paths must differ.
	if VaultPath("custody") == VaultPath("unidoc") {
		t.Fatalf("vault paths collide: %s", VaultPath("custody"))
	}

	// 2. Init shreds the plaintext source — confirms Init actually ran
	// against the file we gave it, not some cached state.
	if _, err := os.Stat(custodyKeyPath); !os.IsNotExist(err) {
		t.Error("custody plaintext source was not shredded after Init")
	}

	// 3. custody's vault must reject unidoc's passphrase — proves the
	// two are genuinely separately encrypted, not just separately
	// named files with the same key underneath.
	wrongPass := func(string) (string, error) { return "unidoc-pass-456", nil }
	if _, err := EnsureUnlocked("custody", wrongPass); err == nil {
		t.Fatal("custody vault decrypted with unidoc's passphrase — not isolated")
	}
	// EnsureUnlocked only sets SOPS_AGE_KEY on success, but be defensive.
	os.Unsetenv(envSopsAgeKey)

	// 4. Each unlocks correctly with its own passphrase.
	custodyPass := func(string) (string, error) { return "custody-pass-123", nil }
	got, err := EnsureUnlocked("custody", custodyPass)
	if err != nil {
		t.Fatalf("EnsureUnlocked(custody): %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1CUSTODYFAKE\n" {
		t.Fatalf("custody decrypted to wrong content: %q", got)
	}
	os.Unsetenv(envSopsAgeKey)

	unidocPass := func(string) (string, error) { return "unidoc-pass-456", nil }
	got, err = EnsureUnlocked("unidoc", unidocPass)
	if err != nil {
		t.Fatalf("EnsureUnlocked(unidoc): %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1UNIDOCFAKE\n" {
		t.Fatalf("unidoc decrypted to wrong content: %q", got)
	}
	os.Unsetenv(envSopsAgeKey)

	// 5. Cache isolation: Lock("custody") must not touch unidoc's still-
	// warm cache — unidoc must unlock again with NO prompt needed.
	if _, err := EnsureUnlocked("custody", custodyPass); err != nil {
		t.Fatalf("re-unlock custody: %v", err)
	}
	if err := Lock("custody"); err != nil {
		t.Fatalf("Lock(custody): %v", err)
	}
	os.Unsetenv(envSopsAgeKey)

	promptShouldNotBeCalled := func(string) (string, error) {
		t.Fatal("unidoc's cache was cleared by Lock(\"custody\") — not isolated")
		return "", nil
	}
	got, err = EnsureUnlocked("unidoc", promptShouldNotBeCalled)
	if err != nil {
		t.Fatalf("unidoc re-unlock after Lock(custody): %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1UNIDOCFAKE\n" {
		t.Fatalf("unidoc cache round-trip mismatch: %q", got)
	}
}
