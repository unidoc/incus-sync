package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// setupIsolatedEnv clears all three backends so each test exercises
// exactly the one it's testing.
func setupIsolatedEnv(t *testing.T) {
	t.Helper()
	for _, e := range []string{envSopsAgeKey, envSopsAgeKeyFile, envSopsAgeKeyCmd} {
		t.Setenv(e, "")
		os.Unsetenv(e)
	}
}

// The bulk of these tests call resolveAgeKey (not the exported
// EnsureUnlocked) so they can assert on exactly which bytes each
// backend produced — EnsureUnlocked itself has no consumer for that
// content (see its doc comment) and is covered separately below by
// TestEnsureUnlockedWrapsResolveAgeKey.

func TestResolveAgeKeyReadsSopsAgeKey(t *testing.T) {
	setupIsolatedEnv(t)
	t.Setenv(envSopsAgeKey, "AGE-SECRET-KEY-1DIRECTFAKE")

	got, err := resolveAgeKey()
	if err != nil {
		t.Fatalf("resolveAgeKey: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1DIRECTFAKE" {
		t.Fatalf("got %q", got)
	}
}

// TestResolveAgeKeyReadsSopsAgeKeyFile covers both a plain identity
// and, in spirit, an age plugin identity — incus-sync treats both
// identically, handing the file's bytes to SOPS unexamined.
func TestResolveAgeKeyReadsSopsAgeKeyFile(t *testing.T) {
	setupIsolatedEnv(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "identity.txt")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-1FILEFAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSopsAgeKeyFile, keyPath)

	got, err := resolveAgeKey()
	if err != nil {
		t.Fatalf("resolveAgeKey: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1FILEFAKE\n" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveAgeKeyPrefersSopsAgeKeyOverFile(t *testing.T) {
	setupIsolatedEnv(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "identity.txt")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-1FILEFAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSopsAgeKeyFile, keyPath)
	t.Setenv(envSopsAgeKey, "AGE-SECRET-KEY-1DIRECTFAKE")

	got, err := resolveAgeKey()
	if err != nil {
		t.Fatalf("resolveAgeKey: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1DIRECTFAKE" {
		t.Fatalf("SOPS_AGE_KEY should win over SOPS_AGE_KEY_FILE, got %q", got)
	}
}

// TestResolveAgeKeyRunsSopsAgeKeyCmd covers SOPS's own native
// SOPS_AGE_KEY_CMD var (github.com/getsops/sops/v3/age.SopsAgeKeyCmdEnv)
// — distinct from the incus-sync-specific INCUS_SYNC_AGE_KEY_CMD hook
// that was deliberately removed; this one is SOPS's, not a
// reinvention, so EnsureUnlocked has to recognize it or its own
// pre-check gate is stricter than what sops itself actually supports.
func TestResolveAgeKeyRunsSopsAgeKeyCmd(t *testing.T) {
	setupIsolatedEnv(t)
	t.Setenv(envSopsAgeKeyCmd, "echo AGE-SECRET-KEY-1CMDFAKE")

	got, err := resolveAgeKey()
	if err != nil {
		t.Fatalf("resolveAgeKey: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1CMDFAKE\n" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveAgeKeyPrefersFileOverCmd(t *testing.T) {
	setupIsolatedEnv(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "identity.txt")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-1FILEFAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSopsAgeKeyFile, keyPath)
	t.Setenv(envSopsAgeKeyCmd, "echo AGE-SECRET-KEY-1CMDFAKE")

	got, err := resolveAgeKey()
	if err != nil {
		t.Fatalf("resolveAgeKey: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1FILEFAKE\n" {
		t.Fatalf("SOPS_AGE_KEY_FILE should win over SOPS_AGE_KEY_CMD, got %q", got)
	}
}

func TestResolveAgeKeyErrorsWithNoBackendConfigured(t *testing.T) {
	setupIsolatedEnv(t)

	if _, err := resolveAgeKey(); err == nil {
		t.Fatal("resolveAgeKey() = nil error, want error when nothing is configured")
	}
}

func TestResolveAgeKeyErrorsOnMissingFile(t *testing.T) {
	setupIsolatedEnv(t)
	t.Setenv(envSopsAgeKeyFile, filepath.Join(t.TempDir(), "does-not-exist.txt"))

	if _, err := resolveAgeKey(); err == nil {
		t.Fatal("resolveAgeKey() = nil error, want error for a missing SOPS_AGE_KEY_FILE")
	}
}

// TestEnsureUnlockedWrapsResolveAgeKey covers the actual public
// surface: EnsureUnlocked returns only an error, no content.
func TestEnsureUnlockedWrapsResolveAgeKey(t *testing.T) {
	setupIsolatedEnv(t)
	if err := EnsureUnlocked(); err == nil {
		t.Fatal("EnsureUnlocked() = nil error, want error when nothing is configured")
	}

	t.Setenv(envSopsAgeKey, "AGE-SECRET-KEY-1DIRECTFAKE")
	if err := EnsureUnlocked(); err != nil {
		t.Fatalf("EnsureUnlocked() = %v, want nil once SOPS_AGE_KEY is set", err)
	}
}
