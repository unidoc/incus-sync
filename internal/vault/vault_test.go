package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// setupIsolatedEnv clears both backends so each test exercises exactly
// the one it's testing.
func setupIsolatedEnv(t *testing.T) {
	t.Helper()
	for _, e := range []string{envSopsAgeKey, envSopsAgeKeyFile} {
		t.Setenv(e, "")
		os.Unsetenv(e)
	}
}

func TestEnsureUnlockedReadsSopsAgeKey(t *testing.T) {
	setupIsolatedEnv(t)
	t.Setenv(envSopsAgeKey, "AGE-SECRET-KEY-1DIRECTFAKE")

	got, err := EnsureUnlocked()
	if err != nil {
		t.Fatalf("EnsureUnlocked: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1DIRECTFAKE" {
		t.Fatalf("got %q", got)
	}
}

// TestEnsureUnlockedReadsSopsAgeKeyFile covers both a plain identity
// and, in spirit, an age plugin identity — incus-sync treats both
// identically, handing the file's bytes to SOPS unexamined.
func TestEnsureUnlockedReadsSopsAgeKeyFile(t *testing.T) {
	setupIsolatedEnv(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "identity.txt")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-1FILEFAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSopsAgeKeyFile, keyPath)

	got, err := EnsureUnlocked()
	if err != nil {
		t.Fatalf("EnsureUnlocked: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1FILEFAKE\n" {
		t.Fatalf("got %q", got)
	}
}

func TestEnsureUnlockedPrefersSopsAgeKeyOverFile(t *testing.T) {
	setupIsolatedEnv(t)
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "identity.txt")
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-1FILEFAKE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSopsAgeKeyFile, keyPath)
	t.Setenv(envSopsAgeKey, "AGE-SECRET-KEY-1DIRECTFAKE")

	got, err := EnsureUnlocked()
	if err != nil {
		t.Fatalf("EnsureUnlocked: %v", err)
	}
	if string(got) != "AGE-SECRET-KEY-1DIRECTFAKE" {
		t.Fatalf("SOPS_AGE_KEY should win over SOPS_AGE_KEY_FILE, got %q", got)
	}
}

func TestEnsureUnlockedErrorsWithNoBackendConfigured(t *testing.T) {
	setupIsolatedEnv(t)

	if _, err := EnsureUnlocked(); err == nil {
		t.Fatal("EnsureUnlocked() = nil error, want error when nothing is configured")
	}
}

func TestEnsureUnlockedErrorsOnMissingFile(t *testing.T) {
	setupIsolatedEnv(t)
	t.Setenv(envSopsAgeKeyFile, filepath.Join(t.TempDir(), "does-not-exist.txt"))

	if _, err := EnsureUnlocked(); err == nil {
		t.Fatal("EnsureUnlocked() = nil error, want error for a missing SOPS_AGE_KEY_FILE")
	}
}
