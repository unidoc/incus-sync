package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3/decrypt"
	"gopkg.in/yaml.v3"

	"github.com/unidoc/incus-sync/internal/vault"
)

// SecretsPath returns the fleet-wide secrets file path. Optional —
// callers accept "no such file" as "no secrets defined".
func SecretsPath(configDir string) string {
	return filepath.Join(configDir, "shared", "secrets.sops.yaml")
}

// LoadSecrets reads shared/secrets.sops.yaml and returns its decoded
// map. Handles both encrypted (with SOPS metadata) and plaintext
// (during initial editing) forms.
//
// Returns an empty map (not nil) if the file does not exist so
// callers can treat "no secrets" as a valid state.
//
// Requires the vault to be unlocked — the caller should have called
// vault.EnsureUnlocked() first so SOPS_AGE_KEY is populated.
func LoadSecrets(configDir string) (map[string]any, error) {
	path := SecretsPath(configDir)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	// Detect SOPS-encrypted content by presence of the sops metadata
	// block. Not perfect but avoids requiring SOPS for a plaintext
	// scaffold during initial `sops <file>` editing.
	if bytes.Contains(raw, []byte("\nsops:\n")) || bytes.Contains(raw, []byte("sops:\n")) {
		meta, err := LoadFleetMeta(configDir)
		if err != nil {
			return nil, fmt.Errorf("determine vault for %s: %w", path, err)
		}
		// Ensure vault is unlocked before SOPS decrypt (populates
		// SOPS_AGE_KEY env). Idempotent: if a remote has already
		// unlocked in this process, this is a cache hit.
		if _, err := vault.EnsureUnlocked(meta.Name, promptFallback); err != nil {
			return nil, fmt.Errorf("unlock vault %q to decrypt %s: %w", meta.Name, path, err)
		}
		raw, err = decrypt.Data(raw, "yaml")
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", path, err)
		}
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m == nil {
		return map[string]any{}, nil
	}
	return m, nil
}

// promptFallback is a minimal passphrase prompt used only if the vault
// happens to be passphrase-encrypted AND unset. For ssh-agent or 1P
// backends this path is never hit (EnsureUnlocked returns immediately).
// Kept intentionally awkward — operators should already have their
// preferred backend wired up via env vars long before secrets are
// touched at sync time.
func promptFallback(msg string) (string, error) {
	return "", fmt.Errorf("passphrase prompt required but no TTY handler bound; run `incus-sync doctor --host <h>` first to unlock the vault interactively")
}

// LoadSecretsStructure returns the KEY structure of shared/secrets.sops.yaml
// WITHOUT decrypting any value. Used by `validate` to cross-check that
// every template's declared `secrets.from` path actually exists as a
// key path in the file — no vault unlock, no SOPS invocation.
//
// SOPS encrypts VALUES; the YAML key structure stays plaintext, so a
// plain YAML unmarshal reveals the full path tree. The `sops:`
// metadata section is stripped since it is not a user secret.
//
// Returns an empty map if the file does not exist.
func LoadSecretsStructure(configDir string) (map[string]any, error) {
	path := SecretsPath(configDir)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m == nil {
		return map[string]any{}, nil
	}
	delete(m, "sops")
	return m, nil
}

// SecretPathExists reports whether a dotted path resolves to any leaf
// value in the given (possibly-still-encrypted) structure. The value
// may be an encrypted string, a plaintext string, or a nested map —
// presence at the terminal path is all we assert here.
//
// Returns false if any segment along the path is missing or if an
// intermediate segment is not a mapping.
func SecretPathExists(secrets map[string]any, path string) bool {
	if path == "" {
		return false
	}
	parts := strings.Split(path, ".")
	var cur any = secrets
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		v, ok := m[p]
		if !ok {
			return false
		}
		cur = v
	}
	return true
}

// LookupSecret returns the string at dotted path in the secrets map.
// Example: LookupSecret(s, "alice.password_hash") returns
// s["alice"]["password_hash"] cast to string.
//
// Fails cleanly if the path is missing OR the terminal value is not a
// string — secrets are always leaf strings by contract, never nested
// structures at reference sites.
func LookupSecret(secrets map[string]any, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty secret path")
	}
	parts := strings.Split(path, ".")
	var cur any = secrets
	for i, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("secret %q: %s is not a mapping",
				path, strings.Join(parts[:i], "."))
		}
		v, ok := m[p]
		if !ok {
			return "", fmt.Errorf("secret %q: missing at %s", path,
				strings.Join(parts[:i+1], "."))
		}
		cur = v
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("secret %q: value is not a string (got %T)", path, cur)
	}
	return s, nil
}
