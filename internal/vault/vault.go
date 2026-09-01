// Package vault resolves the AGE private key material SOPS needs to
// decrypt every secrets file in a fleet repo.
//
// incus-sync implements no secret-retrieval mechanism of its own —
// no custom vault format, no cache, no command hook, nothing
// incus-sync-specific. It reads exactly SOPS's own two native env
// vars and nothing else:
//
//   - SOPS_AGE_KEY — the key content itself, already set.
//   - SOPS_AGE_KEY_FILE — path to an identity file. This can hold a
//     plain age identity, or an AGE PLUGIN identity line
//     (AGE-PLUGIN-<NAME>-1...) for hardware/agent/secret-manager-
//     backed protection with zero key material at rest anywhere.
//     SOPS itself (via filippo.io/age's plugin support, vendored
//     since sops v3.8+) resolves plugin identities transparently by
//     shelling out to the matching age-plugin-* binary on PATH —
//     incus-sync needs no plugin-specific code at all to support any
//     of them. A file may hold several lines (plain and/or plugin);
//     age/SOPS tries each in turn.
//
// This is the whole contract: every secret-manager integration is an
// age plugin, chosen and trusted entirely by the operator — incus-sync
// names none and depends on none. See README.md's Auth section.
//
// Multi-recipient access (several people, several keys) is entirely
// SOPS/age's own native mechanism, not incus-sync's: list every
// recipient's age public key in .sops.yaml and run `sops updatekeys`.
// `incus-sync vault add-recipient` / `remove-recipient` /
// `list-recipients` (see cmd_vault.go) are a thin convenience layer
// over exactly that edit-and-updatekeys workflow — they hold no
// secret material and perform no cryptography of their own.
package vault

import (
	"fmt"
	"os"
)

const (
	envSopsAgeKey     = "SOPS_AGE_KEY"      // read by SOPS
	envSopsAgeKeyFile = "SOPS_AGE_KEY_FILE" // read by SOPS
)

// EnsureUnlocked returns the age key material SOPS should use:
// SOPS_AGE_KEY if set, else the contents of SOPS_AGE_KEY_FILE. Sets
// SOPS_AGE_KEY as a side effect so downstream sops.decrypt.Data calls
// pick it up without further plumbing.
func EnsureUnlocked() ([]byte, error) {
	if v := os.Getenv(envSopsAgeKey); v != "" {
		return []byte(v), nil
	}
	if p := os.Getenv(envSopsAgeKeyFile); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s=%s: %w", envSopsAgeKeyFile, p, err)
		}
		return raw, nil
	}
	return nil, fmt.Errorf(
		"no age key resolvable. Set one of:\n"+
			"  %s       (key content directly)\n"+
			"  %s  (path to a plain age identity, or an age-plugin-* identity —\n"+
			"                     see README.md's Auth section for available plugins)",
		envSopsAgeKey, envSopsAgeKeyFile)
}
