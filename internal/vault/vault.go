// Package vault resolves the AGE private key material SOPS needs to
// decrypt every secrets file in a fleet repo.
//
// incus-sync implements no secret-retrieval mechanism of its own — no
// custom vault format, no cache, no incus-sync-specific command hook,
// no bespoke fallback. EnsureUnlocked pre-checks exactly three of
// SOPS's own native env vars, in the same order the vendored sops
// library itself tries them:
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
//   - SOPS_AGE_KEY_CMD — a shell command whose stdout is the key.
//     This is SOPS's OWN native var (github.com/getsops/sops/v3/age,
//     SopsAgeKeyCmdEnv) — not a reinvention, so it belongs in this
//     same list. It receives SOPS_AGE_KEY_RECIPIENT in its
//     environment (the recipient the file was encrypted to), so a
//     single command can serve several recipients.
//
// This is the whole contract: every secret-manager integration is an
// age plugin (via SOPS_AGE_KEY_FILE) or an arbitrary command (via
// SOPS_AGE_KEY_CMD) — both SOPS's own mechanisms, chosen and trusted
// entirely by the operator. incus-sync names no specific plugin or
// command and depends on none. See README.md's Auth section.
//
// One honesty note: this package's pre-check is stricter than what
// the sops library actually does once decrypt.Data runs. Regardless
// of which of the three vars above is set, sops ALSO unconditionally
// tries its own default identity file
// ($XDG_CONFIG_HOME-or-~/.config/sops/age/keys.txt) if one exists —
// that is baked into the vendored library
// (age.MasterKey.loadIdentities), not something incus-sync can
// suppress without patching sops itself. EnsureUnlocked deliberately
// does NOT bless that default path as one of its own recognized
// backends — an operator relying on it alone gets a clear
// "no age key resolvable" from incus-sync even though a bare
// `sops -d` would succeed — because failing loud on an unconfigured,
// easy-to-forget implicit file beats silently succeeding via it. Set
// SOPS_AGE_KEY_FILE explicitly, even if it points at that same
// conventional path.
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
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

const (
	envSopsAgeKey     = "SOPS_AGE_KEY"      // read by SOPS
	envSopsAgeKeyFile = "SOPS_AGE_KEY_FILE" // read by SOPS
	envSopsAgeKeyCmd  = "SOPS_AGE_KEY_CMD"  // read by SOPS (SopsAgeKeyCmdEnv)
)

// EnsureUnlocked verifies that SOPS will be able to resolve an age
// identity, so callers can fail early with a clear message instead of
// at decrypt time. It deliberately does NOT re-export SOPS_AGE_KEY or
// return the resolved bytes for a caller to thread through: SOPS
// reads all three env vars itself when decrypt.Data actually runs, and
// a plugin identity line is not usable as raw SOPS_AGE_KEY content
// anyway, so there is nothing safe or useful to hand back.
func EnsureUnlocked() error {
	_, err := resolveAgeKey()
	return err
}

// resolveAgeKey is EnsureUnlocked's actual implementation. Kept
// separate — and returning the resolved bytes — purely so tests can
// assert on which backend actually produced them; production code has
// no remaining use for the content itself, see EnsureUnlocked's doc.
func resolveAgeKey() ([]byte, error) {
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
	if cmdline := os.Getenv(envSopsAgeKeyCmd); cmdline != "" {
		cmd := exec.Command("sh", "-c", cmdline)
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("%s command failed (%q): %w", envSopsAgeKeyCmd, cmdline, err)
		}
		if len(bytes.TrimSpace(out)) == 0 {
			return nil, fmt.Errorf("%s command produced empty output", envSopsAgeKeyCmd)
		}
		return out, nil
	}
	return nil, fmt.Errorf(
		"no age key resolvable. Set one of:\n"+
			"  %s      (key content directly)\n"+
			"  %s (path to a plain age identity, or an age-plugin-* identity)\n"+
			"  %s  (a command that prints the key)\n"+
			"See README.md's Auth section.",
		envSopsAgeKey, envSopsAgeKeyFile, envSopsAgeKeyCmd)
}
