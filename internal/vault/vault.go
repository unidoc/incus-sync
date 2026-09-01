// Package vault protects the age private key that decrypts every SOPS
// blob in a fleet repo. Without it, ~/.config/sops/age/keys.txt sits
// plaintext on the bastion; anyone with the operator's shell inherits
// full API access to every Incus host in the fleet.
//
// Vaults are named and independent. Every fleet.yaml declares a
// `name:` — two fleets with different names never share a passphrase,
// an ssh-agent-derived key, an unlocked-cache window, or even a
// directory on disk. An operator who works on both acme-fleet and
// acme2-fleet from the same laptop has two completely separate vaults;
// unlocking one never exposes the other, and compromising one's
// ciphertext never leaks the other's key. The
// name is deliberately NOT derived from the repo's checkout path — it
// travels with the repo (declared in git-tracked fleet.yaml) and is
// stable across re-clones, renamed directories, and other machines;
// the vault files themselves live under ~/.config, decoupled from
// wherever the repo happens to be checked out, so deleting or moving
// the repo checkout never orphans or duplicates a vault.
//
// Threat model:
//
//	Realistic: bastion account compromise via stolen ssh key, malicious
//	dependency in the shell environment, or leaked backup. We defend
//	against ALL three with passphrase-encryption-at-rest and TTL-limited
//	cache. We do NOT defend against a live attacker in the operator's
//	shell — same-user ptrace/mem access lets them read any decrypted
//	material, regardless of storage. That is a "don't get pwned" layer.
//
// Design:
//
//  1. Vault at rest: ~/.config/incus-sync/<name>/vault.age —
//     age-encrypted with an operator passphrase (scrypt KDF,
//     adjustable work factor).
//
//  2. Cache while unlocked: $XDG_RUNTIME_DIR/incus-sync/<name>/age.txt
//     (systemd-managed tmpfs on Linux). Fallback: ~/.cache/incus-sync/
//     <name>/vault-runtime/age.txt with mode 0600 — user should
//     mount tmpfs there if the machine is FreeBSD or non-systemd Linux.
//
//  3. TTL: unlocked_at + 4h hard expiry, plus 60min idle timeout since
//     last use (cache mtime). Either exceeded → re-prompt. Overridable
//     via INCUS_SYNC_VAULT_TTL and INCUS_SYNC_VAULT_IDLE (Go durations).
//
//  4. Auto-lock: at unlock time, spawn a detached process that sleeps
//     the hard TTL then shreds. Best-effort belt-and-suspenders — if
//     the process dies, the mtime check still refuses stale cache.
//
//  5. Never write the plaintext key to disk on a non-tmpfs path
//     without mode 0600 and an explicit warning.
package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/unidoc/incus-sync/internal/vault/sshagent"
)

// Defaults; overridable via environment.
const (
	defaultTTL         = 4 * time.Hour
	defaultIdleTimeout = 60 * time.Minute
	envTTL             = "INCUS_SYNC_VAULT_TTL"
	envIdle            = "INCUS_SYNC_VAULT_IDLE"
	envSopsAgeKey      = "SOPS_AGE_KEY"      // read by SOPS
	envSopsAgeKeyFile  = "SOPS_AGE_KEY_FILE" // read by SOPS

	// EnvKeyCmd names a shell command whose stdout is the plaintext
	// age key. Everything (session cache, biometric approval, TTL) is
	// deferred to whatever the command talks to. Ideal for 1Password,
	// pass, or any secret-manager CLI.
	//
	//   export INCUS_SYNC_AGE_KEY_CMD='op read op://Private/age-key/private-key'
	//   export INCUS_SYNC_AGE_KEY_CMD='pass age-key'
	//   export INCUS_SYNC_AGE_KEY_CMD='vault kv get -field=age secret/incus-sync'
	EnvKeyCmd = "INCUS_SYNC_AGE_KEY_CMD"

	// EnvOnePasswordRef is a shorthand: equivalent to
	//   INCUS_SYNC_AGE_KEY_CMD="op read <ref>"
	// so operators do not have to think about quoting.
	EnvOnePasswordRef = "INCUS_SYNC_AGE_1PASSWORD_REF"
)

// vaultNameRe matches config's checkBaseName rule (lowercase letters,
// digits, hyphens; starts with a letter; no leading/trailing/consecutive
// hyphens). Duplicated here rather than imported — this package must
// not depend on internal/config — but kept in sync deliberately.
var vaultNameRe = regexp.MustCompile(`^[a-z]([a-z0-9]+(-[a-z0-9]+)*)?$`)

// validName rejects anything that isn't a plain, predictable token —
// this runs even when the name came from a trusted fleet.yaml (already
// checked against config's stricter naming rules), because these
// functions are also reachable directly via `--vault <name>` on the
// CLI, bypassing that check. Deliberately as strict as fleet.yaml's own
// rule, not just "no path traversal": cachePath/VaultPath build a shell
// command line (scheduleAutoShred) from a name-derived path, so
// anything beyond [a-z0-9-] is rejected outright rather than trusted to
// be shell-safe.
func validName(name string) error {
	if name == "" {
		return fmt.Errorf("vault name is empty")
	}
	if len(name) > 60 || !vaultNameRe.MatchString(name) {
		return fmt.Errorf("vault name %q must match [a-z][a-z0-9-]*, start with a letter, no consecutive/trailing hyphens, max 60 chars", name)
	}
	return nil
}

// VaultPath is the encrypted-at-rest key location for the named vault.
func VaultPath(name string) string {
	return filepath.Join(configHome(), "incus-sync", name, "vault.age")
}

// PlaintextLegacyPath is where SOPS's own default lives — the file
// `vault init`/`vault ssh-init` migrate from when no --key is given.
// Global, not per-vault: it is a migration SOURCE (an existing
// operator setup predating any named vault), never a destination.
func PlaintextLegacyPath() string {
	return filepath.Join(configHome(), "sops", "age", "keys.txt")
}

// cachePath returns the runtime cache location for the named vault's
// decrypted key. Prefers $XDG_RUNTIME_DIR (systemd tmpfs on Linux)
// which is wiped on logout. Falls back to ~/.cache/incus-sync/<name>/
// vault-runtime/ with a note in the doc that tmpfs should be mounted
// there for stronger guarantees.
func cachePath(name string) string {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		return filepath.Join(v, "incus-sync", name, "age.txt")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "incus-sync", name, "vault-runtime", "age.txt")
}

// unlockedAtPath is a sidecar file holding the unix timestamp when the
// current cache was written. Used for hard-TTL comparison.
func unlockedAtPath(name string) string { return cachePath(name) + ".unlocked_at" }

// configHome returns $XDG_CONFIG_HOME or $HOME/.config.
func configHome() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}

// Status describes the current vault state for `vault status`.
type Status struct {
	Name         string        // the vault name this status describes
	InitDone     bool          // vault.age exists
	CachePresent bool          // cache file exists
	UnlockedAt   time.Time     // when the cache was written
	LastUsedAt   time.Time     // cache file mtime
	HardExpiry   time.Time     // UnlockedAt + TTL
	IdleExpiry   time.Time     // LastUsedAt + IdleTimeout
	Expired      bool          // stale by either measure
	CachePath    string        // for user-facing display
	VaultPath    string        // for user-facing display
	OnTmpfs      bool          // best-guess: cache is in $XDG_RUNTIME_DIR
	TTL          time.Duration // active hard TTL
	Idle         time.Duration // active idle timeout
}

// Read returns the current status for the named vault. Never mutates
// state.
func Read(name string) (Status, error) {
	if err := validName(name); err != nil {
		return Status{}, err
	}
	s := Status{
		Name:      name,
		CachePath: cachePath(name),
		VaultPath: VaultPath(name),
		OnTmpfs:   os.Getenv("XDG_RUNTIME_DIR") != "" && strings.HasPrefix(cachePath(name), os.Getenv("XDG_RUNTIME_DIR")),
		TTL:       parseDurationEnv(envTTL, defaultTTL),
		Idle:      parseDurationEnv(envIdle, defaultIdleTimeout),
	}
	if _, err := os.Stat(s.VaultPath); err == nil {
		s.InitDone = true
	}
	info, err := os.Stat(s.CachePath)
	if err != nil {
		return s, nil
	}
	s.CachePresent = true
	s.LastUsedAt = info.ModTime()
	if raw, err := os.ReadFile(unlockedAtPath(name)); err == nil {
		if ts, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			s.UnlockedAt = time.Unix(ts, 0)
		}
	}
	s.HardExpiry = s.UnlockedAt.Add(s.TTL)
	s.IdleExpiry = s.LastUsedAt.Add(s.Idle)
	now := time.Now()
	s.Expired = now.After(s.HardExpiry) || now.After(s.IdleExpiry)
	return s, nil
}

// EnsureUnlocked returns the plaintext age key bytes for the named
// vault (a fleet's fleet.yaml `name:` field — see the package doc for
// why vaults are named and independent). Backend selection, in order:
//
//  1. SOPS_AGE_KEY env already set — trust the caller, use as-is. NOT
//     name-scoped: an explicit operator override for the current shell,
//     same as SOPS itself would read. If you work multiple fleets in
//     one shell, scope this yourself (e.g. per-repo direnv) rather than
//     relying on incus-sync to do it for you.
//  2. INCUS_SYNC_AGE_KEY_CMD env set — exec the command, use stdout. This
//     is the 1Password / pass / vault-cli path: the external tool owns
//     session state, prompt, and TTL. Also not name-scoped, same caveat.
//  3. INCUS_SYNC_AGE_1PASSWORD_REF env set — shorthand for `op read <ref>`.
//     Same caveat as above.
//  4. Named ssh-agent-backed vault at
//     ~/.config/incus-sync/<name>/vault.ssh.
//  5. Named passphrase-encrypted vault at
//     ~/.config/incus-sync/<name>/vault.age — prompt if cache
//     missing/expired, decrypt with age scrypt.
//  6. Plaintext legacy at ~/.config/sops/age/keys.txt — deprecated,
//     global (pre-dates named vaults), supported so existing
//     single-fleet setups keep working during migration.
//
// Sets SOPS_AGE_KEY as a side effect so downstream sops.decrypt.Data
// calls pick up the key without further plumbing.
//
// prompt is called only for the passphrase-encrypted backend.
func EnsureUnlocked(name string, prompt func(msg string) (string, error)) ([]byte, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	if v := os.Getenv(envSopsAgeKey); v != "" {
		return []byte(v), nil
	}
	if cmd := os.Getenv(EnvKeyCmd); cmd != "" {
		return runKeyCmd(cmd)
	}
	if ref := os.Getenv(EnvOnePasswordRef); ref != "" {
		return runKeyCmd("op read " + shellEscape(ref))
	}
	// SSH-agent-backed vault: no key material on disk, only a
	// ciphertext blob. Every unlock requires a live SIGN from an
	// SSH agent that holds a recipient key — which in turn triggers
	// whatever approval flow the agent enforces (1P biometric,
	// YubiKey touch, etc.). See internal/vault/sshagent/ for the
	// scheme. Checked BEFORE the passphrase vault because operators
	// on the ssh-agent path have already opted into a stricter model.
	if _, err := os.Stat(sshagent.DefaultPath(name)); err == nil {
		return unlockSSHAgent(name)
	}

	if _, err := os.Stat(VaultPath(name)); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		// Legacy plaintext fallback so existing setups keep working
		// while the operator migrates to either backend. Global, not
		// name-scoped — see PlaintextLegacyPath.
		if raw, err := os.ReadFile(PlaintextLegacyPath()); err == nil {
			_ = os.Setenv(envSopsAgeKey, string(raw))
			return raw, nil
		}
		return nil, fmt.Errorf(
			"no age key backend configured for vault %q. Set %s or %s, or run "+
				"`incus-sync vault init` to create a passphrase vault. "+
				"(searched: env, %s, %s)",
			name, EnvKeyCmd, EnvOnePasswordRef, VaultPath(name), PlaintextLegacyPath())
	}

	// Try cache first.
	if key, ok := readValidCache(name); ok {
		_ = os.Setenv(envSopsAgeKey, string(key))
		bumpMTime(name)
		return key, nil
	}

	// Miss — prompt and decrypt.
	pass, err := prompt(fmt.Sprintf("Vault %q passphrase (Ctrl+C to cancel): ", name))
	if err != nil {
		return nil, err
	}
	if pass == "" {
		return nil, fmt.Errorf("empty passphrase")
	}
	key, err := decryptVault(name, pass)
	if err != nil {
		return nil, err
	}
	if err := writeCache(name, key); err != nil {
		return nil, fmt.Errorf("cache write: %w", err)
	}
	scheduleAutoShred(cachePath(name), unlockedAtPath(name), parseDurationEnv(envTTL, defaultTTL))
	_ = os.Setenv(envSopsAgeKey, string(key))
	return key, nil
}

// Init encrypts the plaintext key at path with the given passphrase and
// writes it to the named vault's VaultPath. Removes the plaintext
// original on success — leaving a plaintext key on disk after `vault
// init` would defeat the purpose entirely.
func Init(name, plaintextPath, passphrase string) error {
	if err := validName(name); err != nil {
		return err
	}
	if passphrase == "" {
		return fmt.Errorf("empty passphrase")
	}
	raw, err := os.ReadFile(plaintextPath)
	if err != nil {
		return fmt.Errorf("read plaintext: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("plaintext file %s is empty", plaintextPath)
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	// Bump the work factor from the age default (18) to 20 — ~1s to
	// decrypt on a modern laptop, prohibitive for offline attacks.
	recipient.SetWorkFactor(20)

	if err := os.MkdirAll(filepath.Dir(VaultPath(name)), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	tmp := VaultPath(name) + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, VaultPath(name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Shred the plaintext original.
	if err := shredFile(plaintextPath); err != nil {
		return fmt.Errorf("wrote %s but failed to shred plaintext original: %w", VaultPath(name), err)
	}
	return nil
}

// Lock immediately shreds the named vault's cached plaintext and its
// sidecar. Other vaults' caches are untouched.
func Lock(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	first := shredFile(cachePath(name))
	second := shredFile(unlockedAtPath(name))
	if first != nil && !errors.Is(first, os.ErrNotExist) {
		return first
	}
	if second != nil && !errors.Is(second, os.ErrNotExist) {
		return second
	}
	return nil
}

// readValidCache returns the named vault's cached key if it is present
// and within both hard TTL and idle timeout.
func readValidCache(name string) ([]byte, bool) {
	s, err := Read(name)
	if err != nil || !s.CachePresent || s.Expired {
		return nil, false
	}
	data, err := os.ReadFile(cachePath(name))
	if err != nil {
		return nil, false
	}
	return data, true
}

// bumpMTime marks the named vault's cache "just used" so the idle
// timeout resets.
func bumpMTime(name string) {
	now := time.Now()
	_ = os.Chtimes(cachePath(name), now, now)
}

// writeCache writes the decrypted key to the named vault's runtime
// cache with mode 0600 and records the unlock timestamp for hard-TTL
// enforcement.
func writeCache(name string, key []byte) error {
	dir := filepath.Dir(cachePath(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := cachePath(name) + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, cachePath(name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.WriteFile(unlockedAtPath(name), []byte(stamp), 0o600); err != nil {
		return err
	}
	return nil
}

// decryptVault reads the named vault's VaultPath and decrypts with the
// passphrase.
func decryptVault(name, passphrase string) ([]byte, error) {
	f, err := os.Open(VaultPath(name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(f, identity)
	if err != nil {
		return nil, fmt.Errorf("decrypt (wrong passphrase?): %w", err)
	}
	return io.ReadAll(r)
}

// unlockSSHAgent loads the named ssh-agent vault, connects to the
// agent, and returns the decrypted age key. Sets SOPS_AGE_KEY as a
// side effect. Any failure surfaces a clear message pointing the
// operator at the likely cause (agent not forwarded, key not loaded).
func unlockSSHAgent(name string) ([]byte, error) {
	f, err := sshagent.Load(sshagent.DefaultPath(name))
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, fmt.Errorf("ssh-agent vault at %s vanished mid-flight", sshagent.DefaultPath(name))
	}
	c, err := sshagent.Dial()
	if err != nil {
		return nil, fmt.Errorf(
			"ssh-agent unreachable: %w. If you SSH'd in, ensure ForwardAgent yes "+
				"and that SSH_AUTH_SOCK is populated (echo $SSH_AUTH_SOCK). If not, "+
				"reconnect with `ssh -A <user>@%s`",
			err, mustHostname())
	}
	defer c.Close()
	plaintext, err := sshagent.Unlock(c, f)
	if err != nil {
		return nil, err
	}
	_ = os.Setenv(envSopsAgeKey, string(plaintext))
	return plaintext, nil
}

// mustHostname returns the local hostname, or "<this-host>" if
// resolution fails. Used only in error messages.
func mustHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "<this-host>"
	}
	return h
}

// runKeyCmd exec's a shell command whose stdout is the plaintext age
// key. Stdin/stderr are inherited from the parent so any interactive
// prompt (1Password biometric approval, master password, TouchID) can
// reach the user. On success, SOPS_AGE_KEY is set so downstream SOPS
// calls pick up the key.
//
// No local caching: the external command is expected to own its own
// session/TTL. `op` for example caches sessions per shell for a
// configurable duration; each subsequent invocation is silent until
// the session expires.
func runKeyCmd(cmdline string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", cmdline)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s command failed (%q): %w", EnvKeyCmd, cmdline, err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("%s command produced empty output", EnvKeyCmd)
	}
	_ = os.Setenv(envSopsAgeKey, string(out))
	return out, nil
}

// shellEscape wraps a value in single quotes for safe sh -c inclusion.
// Only used for the 1Password ref shorthand where the value is a URL
// like op://vault/item/field — quoting keeps colons and slashes literal
// and defends against a malicious ref containing shell metacharacters.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// scheduleAutoShred forks a detached process that sleeps ttl then
// shreds the cache. Best-effort — if the process is killed, the
// TTL check on next use still refuses stale material.
func scheduleAutoShred(cache, sidecar string, ttl time.Duration) {
	// cache/sidecar are passed as positional args ($1/$2), never
	// interpolated into the script text — sh -c's double-quoted %q
	// form does NOT stop $(...) / `...` from being interpreted by the
	// shell, so a name-derived path containing either would otherwise
	// be a command-injection vector reachable via `--vault <name>`.
	// validName() already rejects such names, but this is the belt to
	// its suspenders: correct even if that check ever regresses.
	const script = `sleep "$1"; shred -u "$2" "$3" 2>/dev/null || rm -f "$2" "$3"`
	cmd := exec.Command("sh", "-c", script, "sh", strconv.Itoa(int(ttl.Seconds())), cache, sidecar)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
}

// shredFile runs `shred -u <path>` if available, else falls back to
// os.Remove. Missing file is not an error.
func shredFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if _, err := exec.LookPath("shred"); err == nil {
		if err := exec.Command("shred", "-u", path).Run(); err == nil {
			return nil
		}
	}
	return os.Remove(path)
}

// parseDurationEnv reads a Go duration from the environment variable,
// falling back to def on empty or parse error.
func parseDurationEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
