package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/vault"
	"github.com/unidoc/incus-sync/internal/vault/sshagent"
)

// vaultNameFlag overrides the vault name normally read from the
// resolved fleet.yaml's `name:` field — for operating on a vault
// before its fleet repo is even cloned locally (e.g. provisioning a
// new laptop with vaults for several fleets up front).
var vaultNameFlag string

// resolveVaultName returns --vault if given, else the `name:` value
// declared in the resolved config dir's fleet.yaml. Every vault
// subcommand goes through this so two fleets' vaults never collide —
// see internal/vault's package doc.
func resolveVaultName() (string, error) {
	if vaultNameFlag != "" {
		return vaultNameFlag, nil
	}
	meta, err := config.LoadFleetMeta(configDir)
	if err != nil {
		return "", fmt.Errorf("%w (or pass --vault <name> to operate without a fleet.yaml)", err)
	}
	return meta.Name, nil
}

// vaultCmd groups vault-management subcommands. Unlock is implicit:
// any command that needs to decrypt a remote.sops.yaml auto-prompts
// if the cache is missing or expired. Explicit `unlock` would be
// redundant.
func vaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage the age vault that decrypts SOPS remotes",
		Long: `The age private key that decrypts every hosts/<h>/remote.sops.yaml
in the fleet is the crown jewel of the bastion: whoever holds it can
talk to every Incus host in the fleet as a trusted client.

Vaults are named (fleet.yaml's ` + "`name:`" + ` field) and completely
independent — two fleets never share a passphrase, an ssh-agent-derived
key, or an unlocked-cache window, even on the same operator machine.
incus-sync stores each one encrypted at rest with a passphrase
(vault.age), decrypts on demand into a runtime cache with a hard TTL
and idle timeout, and re-prompts when the cache expires.

Locations (per vault name):
  ~/.config/incus-sync/<name>/vault.age            encrypted-at-rest (age scrypt)
  $XDG_RUNTIME_DIR/incus-sync/<name>/age.txt        runtime cache (systemd tmpfs)
  ~/.cache/incus-sync/<name>/vault-runtime/age.txt  fallback if no XDG_RUNTIME_DIR

The name defaults to the ` + "`name:`" + ` field in the fleet.yaml at
--config-dir / $INCUS_SYNC_FLEET_PATH / cwd; override with --vault.

Defaults (overridable via INCUS_SYNC_VAULT_TTL / INCUS_SYNC_VAULT_IDLE):
  hard TTL:      4h since first unlock
  idle timeout: 60m since last use`,
	}
	cmd.PersistentFlags().StringVar(&vaultNameFlag, "vault", "",
		"Vault name (default: the `name:` field in this fleet's fleet.yaml)")
	cmd.AddCommand(
		vaultInitCmd(),
		vaultStatusCmd(),
		vaultLockCmd(),
		vaultSSHInitCmd(),
		vaultSSHAddKeyCmd(),
		vaultSSHRemoveKeyCmd(),
		vaultSSHRotateCmd(),
		vaultSSHListKeysCmd(),
	)
	return cmd
}

// vaultSSHInitCmd creates a new ssh-agent-backed vault.
func vaultSSHInitCmd() *cobra.Command {
	var (
		plaintextPath string
		fingerprint   string
	)
	cmd := &cobra.Command{
		Use:   "ssh-init",
		Short: "Create an ssh-agent-backed vault (no key material on disk)",
		Long: `Reads the current plaintext age key from ONE of these sources
(in order) and encrypts it with a symmetric key derived from an
ssh-agent SIGN operation:

  1. --key <path>           file path (use "-" for stdin)
  2. INCUS_SYNC_AGE_KEY_CMD    env: command whose stdout is the key
  3. INCUS_SYNC_AGE_1PASSWORD_REF env: shorthand for ` + "`op read <ref>`" + `
  4. ~/.config/sops/age/keys.txt   legacy plaintext file

The point of the ordering is: whichever backend you use TODAY to get
the age key at runtime, ssh-init can use it as the source. After
ssh-init succeeds, unset those env vars — the ssh-agent vault takes
over as the higher-priority backend.

Only ssh-ed25519 keys are accepted — deterministic signatures are
required for reproducible decryption. Requires SSH_AUTH_SOCK — SSH
in with ` + "`ForwardAgent yes`" + ` from a laptop where 1Password (or
another confirmation-enforcing agent) holds the key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			target := sshagent.DefaultPath(name)
			if _, err := os.Stat(target); err == nil {
				return fmt.Errorf("%s already exists — rm it or use `vault ssh-rotate` if you want to re-init", target)
			}
			plaintext, source, err := readPlaintextAgeKey(plaintextPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Read %d bytes of age key material from %s.\n", len(plaintext), source)
			c, err := sshagent.Dial()
			if err != nil {
				return err
			}
			defer c.Close()

			key, err := pickAgentKey(c, fingerprint)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Signing test challenge twice to verify determinism...\n")
			f, err := sshagent.Init(c, key, plaintext)
			if err != nil {
				return err
			}
			if err := sshagent.Save(target, f); err != nil {
				return err
			}
			fmt.Printf("Wrote %s\n", target)
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "IMPORTANT — security-critical assumption:")
			fmt.Fprintln(os.Stderr, "  The ssh-agent holding this key MUST prompt for confirmation on")
			fmt.Fprintln(os.Stderr, "  every SIGN operation. This vault protects against 'attacker stole")
			fmt.Fprintln(os.Stderr, "  the ciphertext'; it does NOT protect against 'attacker can invoke")
			fmt.Fprintln(os.Stderr, "  SIGN via a silent ssh-agent' — that is functionally the same as")
			fmt.Fprintln(os.Stderr, "  handing them the plaintext age key.")
			fmt.Fprintln(os.Stderr, "  Verified agent flows:")
			fmt.Fprintln(os.Stderr, "    - 1Password SSH agent (biometric prompt per SIGN)")
			fmt.Fprintln(os.Stderr, "    - Keys loaded via `ssh-add -c` (per-op confirmation)")
			fmt.Fprintln(os.Stderr, "    - YubiKey via piv-agent / gpg-agent with touch policy")
			fmt.Fprintln(os.Stderr)

			// Shred plaintext-on-disk source if that's where it came from.
			// (Not applicable when source was stdin / env-var command.)
			if plaintextPath != "" && plaintextPath != "-" {
				if err := shredIfExists(plaintextPath); err == nil {
					fmt.Printf("Shredded plaintext original %s\n", plaintextPath)
				}
			} else if source == "~/.config/sops/age/keys.txt (legacy)" {
				if err := shredIfExists(vault.PlaintextLegacyPath()); err == nil {
					fmt.Printf("Shredded plaintext original %s\n", vault.PlaintextLegacyPath())
				}
			}
			fmt.Println()
			fmt.Println("Vault protected by:")
			fmt.Printf("  %s  (%s)\n", f.Recipients[0].Fingerprint, f.Recipients[0].Comment)
			fmt.Println()
			fmt.Println("Next step: unset any lingering age-key env vars so the ssh-agent vault takes over.")
			fmt.Println("  unset INCUS_SYNC_AGE_1PASSWORD_REF INCUS_SYNC_AGE_KEY_CMD SOPS_AGE_KEY")
			fmt.Println("  # then remove them from ~/.bashrc")
			fmt.Println()
			fmt.Println("Add more recipients (e.g. backup key on another YubiKey) with:")
			fmt.Println("  incus-sync vault ssh-add-key")
			return nil
		},
	}
	cmd.Flags().StringVar(&plaintextPath, "key", "", "Age key source: file path, `-` for stdin, or empty to try env vars (see --help)")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "SHA256 fingerprint of the ssh key to use (default: prompt)")
	return cmd
}

// readPlaintextAgeKey resolves the age key material from the operator's
// preferred source. Order:
//
//	--key <path>                   (path or "-" for stdin)
//	INCUS_SYNC_AGE_KEY_CMD env var    (arbitrary shell command)
//	INCUS_SYNC_AGE_1PASSWORD_REF env  (shorthand for `op read`)
//	~/.config/sops/age/keys.txt    (legacy plaintext)
//
// Returns the plaintext bytes and a human-readable description of the
// source (for the "Read N bytes from X" status line).
func readPlaintextAgeKey(pathFlag string) ([]byte, string, error) {
	if pathFlag == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, "", fmt.Errorf("read stdin: %w", err)
		}
		return b, "stdin", nil
	}
	if pathFlag != "" {
		b, err := os.ReadFile(pathFlag)
		if err != nil {
			return nil, "", fmt.Errorf("read %s: %w", pathFlag, err)
		}
		return b, pathFlag, nil
	}
	if cmdline := os.Getenv(vault.EnvKeyCmd); cmdline != "" {
		b, err := runShellCapture(cmdline)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", vault.EnvKeyCmd, err)
		}
		return b, fmt.Sprintf("$%s (%q)", vault.EnvKeyCmd, cmdline), nil
	}
	if ref := os.Getenv(vault.EnvOnePasswordRef); ref != "" {
		b, err := runShellCapture("op read " + shellEscape(ref))
		if err != nil {
			return nil, "", fmt.Errorf("op read %s: %w", ref, err)
		}
		return b, fmt.Sprintf("1Password %s", ref), nil
	}
	legacy := vault.PlaintextLegacyPath()
	if b, err := os.ReadFile(legacy); err == nil {
		return b, "~/.config/sops/age/keys.txt (legacy)", nil
	}
	return nil, "", fmt.Errorf(
		"no age key source configured. Provide one of:\n"+
			"  --key <path> (or `-` for stdin: `op read ... | %s vault ssh-init --key -`)\n"+
			"  export INCUS_SYNC_AGE_KEY_CMD='...'   (any command that prints the key)\n"+
			"  export INCUS_SYNC_AGE_1PASSWORD_REF='op://vault/item/field'\n"+
			"  place plaintext at %s", os.Args[0], legacy)
}

// runShellCapture is a small `sh -c` runner that returns stdout,
// forwarding stderr so 1P prompts (or other interactive UX) reach
// the user.
func runShellCapture(cmdline string) ([]byte, error) {
	c := exec.Command("sh", "-c", cmdline)
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	return c.Output()
}

// shellEscape single-quotes a value for safe sh -c interpolation.
// Duplicate of the helper in internal/vault — inlined here to avoid
// exporting it.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func vaultSSHAddKeyCmd() *cobra.Command {
	var fingerprint string
	cmd := &cobra.Command{
		Use:   "ssh-add-key",
		Short: "Wrap the vault DEK for an additional ssh key",
		Long: `Adds a new recipient to the ssh-agent vault. Requires that at
least one existing recipient's key is currently in the agent, so the
current DEK can be recovered and re-wrapped for the new key.

Common use case: register a backup YubiKey alongside the primary.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			target := sshagent.DefaultPath(name)
			f, err := sshagent.Load(target)
			if err != nil {
				return err
			}
			if f == nil {
				return fmt.Errorf("no vault at %s — run `vault ssh-init` first", target)
			}
			c, err := sshagent.Dial()
			if err != nil {
				return err
			}
			defer c.Close()
			key, err := pickAgentKey(c, fingerprint)
			if err != nil {
				return err
			}
			nf, err := sshagent.AddKey(c, f, key)
			if err != nil {
				return err
			}
			if err := sshagent.Save(target, nf); err != nil {
				return err
			}
			fmt.Printf("Added recipient %s (%s) to %s\n",
				nf.Recipients[len(nf.Recipients)-1].Fingerprint,
				nf.Recipients[len(nf.Recipients)-1].Comment, target)
			return nil
		},
	}
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "SHA256 fingerprint of key to add (default: prompt)")
	return cmd
}

func vaultSSHRemoveKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-remove-key <fingerprint>",
		Short: "Remove a recipient and rotate the DEK (real revocation)",
		Long: `Removes a recipient from the vault AND rotates the data-encryption
key + re-encrypts the age key. Without rotation, removal is theatre —
the removed key + a cached vault copy could still decrypt.

Requires every REMAINING recipient's key to be in the ssh-agent, so
we can re-wrap the new DEK for each. Refuses to remove the sole
recipient (would lock everyone out).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			target := sshagent.DefaultPath(name)
			f, err := sshagent.Load(target)
			if err != nil {
				return err
			}
			if f == nil {
				return fmt.Errorf("no vault at %s", target)
			}
			c, err := sshagent.Dial()
			if err != nil {
				return err
			}
			defer c.Close()
			nf, err := sshagent.RemoveKey(c, f, args[0])
			if err != nil {
				return err
			}
			if err := sshagent.Save(target, nf); err != nil {
				return err
			}
			fmt.Printf("Removed %s. DEK rotated; vault re-encrypted for %d recipient(s).\n", args[0], len(nf.Recipients))
			return nil
		},
	}
}

func vaultSSHRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-rotate",
		Short: "Rotate the DEK, re-wrap for all current recipients",
		Long: `Generates a new data-encryption key and re-encrypts the age key.
Every existing recipient's ssh key must be present in the ssh-agent
(otherwise we would silently drop them). Useful after a suspected
exposure of a vault ciphertext or on a routine cadence.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			target := sshagent.DefaultPath(name)
			f, err := sshagent.Load(target)
			if err != nil {
				return err
			}
			if f == nil {
				return fmt.Errorf("no vault at %s", target)
			}
			c, err := sshagent.Dial()
			if err != nil {
				return err
			}
			defer c.Close()
			nf, err := sshagent.Rotate(c, f)
			if err != nil {
				return err
			}
			if err := sshagent.Save(target, nf); err != nil {
				return err
			}
			fmt.Printf("Rotated DEK; %d recipient(s) preserved.\n", len(nf.Recipients))
			return nil
		},
	}
}

func vaultSSHListKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-list-keys",
		Short: "List recipients authorised to unlock the ssh-agent vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			target := sshagent.DefaultPath(name)
			f, err := sshagent.Load(target)
			if err != nil {
				return err
			}
			if f == nil {
				fmt.Printf("No ssh-agent vault at %s\n", target)
				return nil
			}
			// Note which recipients are currently loaded so operator sees
			// at a glance whether they can unlock right now.
			var loaded map[string]bool
			if c, err := sshagent.Dial(); err == nil {
				defer c.Close()
				if keys, err := c.List(); err == nil {
					loaded = map[string]bool{}
					for _, k := range keys {
						loaded[sshagent.Fingerprint(k)] = true
					}
				}
			}
			fmt.Printf("Vault: %s\n", target)
			fmt.Printf("Recipients (%d):\n", len(f.Recipients))
			for i, r := range f.Recipients {
				marker := " "
				if loaded != nil && loaded[r.Fingerprint] {
					marker = "✓"
				}
				comment := r.Comment
				if comment == "" {
					comment = "(no comment)"
				}
				fmt.Printf("  %s %d. %s   %s\n", marker, i+1, r.Fingerprint, comment)
			}
			if loaded == nil {
				fmt.Println("\n(ssh-agent not reachable — cannot check which keys are currently loaded)")
			} else {
				fmt.Println("\n✓ = currently loaded in ssh-agent (can unlock now)")
			}
			return nil
		},
	}
}

// pickAgentKey resolves an ed25519 key from the ssh-agent by
// fingerprint. If fingerprint is empty and stdin is a TTY, presents
// a numbered menu.
func pickAgentKey(c sshagent.Client, fingerprint string) (*agent.Key, error) {
	keys, err := c.List()
	if err != nil {
		return nil, err
	}
	var eligible []*agent.Key
	for _, k := range keys {
		if k.Type() == sshagent.KeyAlgoEd25519 {
			eligible = append(eligible, k)
		}
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no ssh-ed25519 keys in agent (only ed25519 is supported — RSA/ECDSA/sk-ed25519 sign non-deterministically)")
	}
	fpOf := func(k *agent.Key) string {
		p, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			return "<unparseable>"
		}
		return sshagent.Fingerprint(p)
	}
	if fingerprint != "" {
		for _, k := range eligible {
			if fpOf(k) == fingerprint {
				return k, nil
			}
		}
		return nil, fmt.Errorf("no ed25519 key in agent with fingerprint %s", fingerprint)
	}
	if len(eligible) == 1 {
		fmt.Fprintf(os.Stderr, "Using only ed25519 key in agent: %s (%s)\n", fpOf(eligible[0]), eligible[0].Comment)
		return eligible[0], nil
	}
	fmt.Fprintln(os.Stderr, "Available ssh-ed25519 keys:")
	for i, k := range eligible {
		fmt.Fprintf(os.Stderr, "  %d. %s  %s\n", i+1, fpOf(k), k.Comment)
	}
	fmt.Fprint(os.Stderr, "Select (1..N): ")
	var line string
	if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
		return nil, err
	}
	line = strings.TrimSpace(line)
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(eligible) {
		return nil, fmt.Errorf("invalid selection %q", line)
	}
	return eligible[n-1], nil
}

// shredIfExists best-effort shreds a path. Missing file is not an
// error.
func shredIfExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.Remove(path)
}

func vaultInitCmd() *cobra.Command {
	var plaintextPath string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Encrypt an existing plaintext age key at rest with a passphrase",
		Long: `Reads a plaintext age key file (default: SOPS's own
~/.config/sops/age/keys.txt), prompts twice for a passphrase, writes
the encrypted result to ~/.config/incus-sync/<name>/vault.age,
and shreds the plaintext original.

Refuses to run if vault.age already exists — pass --force after backing
it up first.

The passphrase cannot be recovered. Write it in 1Password now.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			if plaintextPath == "" {
				plaintextPath = vault.PlaintextLegacyPath()
			}
			if _, err := os.Stat(vault.VaultPath(name)); err == nil {
				return fmt.Errorf("%s already exists — refusing to overwrite (rm it first if intentional)", vault.VaultPath(name))
			}
			if _, err := os.Stat(plaintextPath); err != nil {
				return fmt.Errorf("no plaintext key at %s (pass --key <path>)", plaintextPath)
			}
			pass1, err := promptPassphrase("New vault passphrase: ")
			if err != nil {
				return err
			}
			pass2, err := promptPassphrase("Confirm passphrase:    ")
			if err != nil {
				return err
			}
			if pass1 != pass2 {
				return fmt.Errorf("passphrases do not match")
			}
			if err := vault.Init(name, plaintextPath, pass1); err != nil {
				return err
			}
			fmt.Printf("Wrote %s (encrypted).\n", vault.VaultPath(name))
			fmt.Printf("Shredded plaintext original %s.\n", plaintextPath)
			fmt.Println()
			fmt.Println("Save the passphrase in 1Password NOW — recovery is impossible.")
			return nil
		},
	}
	cmd.Flags().StringVar(&plaintextPath, "key", "", "Plaintext key file to encrypt (default: ~/.config/sops/age/keys.txt)")
	return cmd
}

func vaultStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show which backend is active and (for passphrase vault) lock state",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			fmt.Printf("vault name       %s\n", name)
			// Backend selection mirrors EnsureUnlocked exactly.
			if v := os.Getenv("SOPS_AGE_KEY"); v != "" {
				fmt.Println("backend          SOPS_AGE_KEY env (caller-managed, not name-scoped)")
				return nil
			}
			if c := os.Getenv(vault.EnvKeyCmd); c != "" {
				fmt.Printf("backend          %s → %q (not name-scoped)\n", vault.EnvKeyCmd, c)
				fmt.Println("  Session state, TTL, and approval prompt are managed by that command.")
				fmt.Println("  (1Password: session TTL is configured in the 1P desktop app.)")
				return nil
			}
			if ref := os.Getenv(vault.EnvOnePasswordRef); ref != "" {
				fmt.Printf("backend          1Password → %s (not name-scoped)\n", ref)
				fmt.Println("  Session state and approval prompt are managed by `op`.")
				return nil
			}
			// ssh-agent-backed vault (agent-backed KDF, no key material at rest).
			if f, err := sshagent.Load(sshagent.DefaultPath(name)); err == nil && f != nil {
				fmt.Printf("backend          ssh-agent (agent-backed KDF)\n")
				fmt.Printf("vault.ssh        %s\n", sshagent.DefaultPath(name))
				fmt.Printf("recipients       %d\n", len(f.Recipients))
				// Try to connect to agent to show which recipients are live.
				if c, err := sshagent.Dial(); err == nil {
					defer c.Close()
					if keys, err := c.List(); err == nil {
						loaded := map[string]bool{}
						for _, k := range keys {
							loaded[sshagent.Fingerprint(k)] = true
						}
						liveCount := 0
						for _, r := range f.Recipients {
							if loaded[r.Fingerprint] {
								liveCount++
							}
						}
						fmt.Printf("agent            %s (SSH_AUTH_SOCK)\n", os.Getenv("SSH_AUTH_SOCK"))
						fmt.Printf("live recipients  %d / %d (keys currently loaded in agent)\n", liveCount, len(f.Recipients))
						if liveCount == 0 {
							fmt.Println("  ⚠️  No recipient key is loaded — unlock will fail. Forward the agent or plug in the YubiKey.")
						}
					}
				} else {
					fmt.Printf("agent            UNREACHABLE (%v)\n", err)
					fmt.Println("  If SSH'd in, reconnect with ForwardAgent yes.")
				}
				fmt.Println()
				fmt.Println("Security requires the agent to prompt on every SIGN.")
				fmt.Println("  1Password SSH agent → biometric per SIGN")
				fmt.Println("  ssh-add -c          → per-op confirmation")
				fmt.Println("  Plain ssh-add       → NOT sufficient (SIGN is silent).")
				return nil
			}

			s, err := vault.Read(name)
			if err != nil {
				return err
			}
			fmt.Printf("backend          passphrase-encrypted vault\n")
			fmt.Printf("vault.age        %s   %s\n", s.VaultPath, boolMark(s.InitDone, "present", "MISSING — run `vault init`"))
			fmt.Printf("cache            %s\n", s.CachePath)
			if !s.OnTmpfs {
				fmt.Println("  warning: cache path is NOT tmpfs — plaintext key touches real disk.")
				fmt.Println("           Mount tmpfs at that directory on FreeBSD / non-systemd Linux.")
			}
			if !s.CachePresent {
				fmt.Println("state            LOCKED")
				return nil
			}
			now := time.Now()
			if s.Expired {
				fmt.Println("state            EXPIRED (next command will re-prompt)")
			} else {
				hard := s.HardExpiry.Sub(now).Round(time.Second)
				idle := s.IdleExpiry.Sub(now).Round(time.Second)
				fmt.Printf("state            UNLOCKED\n")
				fmt.Printf("  hard expiry    %s   (in %s)\n", s.HardExpiry.Format(time.RFC3339), hard)
				fmt.Printf("  idle expiry    %s   (in %s)\n", s.IdleExpiry.Format(time.RFC3339), idle)
			}
			fmt.Printf("policy           ttl=%s  idle=%s\n", s.TTL, s.Idle)
			return nil
		},
	}
}

func vaultLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Shred the runtime cache immediately",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := resolveVaultName()
			if err != nil {
				return err
			}
			if err := vault.Lock(name); err != nil {
				return err
			}
			fmt.Printf("Vault %q locked.\n", name)
			return nil
		},
	}
}

// promptPassphrase reads a passphrase from the TTY without echo. Uses
// golang.org/x/term so it works on Linux, macOS, and FreeBSD.
func promptPassphrase(msg string) (string, error) {
	fmt.Fprint(os.Stderr, msg)
	// term.ReadPassword needs the TTY fd. On some CI runners stdin is
	// not a TTY — in that case ReadPassword returns an error.
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("stdin is not a TTY — passphrase must be entered interactively")
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func boolMark(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
