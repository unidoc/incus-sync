# incus-sync

Declarative, GitOps-style sync tool for [Incus](https://linuxcontainers.org/incus/):
network address sets, ACLs, and container identity, described as YAML in
a git repo and reconciled against one or more Incus hosts. Pairs
naturally with [incus-console](https://github.com/unidoc/incus-console)
for interactive, single-host access.

Not tied to any one organization's setup — anyone running a fleet of
Incus hosts and wanting git-tracked network policy, address sets, ACLs,
and container identity can use it.

## What it manages

- Network address sets (with per-address comments preserved in git)
- Network ACLs (with tag-based policy attachment, Hetzner-firewall style)
- Fleet-repo-only host aliases (`@name` expansion, cycle-detected)
- Per-instance eth0 device config: static IPs, attached ACLs, default actions
- Container creation with declared image + tags

## What it deliberately does NOT manage

- Container contents (packages, files, running processes) — hand-tune via `incus-sync shell`
- Storage volumes, profiles, projects — provisioned once per host
- Instance state (running/stopped) — one-shot via `incus start/stop`
- Deletion of unmanaged Incus objects — safety by default

## Install

Build from source (Go 1.26.3+):

```sh
just build            # produces bin/incus-sync (static, ~16 MB stripped)
just install-completion-bash
```

Or via `go install` (works out of the box against a public GitHub repo,
no extra setup needed):

```sh
go install github.com/unidoc/incus-sync/cmd/incus-sync@latest
```

## Setup on an Incus host

```sh
# 1. Get the binary (or `just build` from a checkout)
install -m 0755 bin/incus-sync /usr/local/sbin/incus-sync

# 2. Clone your fleet config repo
git clone <your-fleet-repo-url> /etc/incus-sync-fleet

# 3. Point the tool at it
cat > /etc/profile.d/incus-sync.sh <<'EOF'
export INCUS_SYNC_FLEET_PATH=/etc/incus-sync-fleet
EOF

# 4. Verify
incus-sync doctor
```

`doctor` prints the config-dir source, hostname target, host-directory
existence, and daemon reachability. Fails if anything is off. Run
`incus-sync doctor --deep` to also check for an expected profile/network
name (set `INCUS_SYNC_EXPECT_PROFILE` / `INCUS_SYNC_EXPECT_NETWORK` —
unset by default, since there's no fleet-agnostic default to assume).

For a multi-host fleet driven from one machine over the network instead
of running locally on each host, see [Auth](#auth) below.

## Commands

| Command | Purpose | Reads Incus? | Writes Incus? |
|---------|---------|--------------|---------------|
| `doctor` | Sanity-check tool + config + daemon alignment | Yes | No |
| `validate` | Parse, resolve, enforce naming, semantic-check | No | No |
| `render` | Print the fully-resolved YAML that would be pushed | No | No |
| `explain <instance>` | Show why each ACL is attached | No | No |
| `adopt` | Dump live Incus state into per-object YAML files | Yes | No |
| `import <instance>` | Adopt one unmanaged container into the fleet repo | Yes | No |
| `list` | Managed instances with status/image/tags/IPs | Yes | No |
| `orphans` | Containers with no fleet file | Yes | No |
| `prune-check` | What `sync` would flag as unmanaged (never deletes) | Yes | No |
| `diff` | Colored diff of live vs desired | Yes | No |
| `sync` | Dry-run of what would change | Yes | No |
| `sync --apply` | Apply changes (TTY prompts unless `--yes`) | Yes | Yes |
| `refresh-nft` | Regenerate nftables rules from current ACLs | Yes | No |
| `refs <name>` | Find/rename every reference to an alias or address set | No | No |
| `shell <instance>` | Interactive shell (prefers bash) | Yes | Exec |
| `create <name>` | Scaffold a new instance YAML file | No | No |
| `remote bootstrap <host>` | Generate a TLS client cert + write `remote.sops.yaml` | Yes | No — prints the `incus config trust add-certificate` command for you to run on the target |
| `remote list` | List configured remote (HTTPS) hosts | No | No |
| `vault ...` | Manage the AGE key that decrypts SOPS secrets (see [Auth](#auth)) | No | No |
| `fleet <subcommand>` | Re-run a subcommand once per host declared in `fleet.yaml` | Yes | Depends on subcommand |
| `version` | Print the build version | No | No |

Every command that resolves a target host defaults to `hostname -s`.
Refuses to run if `hosts/<hostname>/` does not exist in the config repo
and no explicit `--host` was given — unless that host has a
`hosts/<host>/remote.sops.yaml`, in which case it connects over HTTPS
instead (see [Auth](#auth)).

## Config repo layout

```
<config-repo>/
├── fleet.yaml              # fleet name, managed projects; secrets live in shared/secrets.sops.yaml
├── shared/
│   ├── aliases/           # named host groups (@name), never pushed
│   ├── address-sets/      # fleet-wide address sets
│   ├── acls/              # reusable ACLs — must be "default-policy" or "generic-*"
│   ├── policies/          # tag-selector ACL attachment
│   └── secrets.sops.yaml  # SOPS-encrypted app secrets, looked up by dotted path
├── hosts/<host>/
│   ├── aliases/           # host-scoped aliases  (name prefix: <host>-)
│   ├── address-sets/      # host-scoped sets     (name prefix: <host>-)
│   ├── acls/              # host-scoped ACLs     (name prefix: <host>-)
│   ├── remote.sops.yaml   # optional: HTTPS URL + SOPS-encrypted TLS client cert/key
│   └── instances/
│       └── <instance>.yaml
```

Full schema: [docs/schema.md](docs/schema.md). Complete runnable
example: [examples/minimal-fleet](examples/minimal-fleet) — clone it,
run `validate`/`render`/`explain` against it, no Incus daemon needed.

## Instance file (Option 4 flat form)

```yaml
instance: wiki
description: Public wiki (mediawiki)
original_image: images:alpine/3.24
tags: [web]

ip6: 2001:db8:1::82
ingress-default: reject
egress-default: allow
```

Seven lines. `tags: [web]` triggers any tag-matching policy in
`shared/policies/`. If you need multi-NIC, use the explicit `devices:`
map instead.

## Reference resolution

| Syntax | Meaning | Resolved by |
|--------|---------|-------------|
| `@name` | fleet-repo alias | tool expands before push |
| `$name` | Incus address set | Incus at rule eval time |
| bare IP/CIDR | literal | pass-through |

Missing `@` or `$` reference = hard validate error. Rename an alias =
every referrer fails validate until updated. That is the point.

## Auth

Two connection modes, chosen automatically per host:

- **Local**: unix socket (`/var/lib/incus/unix.socket` by default,
  override with `--socket`). No TLS, no passwords. Used when
  `hosts/<hostname>/` has no `remote.sops.yaml`. Must run as a user in
  the `incus-admin` group (or root).
- **Remote**: HTTPS with a TLS client certificate, used whenever
  `hosts/<host>/remote.sops.yaml` exists. The file holds the host's API
  URL and pinned server-certificate fingerprint in plaintext, and a
  SOPS-encrypted client cert/key. Bootstrap one with
  `incus-sync remote bootstrap <host> --url https://<host>:8443` — it
  generates a keypair, prints the enrollment command to run on the
  target (`incus config trust add-certificate ...`), and writes the
  encrypted `remote.sops.yaml` for you to commit.

### Secrets: SOPS/AGE, with no AGE key required on disk

Both `remote.sops.yaml` (per-host TLS client cert/key) and
`shared/secrets.sops.yaml` (fleet-wide app secrets, e.g. for
`provision.after` templates) are SOPS-encrypted with AGE. Decrypting
either requires an AGE private key, which `incus-sync vault` can source
from several backends, tried in this order:

1. `SOPS_AGE_KEY` env — already set, used as-is.
2. `INCUS_SYNC_AGE_KEY_CMD` env — an arbitrary shell command whose
   stdout is the key (1Password CLI, `pass`, `vault kv get`, ...).
   Session state, prompting, and TTL are all deferred to that tool.
3. `INCUS_SYNC_AGE_1PASSWORD_REF` env — shorthand for
   `INCUS_SYNC_AGE_KEY_CMD='op read <ref>'`.
4. **SSH-agent-backed vault** (`incus-sync vault ssh-init` /
   `ssh-add-key`) — no AGE key material touches disk at all. A
   deterministic signature from an ed25519 key held by your SSH agent
   is run through HKDF to derive the key that unwraps a ciphertext blob
   at `~/.config/incus-sync/<name>/vault.ssh`. Every unlock
   requires a live SIGN from the agent, so it's only as strong as your
   agent's own approval policy — a YubiKey or 1Password SSH agent with
   touch/biometric confirmation is meaningfully different from a plain
   `ssh-add`-loaded key with no prompt. This is the backend to use if,
   like most operators, you don't want a raw AGE identity sitting on
   disk.
5. **Passphrase-encrypted vault** (`incus-sync vault init`) —
   `~/.config/incus-sync/<name>/vault.age`, age-encrypted with
   scrypt, unlocked into a TTL-limited runtime cache (`$XDG_RUNTIME_DIR`
   tmpfs when available), 4h hard expiry / 60min idle timeout by
   default (`INCUS_SYNC_VAULT_TTL`, `INCUS_SYNC_VAULT_IDLE`),
   auto-shredded on expiry.
6. Legacy plaintext `~/.config/sops/age/keys.txt` (SOPS's own default
   location, global — not per-vault) — supported for migration only;
   deprecated.

Backends 1-3 are per-shell-session overrides, not scoped to any
particular fleet — that's the operator's own responsibility (e.g. via
per-repo direnv) if they want to keep them separate. Backends 4-5 are
scoped by **name**: `fleet.yaml` requires a `name:` field, and
every fleet gets its own — two fleets with different names never share
a passphrase, an ssh-agent-derived key, or even an unlocked-cache
window, on the same machine or not. Manage `acme-fleet` and
`acme2-fleet` side by side and each has a genuinely separate vault;
compromising one's ciphertext, or catching one mid-unlock, never
exposes the other. See `internal/vault`'s package doc for the full
design rationale.

None of the six backends are mutually exclusive with the others being
*available* — they're tried in order per invocation, so you can mix: an
operator using 1Password on their laptop, a CI runner using
`INCUS_SYNC_AGE_KEY_CMD` against a secrets manager, and a bastion host
using the SSH-agent vault, all against the same encrypted fleet repo.

**Threat model** (see `internal/vault/vault.go` for the full writeup):
this defends against a stolen laptop/backup, a compromised dependency
in your shell environment, or leaked ciphertext — not against a live
attacker already inside your shell with ptrace/mem access to a process
holding the decrypted key. That's a "don't get pwned" layer, not a hard
security boundary.

`incus-sync vault status` shows which backend is active and whether the
cache is expired. `incus-sync vault lock` shreds the runtime cache
immediately.

## Safety posture

- `sync` is dry-run by default. `--apply` prompts on a TTY unless `--yes`.
- Never deletes objects that exist in Incus but not in the fleet. Prints
  them as "unmanaged". Includes containers with no fleet file.
- Instance device patches touch only the keys the model marks as managed
  (see `internal/model/instance.go:ManagedDeviceKeys`). Every other key
  on the device — including profile-provided ones — is left alone.
- ETag-safe updates re-fetch the object at apply time.
- 60s timeout on instance updates, 120s on container creation. Long
  operations that never complete raise a clear error instead of hanging.
- Remote HTTPS connections pin the server certificate fingerprint from
  `remote.sops.yaml` rather than trusting a CA chain — TOFU, verified
  on every connection thereafter.

### Refuse-worthy changes require `--force`

`sync --apply` refuses to execute without `--force` if the plan contains any
of these dangerous shapes:

- Address set update that would reduce it to zero members (silently
  disables every rule referencing it via `$ref`).
- ACL update that would reduce it to zero rules (every attached device
  falls back to its default action only).
- Instance eth0 `ingress-default` changing from `reject` or `drop` to
  `allow` (world-open flip).
- Instance eth0 removing all attached ACLs.

Emitted by `diff` in red with a `DANGER` prefix; emitted by `sync
--apply` output and required in a `--force` flag before proceeding.

### Widening warnings (informational)

`validate` prints `RISK:` warnings for configurations that are
*syntactically valid but security-relevant*:

- `ingress-default: allow` on a device.
- Allow rules with empty source (world-open on port).
- Instances with tags but no matching policy (silently unprotected).

Warnings do not fail validate — they surface so reviewers see them.

## Common failure modes

| Symptom | Likely cause | Recovery |
|---------|--------------|----------|
| `instance %q create did not complete in 120s` | DNS failure to images.linuxcontainers.org, slow network, or full disk | `df -h /var/lib/incus`; `curl -I https://images.linuxcontainers.org`; retry after fix |
| `instance %q created but is in state "Stopped"` | Image pull ok but container init failed | `incus console --show-log <name>`; often kernel-cgroup, apparmor, or unshare mismatch |
| `refusing to apply with dirty or stale fleet repo` | Uncommitted local edits or upstream commits not pulled | `git status`, `git pull --rebase`, or override with `--dirty-ok` |
| `lockfile ... held (contents: "12345\n")` | Another sync is running (pid 12345) or crashed | Wait, or if pid 12345 is dead: `rm $INCUS_SYNC_FLEET_PATH/.incus-sync.lock` |
| `target host %q != hostname -s %q` | Ran `sync --host X` from a different host with no `remote.sops.yaml` for X | Run from the target host, bootstrap a remote for it, or pass `--socket` |
| Apply log at `~/.local/state/incus-sync/apply-*.log` | Every `sync --apply` writes one | JSONL; grep with `jq` for `apply_error` events |
| `no /var/lib/incus/unix.socket` | Incus daemon down | `rc-service incusd status` (Alpine) or `systemctl status incus` |
| `instance %q created but provisioning failed` | `provision.after` command exited non-zero | `incus console --show-log <name>`; fix the command or file content, then delete container and re-sync |
| `passphrase prompt required but no TTY handler bound` | Vault needs unlocking but running non-interactively | Set `INCUS_SYNC_AGE_KEY_CMD`/`SOPS_AGE_KEY`, or run `incus-sync doctor --host <h>` interactively first |

## Persistent apply log

Every `sync --apply` writes a JSONL transcript to
`~/.local/state/incus-sync/apply-<timestamp>-<host>.log`. Records
`apply_start`, `apply_error` (if any), and `apply_end` with the plan
summary.

Answers "what did sync do last Tuesday?" without needing `tee`.

## Daily drift check (optional)

Ship a `incus-sync-drift.{service,timer}` systemd unit (in your fleet
repo, or wherever you keep host provisioning) that runs
`incus-sync diff --format=summary` on a timer. Alert on non-empty
output via `journalctl -u incus-sync-drift`.

## License

Apache 2.0 — see [LICENSE.md](LICENSE.md).
