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

# 2. Clone your fleet repo
git clone <your-fleet-repo-url> /etc/incus-sync-fleet

# 3. Point the tool at it
cat > /etc/profile.d/incus-sync.sh <<'EOF'
export INCUS_SYNC_FLEET_PATH=/etc/incus-sync-fleet
EOF

# 4. Verify
incus-sync doctor
```

`doctor` prints the fleet-path source, hostname target, host-directory
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
Refuses to run if `hosts/<hostname>/` does not exist in the fleet repo
and no explicit `--host` was given — unless that host has a
`hosts/<host>/remote.sops.yaml`, in which case it connects over HTTPS
instead (see [Auth](#auth)).

## Fleet repo layout

```
<config-repo>/
├── fleet.yaml              # managed projects; secrets live in shared/secrets.sops.yaml
├── .sops.yaml              # SOPS encryption policy: recipients + which files/fields to encrypt
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

### Secrets: SOPS/AGE — incus-sync owns no cryptography of its own

Both `remote.sops.yaml` (per-host TLS client cert/key) and
`shared/secrets.sops.yaml` (fleet-wide app secrets, e.g. for
`provision.after` templates) are SOPS-encrypted with AGE. Decrypting
either requires an AGE private key, which incus-sync resolves from
exactly two of SOPS's own native env vars — nothing incus-sync-specific,
no custom hook, no legacy fallback:

1. `SOPS_AGE_KEY` env — the key content itself, already set, used as-is.
2. `SOPS_AGE_KEY_FILE` env — path to an **identity file**. This is the
   recommended way to point at anything beyond a raw key sitting in an
   env var — see below for what can go in it.

incus-sync implements neither var itself: it reads whichever is set
and hands the bytes to the sops library. There is no third mechanism —
every secret-manager integration is an **age plugin identity** in the
file above, never an incus-sync feature.

#### What goes in the identity file

An age identity file can hold one or more lines, each either:

- A **plain age private key** (`AGE-SECRET-KEY-1...`) — simplest,
  zero extra tooling, but it's a bearer credential sitting on disk.
- An **age plugin identity** (`AGE-PLUGIN-<NAME>-1...`) — hardware-,
  agent-, or secret-manager-backed, zero key material at rest. SOPS
  itself resolves these transparently (via `filippo.io/age`'s plugin
  support, vendored since sops v3.8+): it shells out to the matching
  `age-plugin-<name>` binary on PATH. incus-sync needs no
  plugin-specific code to support any of them — it just hands the
  file's bytes to SOPS unexamined.

Multiple lines in one identity file, or several people each with their
own plugin-derived identity, both work the same way SOPS has always
supported multiple recipients — see below.

#### Which plugin to use

incus-sync has no opinion and no list — that's deliberate. Plugins
exist for hardware tokens, ssh-agents, and various secret managers;
search `age-plugin-<your tool>` for what's out there, pin whichever
one you choose to a specific version (or your own audited fork) the
same way you would any other dependency with access to a decryption
key, and point `SOPS_AGE_KEY_FILE` at the identity it produces. If
nothing exists yet for your tool, the [age plugin
protocol](https://github.com/C2SP/C2SP/blob/main/age-plugin.md) is
small and documented — writing one is on you, not incus-sync, and
incus-sync will use it exactly like any other identity the moment
SOPS can resolve it.

#### Multiple recipients: SOPS/age's own mechanism, not incus-sync's

Every recipient (person, machine, backup key) is one age **public**
key listed in `.sops.yaml`'s `keys:`, wrapped for a file's data key
the same way for all of them — this is native SOPS/age behavior,
unrelated to which backend above supplied any one recipient's private
half. incus-sync adds a thin, auditable convenience layer on top,
since hand-editing `.sops.yaml` and remembering to `sops updatekeys`
every affected file is an easy way to make a silent mistake:

```sh
# See who can currently decrypt what.
incus-sync vault list-recipients

# Add a recipient (label it — the anchor name IS the label) and
# re-wrap every already-encrypted file the matching creation_rule(s)
# cover, in one step:
incus-sync vault add-recipient ahall_laptop age1u2fys28ye... \
    --comment "ahall's laptop key"

# Remove one — re-wraps remaining recipients, which is what makes
# this real revocation rather than just deleting a line:
incus-sync vault remove-recipient ahall_laptop
```

Both commands refuse to leave any `creation_rule` with zero
recipients (that would make its files permanently undecryptable, not
revoke access), and print a reminder to commit `.sops.yaml` plus every
re-wrapped file — none of it takes effect for anyone else's clone
until that lands.

These commands hold no secret material and perform no cryptography of
their own — they edit YAML and shell out to `sops updatekeys`, the
same operation you'd otherwise run by hand.

`incus-sync vault status` shows which of the four backends above is
currently resolvable.

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
| `no age key resolvable` | Neither `SOPS_AGE_KEY` nor `SOPS_AGE_KEY_FILE` is set | Set one — see [Auth](#auth) |

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
