# YAML schema

Every YAML file in the config repo describes one incus-sync object.
Filename minus `.yaml` MUST equal the declared `name`. The loader
enforces this.

## fleet.yaml

One per repo, at the root. Not a per-object file — declares fleet-wide
metadata. Every field is required; there is no silent default.

```yaml
name: <name>               # identifies this fleet — see below
projects:                 # every Incus project this fleet manages
  - <project>...
network_project: <string> # optional; where ACLs/address-sets live (default "default")
```

`name:` is the one field worth dwelling on: it is NOT a secret itself,
just a label. Two fleets with different `name:` values get completely
independent AGE vaults (`~/.config/incus-sync/<name>/`) — never
share a passphrase, an ssh-agent-derived key, or an unlocked-cache
window, even run from the same operator machine. Pick something unique
across every fleet you manage (the repo name is a safe default) and
never reuse it for a different fleet.

## Six object kinds

- **alias** — `shared/aliases/<name>.yaml`, `hosts/<h>/aliases/<name>.yaml`
- **address_set** — `shared/address-sets/<name>.yaml`, `hosts/<h>/address-sets/<name>.yaml`
- **acl** — `shared/acls/<name>.yaml`, `hosts/<h>/acls/<name>.yaml`
- **policy** — `shared/policies/<name>.yaml`, `hosts/<h>/policies/<name>.yaml`
- **template** — `templates/<name>/` (a directory, not a YAML file — see
  [template](#template) below)
- **instance** — `hosts/<h>/instances/<name>/instance.yaml` (a directory
  per instance, not a flat file. Optional siblings `files/` and
  `after.sh` hold instance-specific provisioning content, same shape as
  a template.)

Inline definitions under `instance.defines:` are equivalent to
top-level ACLs and address sets, scoped by prefix rule.

## alias

```yaml
alias: <name>
description: <string>
addresses:
  - <string>          # literal IP or CIDR
  - "@other-alias"    # reference (recursive; cycles rejected)
```

Not pushed to Incus. Expanded to literal addresses at render/sync time.

## address_set

```yaml
name: <name>
description: <string>
addresses:
  - <string>                      # literal
  - "@alias"                      # fleet-repo alias reference
  - address: <string>             # extended: literal + human comment
    comment: <string>             # not stored in Incus, only in git
config:                           # optional user.* keys
  <key>: <value>
```

## acl

Schema matches Incus's own `incus network acl show --format=yaml`
exactly, with two additions: filename convention and reference syntax
inside rules.

```yaml
name: <name>
description: <string>
ingress:
  - action: allow | reject | drop
    source: <string>              # CIDR, $set, @alias, comma-separated
    destination: <string>
    protocol: tcp | udp | icmp4 | icmp6
    source_port: <string>         # "N", "N-N", "N,N-N,..."
    destination_port: <string>
    icmp_type: <string>
    icmp_code: <string>
    description: <string>
    state: enabled | disabled | logged
egress: [...]                      # same shape
config:                            # optional user.* keys
  <key>: <value>
```

Shared ACLs (under `shared/acls/`) must be named `default-policy` or
start with `generic-`. Instance-owned inline ACLs (`instance.defines.acls`)
must start with `<instance>-`.

## policy

```yaml
policy: <name>
description: <string>
selector:
  tags:                            # AND semantics — all must match
    - <tag>
attach:
  security.acls:                   # ACL names to attach to matching instances
    - <acl-name>
```

Every matching instance gets these ACLs unioned with its own
`acls:` list. Empty selector matches every instance (rare; use
`shared/acls/default-policy.yaml` instead).

**Policies attach only to eth0.** On multi-NIC instances (`devices:`
map with eth1, wg0, etc.), tag-driven policies never touch non-eth0
devices — those get only what the instance file explicitly lists.
This preserves the "left alone" guarantee for private/management
interfaces (Wireguard, storage, out-of-band).

## template

A directory, not a single YAML file:

```
templates/<name>/
  manifest.yaml   # optional — name, description, secrets, per-file owner/mode
  before.sh       # optional — runs BEFORE files/ is pushed
  files/          # optional — tree copied 1:1 into the container root
  after.sh        # optional — runs AFTER files/ is pushed
```

`manifest.yaml`:

```yaml
template: <name>                     # must match the directory name
description: <string>
secrets:                             # optional — injected as env vars into before.sh/after.sh
  - env: <ENV_VAR_NAME>
    from: <dotted.path.into.secrets.sops.yaml>
files:                               # optional per-file owner/group/mode overrides
  <path>:
    owner: <string>                  # default: root (resolved via getpwnam inside the container)
    group: <string>                  # default: root
    mode: <string>                   # default: "0644" files, "0755" dirs
```

Applied only at container create time (never re-run by `sync`), in the
order an instance's `provision.templates:` lists them. Execution order
per template: `before.sh` → tar-push `files/` → `after.sh`. Referencing
a template that doesn't resolve, or a `secrets.from` path missing from
`shared/secrets.sops.yaml`, is a hard `validate` error — no silent
partial provisioning.

An instance's own `files/` and `after.sh` (siblings of its
`instance.yaml`) work identically, scoped to that one container instead
of being reusable.

## instance (flat form, common case)

```yaml
instance: <name>
description: <string>
original_image: images:<alias>              # required if sync should create the container
profiles: [<profile>...]           # optional; default [default]
tags: [<tag>...]                   # match tag-based policies
start: true | false                # optional; default true on first create

# eth0 device — all fields optional
ip4: <IPv4 address>
ip6: <IPv6 address>
acls:                              # attached ACL names (union with policy-attached)
  - <acl-name>
acls-exclude:                      # subtract from effective set (rare, opt-out)
  - <acl-name>
ingress-default: allow | reject | drop
egress-default: allow | reject | drop

# One-shot provisioning at create time (never re-run by sync).
# Deliberately small: pick a template OR write raw files + commands.
provision:
  interface: alpine        # or: debian-networkd, debian-interfaces
  files:                    # optional escape hatch
    - path: /etc/motd
      content: "fleet-managed instance\n"
      mode: "0644"
  after:                    # optional shell commands inside the container
    - apk add nginx
    - rc-update add nginx default

# Instance-owned inline definitions (rare)
defines:
  acls:
    - name: <instance>-<something>
      description: ...
      ingress: [...]
  address_sets:
    - name: <instance>-<something>
      description: ...
      addresses: [...]
```

## instance (explicit form, multi-NIC)

```yaml
instance: <name>
description: <string>
original_image: images:<alias>

# ip4/ip6 stay top-level metadata even with explicit devices: below —
# see "IP addresses" note under the flat form above. They are not part
# of what makes flat/explicit "mutually exclusive".
ip6: <IPv6 address>

# Mutually exclusive with flat form's acls/ingress-default/egress-default.
devices:
  eth0:
    security.acls: [<name>...]
    security.acls.default.ingress.action: reject
    security.acls.default.egress.action: allow
  eth1:
    security.acls: [<name>...]
```

`ipv4.address`/`ipv6.address` are deliberately not managed keys here —
Incus rejects them on bridged networks without DHCP, and static IPs
belong inside the container's own network config (see `provision.interface`),
not on the Incus device. Only the three keys shown above are
reconciled per device. Every other key on the
device — including profile-provided ones — is left alone.

## Reference syntax

| Prefix | Where it resolves | Example |
|--------|-------------------|---------|
| `@name` | fleet-repo alias, tool-expanded before push | `"@lupin"` |
| `@name.field` | instance field lookup (ip4, ip6) on the CURRENT host | `"@webapp.ip6"` |
| `$name` | Incus address set, resolved at rule eval | `"$secure-servers"` |
| `@internal`, `@external` | Incus subject keyword, passed through | ACL `source:` |

Aliases can reference other aliases. Cycles are hard errors.

**Dispatch rule.** `@X.Y` always means instance field lookup. `@X` (no dot)
always means alias. The loader forbids alias names and instance names from
colliding — that would make `@X` and `@X.Y` reference two different things.

**Same-host constraint.** `@instance.field` only resolves against the
current host's instances. Cross-host references are not supported by
design — if you need one host's IP visible on another, define an alias in
`shared/aliases/<host>-*.yaml` with the literal address.

## Port syntax

Always strings. Single port, range, or comma-separated list:

```yaml
destination_port: "80"
destination_port: "80,443"
destination_port: "8000-8010"
destination_port: "22,80,8000-8010"
```

## Comments on addresses

Only address sets and aliases keep comments. Two accepted forms in
address sets:

```yaml
addresses:
  - 203.0.113.10                                 # plain
  - address: 198.51.100.20                        # with comment
    comment: bogor v4 — AlbaHost Tirana
  - "@lupin"                                    # alias reference
```

Comments live only in git. Incus does not store them.

## Merge and conflict rules

- Objects with the same name in different scopes = hard error at load.
- Missing `@` or `$` reference = hard error.
- Alias cycle = hard error with the full path in the message.
- Instance file present but container missing from Incus AND no `original_image:`
  field = warning (sync cannot create).
- Instance file names an inline ACL that already exists elsewhere =
  hard error (duplicate).
