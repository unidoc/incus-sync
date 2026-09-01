# minimal-fleet

A complete, runnable example fleet — two hosts, a shared policy that
tag-attaches ACLs, a host-scoped ACL, both instance forms (flat and
explicit multi-NIC), and a provisioning template that reads a fleet
secret. Covers every object kind in [docs/schema.md](../../docs/schema.md)
except aliases-of-aliases and instance-owned `defines:`.

It's also a regression test: `internal/config/examples_test.go` loads
and validates this fleet on every `go test`, so it can't silently rot
out of sync with the schema.

## Try it

No Incus daemon needed — `validate` and `render` are pure config-repo
operations:

```sh
just build
./bin/incus-sync --fleet-path examples/minimal-fleet validate --host web1
./bin/incus-sync --fleet-path examples/minimal-fleet validate --host db1
./bin/incus-sync --fleet-path examples/minimal-fleet render --host web1 --kind all
./bin/incus-sync --fleet-path examples/minimal-fleet explain --host web1 blog
```

`explain blog` shows *why* each ACL on `blog` is attached — one comes
from `acls:` directly, three from the tag-matched `web-tier` policy.

## Layout

```
fleet.yaml                          # projects: [default]
shared/
├── aliases/office.yaml             # @office — office CIDR + admin's IP
├── address-sets/secure-servers.yaml # references @office + a literal
├── acls/
│   ├── default-policy.yaml         # ICMP baseline (reserved name)
│   ├── generic-web-in.yaml         # 80/443 world-open (ack'd)
│   └── generic-ssh-management.yaml # SSH from $secure-servers only
├── policies/web-tier.yaml          # tags:[web] -> attach the three ACLs above
└── secrets.sops.yaml               # plaintext here on purpose — see file comment
templates/motd/                     # provisioning bundle: files/ + after.sh + a secret
hosts/
├── web1/
│   ├── acls/web1-internal.yaml     # host-scoped (must start with "web1-")
│   ├── address-sets/web1-neighbors.yaml
│   └── instances/blog/instance.yaml   # flat form
└── db1/
    └── instances/postgres/instance.yaml  # explicit devices: form, multi-NIC
```

## What to try changing

- Typo the `$secure-servers` reference in `generic-ssh-management.yaml`
  (e.g. to `$secure-serverz`) — `validate` fails immediately with
  `acl "generic-ssh-management" ingress rule source references unknown
  address_set "secure-serverz"`.
- In `blog/instance.yaml`, typo `tags: [web]` to `tags: [webb]` *and*
  delete the `acls: [web1-internal]` lines (so nothing is attached any
  other way) — `validate` now warns `RISK: instance "blog" has tags
  [webb] but no ACL matched`. Leaving `acls: [web1-internal]` in place
  hides the warning, since that ACL alone makes the effective set
  non-empty — a good illustration of why the check only fires on a
  *fully* unprotected instance.
- Delete the `(ack world-open)` from `generic-web-in.yaml`'s
  description — `validate` starts printing a `RISK:` warning for the
  world-open rule.
