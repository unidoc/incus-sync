# Justfile for the incus-sync tool.
# Config lives in a separate repo (see README.md).

default: build

# ── Build ────────────────────────────────────────────────────────────────

# Native build (host arch), version-stamped from version.txt.
build:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p bin
    VERSION=$(cat version.txt | tr -d '[:space:]')
    CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o bin/incus-sync ./cmd/incus-sync

# Cross-build for Alpine arm64 hosts.
build-arm64:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p bin
    VERSION=$(cat version.txt | tr -d '[:space:]')
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.version=${VERSION}" -o bin/incus-sync-linux-arm64 ./cmd/incus-sync

# Cross-build for FreeBSD hosts.
build-freebsd arch="amd64":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p bin
    VERSION=$(cat version.txt | tr -d '[:space:]')
    CGO_ENABLED=0 GOOS=freebsd GOARCH={{arch}} go build -ldflags="-s -w -X main.version=${VERSION}" -o bin/incus-sync-freebsd-{{arch}} ./cmd/incus-sync

# Cross-build for OpenBSD (amd64 only — lowest-priority target).
build-openbsd:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p bin
    VERSION=$(cat version.txt | tr -d '[:space:]')
    CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 go build -ldflags="-s -w -X main.version=${VERSION}" -o bin/incus-sync-openbsd-amd64 ./cmd/incus-sync

# Build every target locally, for a quick manual smoke-test. Not the release
# path — see `release-pr`/`release` below for that.
build-all: build build-arm64 build-freebsd build-openbsd
    @ls -la bin/

fmt:
    go fmt ./...
    go vet ./...

test:
    go test ./...

# Install bash completion into /etc/bash_completion.d/ (needs root).
install-completion-bash: build
    ./bin/incus-sync completion bash | sudo tee /etc/bash_completion.d/incus-sync > /dev/null
    @echo "Installed bash completion. Start a new shell or source /etc/bash_completion.d/incus-sync."

# Same for zsh.
install-completion-zsh: build
    #!/usr/bin/env sh
    dir="$(zsh -c 'print -r ${fpath[1]}' 2>/dev/null || echo /usr/local/share/zsh/site-functions)"
    ./bin/incus-sync completion zsh | sudo tee "$dir/_incus-sync" > /dev/null
    echo "Installed zsh completion to $dir/_incus-sync"

clean:
    rm -rf bin dist

# ── Release ──────────────────────────────────────────────────────────────
#
# Two-step, PR-based release flow:
#   1. just release-pr 0.2.0   → branch + version.txt bump + PR (review, CI)
#   2. merge the PR
#   3. just release 0.2.0      → verifies master carries 0.2.0, signs the tag,
#                                pushes — CI (goreleaser) publishes binaries,
#                                checksums and changelog to a GitHub Release.

# Step 1: open the version-bump PR.
release-pr VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    # Bare X.Y.Z only — the recipe adds the `v`. Rejects "v0.2.0" (→ vv0.2.0).
    [[ "{{VERSION}}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "✗ version must be X.Y.Z (no leading v), got '{{VERSION}}'"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "✗ working tree not clean"; exit 1; }
    git fetch origin
    if [ "$(git show origin/master:version.txt | tr -d '[:space:]')" = "{{VERSION}}" ]; then
        echo "✗ version.txt on master is already {{VERSION}} — nothing to bump; run: just release {{VERSION}}"
        exit 1
    fi
    trap 'git checkout master 2>/dev/null; git branch -D "release/v{{VERSION}}" 2>/dev/null || true' EXIT
    git checkout -b "release/v{{VERSION}}" origin/master
    echo "{{VERSION}}" > version.txt
    git add version.txt
    git commit -m "Release v{{VERSION}}"
    git push -u origin "release/v{{VERSION}}"
    gh pr create --title "Release v{{VERSION}}" \
        --body "Bumps version.txt to {{VERSION}}. After merge: \`just release {{VERSION}}\` tags master and CI publishes the release."
    trap - EXIT
    echo "✓ release PR opened — merge it, then run: just release {{VERSION}}"

# Local test-build of the release pipeline — same artifacts as a real
# release (dist/), nothing published. Requires goreleaser installed.
snapshot:
    goreleaser release --snapshot --clean --skip=validate
    @echo "✓ snapshot in dist/ — try: tar -xzf dist/*linux_amd64.tar.gz -C /tmp && /tmp/incus-sync version"

# Step 2 (after the PR is merged): tag master and push the tag.
release VERSION:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ "{{VERSION}}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "✗ version must be X.Y.Z (no leading v), got '{{VERSION}}'"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "✗ working tree not clean"; exit 1; }
    git checkout master
    git pull --ff-only
    git fetch --tags origin  # catch remote-only tags the local repo hasn't seen
    [ "$(tr -d '[:space:]' < version.txt)" = "{{VERSION}}" ] || \
        { echo "✗ version.txt is '$(cat version.txt)' — merge the release PR first"; exit 1; }
    git rev-parse "v{{VERSION}}" >/dev/null 2>&1 && { echo "✗ tag v{{VERSION}} already exists"; exit 1; }
    git tag -s "v{{VERSION}}" -m "v{{VERSION}}"
    git push origin "v{{VERSION}}"
    echo "✓ v{{VERSION}} tagged — CI builds the release: gh run watch"
