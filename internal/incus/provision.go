// Package incus, provision.go — one-shot container-side bootstrap at
// create time. Never re-runs on subsequent sync passes. If you need
// re-provisioning, delete the container and let sync recreate.
//
// Two primitives:
//   - Interface templates: generate the distro's networking file from the
//     instance's ip4/ip6 fields. Alpine, Debian networkd, Debian interfaces.
//   - Raw files + after-commands: escape hatch for anything else.
//
// Runs against the local Incus unix socket — no remote API needed. On
// bastion-orchestrated flows, provisioning executes on the target host
// itself via the orchestrator's ssh + incus-sync sync loop.

package incus

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"
	"gopkg.in/yaml.v3"

	"github.com/unidoc/incus-sync/internal/model"
)

// provisionContainer runs one-shot bootstrap against a freshly created,
// running container. Called from createInstance after the post-start
// health check succeeds.
//
// Order of operations:
//  1. Interface template (if set) → /etc/network/interfaces (or equiv)
//  2. Named templates (<fleet-repo>/templates/<name>/, in list order):
//     files/ tree pushed via tar-over-exec, then after.sh runs
//  3. Instance's own directory content: files/ tree pushed the same way,
//     then after.sh runs. Same shape as a template, but scoped to one
//     container instead of being reusable across many.
//
// templatePaths is a slice of on-disk directories in fleet template order.
// Resolved at plan time so this function has no fleet dependency at
// execution time.
//
// secrets is the pre-decrypted content of shared/secrets.sops.yaml —
// resolved at plan time under the operator's already-unlocked vault,
// so provisionContainer never touches SOPS itself.
func provisionContainer(srv incusclient.InstanceServer, inst model.Instance, templatePaths []string, secrets map[string]any) error {
	// 1. Interface template
	if inst.Provision != nil && inst.Provision.Interface != "" {
		t0 := time.Now()
		printStep("      interface template %q → in-container network config", inst.Provision.Interface)
		gen, err := renderInterfaceTemplate(inst.Provision.Interface, inst)
		if err != nil {
			return fmt.Errorf("provision interface template: %w", err)
		}
		if err := pushFile(srv, inst.Name, gen); err != nil {
			return fmt.Errorf("push %s: %w", gen.Path, err)
		}
		printDone(fmt.Sprintf("      wrote %s", gen.Path), time.Since(t0))
	}

	// 2. Named templates (bastille-style bundles, reusable)
	for _, path := range templatePaths {
		printStep("      template %s", filepath.Base(path))
		if err := applyTemplate(srv, inst.Name, path, secrets); err != nil {
			return fmt.Errorf("apply template %s: %w", path, err)
		}
	}

	// 3. Instance's own directory (files/ + after.sh alongside instance.yaml)
	if inst.SourceDir != "" {
		printStep("      instance dir %s", filepath.Base(inst.SourceDir))
		if err := applyTemplate(srv, inst.Name, inst.SourceDir, secrets); err != nil {
			return fmt.Errorf("apply instance dir %s: %w", inst.SourceDir, err)
		}
	}
	return nil
}

// applyTemplate applies one template bundle to the container in fixed
// order: before.sh → tar-push files/ (with per-file modes from
// manifest.yaml) → after.sh. Every phase is optional.
//
// before.sh is the place to install packages: apk / apt / etc. Running
// it BEFORE the tar-push means package post-install scripts create
// standard paths (/etc/ssh, /etc/postfix, ...) with correct ownership
// before we overlay our config on top.
func applyTemplate(srv incusclient.InstanceServer, instance, templatePath string, secrets map[string]any) error {
	manifest, err := readTemplateManifest(templatePath)
	if err != nil {
		return err
	}
	// Resolve declared secrets → env vars. Fail-closed: if a template
	// declares a secret and shared/secrets.sops.yaml is missing it,
	// refuse to run rather than silently applying a template whose
	// after.sh expects a variable that will be empty.
	env, err := resolveTemplateSecrets(manifest, secrets)
	if err != nil {
		return err
	}

	beforeSh := filepath.Join(templatePath, "before.sh")
	if data, err := os.ReadFile(beforeSh); err == nil {
		t0 := time.Now()
		printStep("        before.sh…")
		if err := execIn(srv, instance, string(data), env); err != nil {
			return fmt.Errorf("before.sh: %w", err)
		}
		printDone("        before.sh", time.Since(t0))
	}

	filesDir := filepath.Join(templatePath, "files")
	if info, err := os.Stat(filesDir); err == nil && info.IsDir() {
		t0 := time.Now()
		n := countTreeEntries(filesDir)
		printStep("        push files/ (%d entries)…", n)
		if err := pushTemplateFilesTar(srv, instance, filesDir, manifest.Files); err != nil {
			return fmt.Errorf("push files/: %w", err)
		}
		printDone("        push files/", time.Since(t0))
	}

	afterSh := filepath.Join(templatePath, "after.sh")
	if data, err := os.ReadFile(afterSh); err == nil {
		t0 := time.Now()
		printStep("        after.sh…")
		if err := execIn(srv, instance, string(data), env); err != nil {
			return fmt.Errorf("after.sh: %w", err)
		}
		printDone("        after.sh", time.Since(t0))
	}
	return nil
}

// countTreeEntries returns how many regular files + directories live
// under dir. Used only for progress display so a "push files/ tree"
// step shows the operator whether they're pushing 3 files or 300.
func countTreeEntries(dir string) int {
	n := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return nil
		}
		n++
		return nil
	})
	return n
}

// printStep writes a progress line to stderr. Format string same as
// Printf. Kept separate from stdout so pipelines capturing sync
// output (jq, tee) see clean data.
func printStep(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// printDone writes a "step done in <duration>" line, right-aligned
// duration for scan-ability. Follows a matching printStep line.
func printDone(label string, dur time.Duration) {
	fmt.Fprintf(os.Stderr, "%s   ✓  [%s]\n", label, dur.Round(100*time.Millisecond))
}

// resolveTemplateSecrets looks up each declared secret in the loaded
// secrets map and returns the env-var-to-value mapping to pass into
// before.sh / after.sh. Missing paths are hard errors — templates
// declaring a secret assert that it exists.
func resolveTemplateSecrets(t model.Template, secrets map[string]any) (map[string]string, error) {
	if len(t.Secrets) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(t.Secrets))
	for _, s := range t.Secrets {
		if s.Env == "" || s.From == "" {
			return nil, fmt.Errorf("template %q: secret entry missing env or from", t.Name)
		}
		v, err := lookupSecretPath(secrets, s.From)
		if err != nil {
			return nil, fmt.Errorf("template %q secret %q: %w", t.Name, s.Env, err)
		}
		out[s.Env] = v
	}
	return out, nil
}

// lookupSecretPath resolves a dotted path in a nested map. Copy of
// config.LookupSecret to avoid an import cycle (config depends on
// this package via loader→fleet, not the other way).
func lookupSecretPath(secrets map[string]any, path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty secret path")
	}
	parts := strings.Split(path, ".")
	var cur any = secrets
	for i, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s is not a mapping", strings.Join(parts[:i], "."))
		}
		v, ok := m[p]
		if !ok {
			return "", fmt.Errorf("missing at %s", strings.Join(parts[:i+1], "."))
		}
		cur = v
	}
	s, ok := cur.(string)
	if !ok {
		return "", fmt.Errorf("value is not a string (got %T)", cur)
	}
	return s, nil
}

// readTemplateManifest reads manifest.yaml if it exists. Absent manifest
// is not an error — older fleet templates may have no manifest.
func readTemplateManifest(templatePath string) (model.Template, error) {
	var t model.Template
	path := filepath.Join(templatePath, "manifest.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return t, nil
		}
		return t, fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &t); err != nil {
		return t, fmt.Errorf("parse %s: %w", path, err)
	}
	return t, nil
}

// pushTemplateFilesTar tars the entire files/ tree in-memory and streams
// it into `tar -xf - -C /` inside the container. Handles nested paths
// without needing to mkdir -p each parent.
//
// Ownership: always root:root — host filesystem uids are meaningless
// inside the container.
//
// Modes: applied from `fileMeta` (manifest.yaml files: map) if the entry
// is listed there; otherwise defaults are 0644 for regular files and
// 0755 for directories. Host filesystem mode is IGNORED for regular
// files so a git-checked-out fleet with default umask produces the same
// container state on every machine.
//
// Both Alpine (busybox tar) and Debian (GNU tar) accept this invocation.
func pushTemplateFilesTar(srv incusclient.InstanceServer, instance, filesDir string, fileMeta map[string]model.TemplateFileMeta) error {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	err := filepath.WalkDir(filesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == filesDir {
			return nil
		}
		rel, err := filepath.Rel(filesDir, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		// WalkDir uses Lstat semantics — a symlink shows up as itself,
		// not its target. tar.FileInfoHeader's second arg (the link
		// target) is required for a symlink entry to mean anything; we
		// don't have a sensible one to give it (a git-committed
		// symlink's target is host-relative, not container-relative),
		// so a symlink here would tar up as TypeSymlink with an empty
		// Linkname — broken on extraction, and not obviously so.
		// files/ trees are meant to be plain config, not symlink farms;
		// reject rather than guess.
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlinks are not supported under files/ (found %s) — "+
				"use before.sh/after.sh to create one inside the container instead",
				filesDir, rel)
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if d.IsDir() {
			hdr.Name += "/"
		}

		// Defaults: root:root, 0755 dirs / 0644 files. Host filesystem
		// mode is intentionally ignored for regular files so a git
		// checkout with any umask produces the same container state.
		hdr.Uid = 0
		hdr.Gid = 0
		hdr.Uname = "root"
		hdr.Gname = "root"
		if d.IsDir() {
			hdr.Mode = 0o755
		} else if d.Type().IsRegular() {
			hdr.Mode = 0o644
		}

		// Manifest override wins where declared.
		//
		// Owner/group as NAMES ride in Uname/Gname. tar-extract inside
		// the container resolves them via getpwnam/getgrnam. That
		// requires the user/group to exist BEFORE the tar-push — the
		// template's before.sh is where you create them. If lookup
		// fails, tar falls back to numeric Uid/Gid = 0 (root).
		containerPath := "/" + rel
		if meta, ok := fileMeta[containerPath]; ok {
			if meta.Owner != "" {
				hdr.Uname = meta.Owner
			}
			if meta.Group != "" {
				hdr.Gname = meta.Group
			}
			if meta.Mode != "" {
				parsed, err := strconv.ParseInt(meta.Mode, 8, 32)
				if err != nil {
					return fmt.Errorf("template file %q: invalid mode %q: %w", containerPath, meta.Mode, err)
				}
				hdr.Mode = parsed
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.Type().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}

	var stderr bytes.Buffer
	req := api.InstanceExecPost{
		Command:     []string{"tar", "-xf", "-", "-C", "/"},
		WaitForWS:   true,
		Interactive: false,
	}
	args := incusclient.InstanceExecArgs{
		Stdin:  &buf,
		Stdout: io.Discard,
		Stderr: &stderr,
	}
	op, err := srv.ExecInstance(instance, req, &args)
	if err != nil {
		return err
	}
	if err := op.Wait(); err != nil {
		return err
	}
	if md := op.Get().Metadata; md != nil {
		if rc, ok := md["return"]; ok {
			if code, ok := rc.(float64); ok && code != 0 {
				return fmt.Errorf("tar exit %d: %s", int(code), strings.TrimSpace(stderr.String()))
			}
		}
	}
	return nil
}

// provisionFile is one file to push into a container during provisioning.
// Internal-only — not part of the YAML schema anymore. Populated by
// renderInterfaceTemplate for the interface config; the rest of the
// files come from tar-pushed template / instance directories.
type provisionFile struct {
	Path    string
	Content string
	Mode    string // octal, e.g. "0644"
}

// pushFile writes a single provision file into the container.
func pushFile(srv incusclient.InstanceServer, instance string, f provisionFile) error {
	mode := 0o644
	if f.Mode != "" {
		parsed, err := strconv.ParseUint(f.Mode, 8, 32)
		if err != nil {
			return fmt.Errorf("bad file mode %q: %w", f.Mode, err)
		}
		mode = int(parsed)
	}
	args := incusclient.InstanceFileArgs{
		Content: bytes.NewReader([]byte(f.Content)),
		Type:    "file",
		Mode:    mode,
		UID:     0,
		GID:     0,
	}
	return srv.CreateInstanceFile(instance, f.Path, args)
}

// execIn runs `sh -c "<cmd>"` inside the container. Stderr is captured
// and included in the error message on non-zero exit — critical for
// debugging a failed provision at 300-container scale.
func execIn(srv incusclient.InstanceServer, instance, cmd string, env map[string]string) error {
	var stderr bytes.Buffer
	req := api.InstanceExecPost{
		Command:     []string{"sh", "-c", cmd},
		WaitForWS:   true,
		Interactive: false,
		Environment: env,
	}
	args := incusclient.InstanceExecArgs{
		Stdin:  nil,
		Stdout: io.Discard,
		Stderr: &stderr,
	}
	op, err := srv.ExecInstance(instance, req, &args)
	if err != nil {
		return err
	}
	if err := op.Wait(); err != nil {
		return err
	}
	if md := op.Get().Metadata; md != nil {
		if rc, ok := md["return"]; ok {
			if code, ok := rc.(float64); ok && code != 0 {
				return fmt.Errorf("exit %d: %s", int(code), strings.TrimSpace(stderr.String()))
			}
		}
	}
	return nil
}

// renderInterfaceTemplate materialises the distro-specific network file
// from the instance's ip4/ip6 fields. Returns a provisionFile with path
// + content pre-filled.
func renderInterfaceTemplate(kind string, inst model.Instance) (provisionFile, error) {
	entry, ok := interfaceTemplates[kind]
	if !ok {
		return provisionFile{}, fmt.Errorf(
			"unknown interface template %q (supported: alpine, debian-networkd, debian-interfaces)",
			kind)
	}
	ip6 := strings.TrimSpace(inst.IP6)
	prefix := inst.IP6PrefixLength
	if prefix == 0 {
		prefix = 80 // /80 is a common per-tenant IPv6 prefix size by convention.
	}
	gateway := strings.TrimSpace(inst.IP6Gateway)
	if gateway == "" && ip6 != "" {
		derived, err := deriveGateway(ip6, prefix)
		if err != nil {
			return provisionFile{}, fmt.Errorf("derive ip6 gateway: %w", err)
		}
		gateway = derived
	}
	data := struct {
		IP4       string
		IP4Prefix int
		IP4GW     string
		IP6       string
		IP6Prefix int
		IP6GW     string
	}{
		IP4:       strings.TrimSpace(inst.IP4),
		IP4Prefix: inst.IP4PrefixLength,
		IP4GW:     strings.TrimSpace(inst.IP4Gateway),
		IP6:       ip6,
		IP6Prefix: prefix,
		IP6GW:     gateway,
	}

	t, err := template.New(kind).Parse(entry.tpl)
	if err != nil {
		return provisionFile{}, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return provisionFile{}, err
	}
	return provisionFile{
		Path:    entry.path,
		Content: buf.String(),
		Mode:    "0644",
	}, nil
}

// deriveGateway returns the ::1 host of the /prefix network that contains ip.
// For /80 networks this reliably yields e.g. 2001:db8:1::1 from a
// 2a03:...100::80/80 address.
func deriveGateway(ip string, prefix int) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", err
	}
	if !addr.Is6() {
		return "", fmt.Errorf("%q is not IPv6", ip)
	}
	pfx, err := addr.Prefix(prefix)
	if err != nil {
		return "", err
	}
	b := pfx.Addr().As16()
	b[15] |= 1
	return netip.AddrFrom16(b).String(), nil
}

// interfaceTemplates: distro → (template, target path).
// Kept minimal. `accept_ra 2` on Alpine lets the default gateway come
// from Incus's dnsmasq RA while the specific address stays static.
var interfaceTemplates = map[string]struct {
	tpl  string
	path string
}{}

func init() {
	// Templates mix-and-match per protocol: v4 and v6 are chosen
	// independently. If an IP is declared, that protocol is static;
	// otherwise it falls back to DHCP (v4) or SLAAC/RA (v6).
	// A common shape is "static v6, DHCP v4" — Incus's dnsmasq
	// hands out v4 leases while operators pin v6 for stable ACL refs.
	interfaceTemplates["alpine"] = struct {
		tpl  string
		path string
	}{
		path: "/etc/network/interfaces",
		tpl: `auto eth0
{{- if .IP4}}
iface eth0 inet static
    address {{.IP4}}/{{.IP4Prefix}}
    gateway {{.IP4GW}}
{{- else}}
iface eth0 inet dhcp
{{- end}}
{{- if .IP6}}
iface eth0 inet6 static
    address {{.IP6}}/{{.IP6Prefix}}
    gateway {{.IP6GW}}
{{- else}}
iface eth0 inet6 auto
{{- end}}
hostname $(hostname)
`,
	}

	interfaceTemplates["debian-interfaces"] = struct {
		tpl  string
		path string
	}{
		path: "/etc/network/interfaces.d/eth0",
		tpl: `auto eth0
{{- if .IP4}}
iface eth0 inet static
    address {{.IP4}}/{{.IP4Prefix}}
    gateway {{.IP4GW}}
{{- else}}
iface eth0 inet dhcp
{{- end}}
{{- if .IP6}}
iface eth0 inet6 static
    address {{.IP6}}/{{.IP6Prefix}}
    gateway {{.IP6GW}}
{{- else}}
iface eth0 inet6 auto
{{- end}}
`,
	}

	interfaceTemplates["debian-networkd"] = struct {
		tpl  string
		path string
	}{
		path: "/etc/systemd/network/20-incus-sync.network",
		tpl: `[Match]
Name=eth0

[Network]
{{- if not .IP4}}
DHCP=ipv4
{{- end}}
{{- if .IP4}}
Address={{.IP4}}/{{.IP4Prefix}}
Gateway={{.IP4GW}}
{{- end}}
{{- if .IP6}}
Address={{.IP6}}/{{.IP6Prefix}}
Gateway={{.IP6GW}}
{{- else}}
IPv6AcceptRA=yes
{{- end}}
`,
	}
}
