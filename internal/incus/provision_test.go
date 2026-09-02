package incus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/incus-sync/internal/model"
)

// TestRenderInterfaceTemplateStaticIPv4 guards the bug found in code
// review: a static ip4 rendered with no netmask/prefix and no gateway
// on all three interface templates, producing an incomplete (and on
// debian-networkd, arguably invalid) network config. validate now
// requires ip4_prefix_length + ip4_gateway whenever ip4 is set — this
// checks the renderer actually uses them.
func TestRenderInterfaceTemplateStaticIPv4(t *testing.T) {
	inst := model.Instance{
		IP4:             "203.0.113.10",
		IP4PrefixLength: 24,
		IP4Gateway:      "203.0.113.1",
	}
	for _, kind := range []string{"alpine", "debian-interfaces", "debian-networkd"} {
		t.Run(kind, func(t *testing.T) {
			f, err := renderInterfaceTemplate(kind, inst)
			if err != nil {
				t.Fatalf("render %s: %v", kind, err)
			}
			for _, want := range []string{"203.0.113.10/24", "203.0.113.1"} {
				if !strings.Contains(f.Content, want) {
					t.Errorf("%s: expected %q in rendered content:\n%s", kind, want, f.Content)
				}
			}
		})
	}
}

// TestPushTemplateFilesTarRejectsSymlinks guards the bug found in code
// review: a symlink under files/ tarred up as TypeSymlink with an
// empty Linkname (WalkDir sees the symlink itself via Lstat, and there
// is no sensible container-relative target to give it) — broken on
// extraction, silently. Reject it instead.
func TestPushTemplateFilesTarRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks not supported on this filesystem: %v", err)
	}

	// srv is never reached — pushTemplateFilesTar must fail during the
	// WalkDir pass, before it ever calls srv.ExecInstance.
	err := pushTemplateFilesTar(nil, "some-instance", dir, nil)
	if err == nil {
		t.Fatal("expected an error for a symlink under files/, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected error to mention symlinks, got: %v", err)
	}
}
