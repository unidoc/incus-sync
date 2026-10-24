package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFleet lays out a minimal multi-host, multi-project fleet under
// t.TempDir(): fleet.yaml (with the given host_projects block) plus one
// instance per (host, project) pair in instancesByHost.
func writeFleet(t *testing.T, hostProjectsYAML string, instancesByHost map[string]map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	fleetYAML := "projects:\n  - unidoc\n  - foxyutils\n" + hostProjectsYAML
	if err := os.WriteFile(filepath.Join(dir, "fleet.yaml"), []byte(fleetYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	for host, instances := range instancesByHost {
		for name, project := range instances {
			instDir := filepath.Join(dir, "hosts", host, "instances", name)
			if err := os.MkdirAll(instDir, 0o755); err != nil {
				t.Fatal(err)
			}
			body := "instance: " + name + "\nproject: " + project + "\n"
			if err := os.WriteFile(filepath.Join(instDir, "instance.yaml"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Hosts with zero instances still need a directory to exist (Load
	// stats hosts/<host>/ up front).
	for host := range instancesByHost {
		if err := os.MkdirAll(filepath.Join(dir, "hosts", host), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestHostProjectsNarrowedToInstancesUsed is the core regression: a
// project used by one host's instances must never show up in another
// host's effective Projects, even though both are declared fleet-wide.
func TestHostProjectsNarrowedToInstancesUsed(t *testing.T) {
	dir := writeFleet(t, "", map[string]map[string]string{
		"hosta": {"web-a": "unidoc"},
		"hostb": {"web-b": "foxyutils"},
	})

	fa, err := Load(dir, "hosta")
	if err != nil {
		t.Fatalf("Load(hosta): %v", err)
	}
	if got := fa.Projects; len(got) != 1 || got[0] != "unidoc" {
		t.Errorf("hosta Projects = %v, want [unidoc]", got)
	}

	fb, err := Load(dir, "hostb")
	if err != nil {
		t.Fatalf("Load(hostb): %v", err)
	}
	if got := fb.Projects; len(got) != 1 || got[0] != "foxyutils" {
		t.Errorf("hostb Projects = %v, want [foxyutils] — a project only hostb uses must not leak onto hosta and vice versa", got)
	}
}

// TestHostWithNoInstancesHasEmptyProjects: a host that declares no
// instances yet (and no host_projects override) manages nothing — it
// must never be scoped to the fleet-wide project list by default.
func TestHostWithNoInstancesHasEmptyProjects(t *testing.T) {
	dir := writeFleet(t, "", map[string]map[string]string{
		"hosta": {"web-a": "unidoc"},
		"hostb": {}, // no instances at all
	})
	fb, err := Load(dir, "hostb")
	if err != nil {
		t.Fatalf("Load(hostb): %v", err)
	}
	if len(fb.Projects) != 0 {
		t.Errorf("hostb Projects = %v, want empty", fb.Projects)
	}
}

// TestHostProjectsExplicitEntry: fleet.yaml's host_projects escape hatch
// pre-declares a project for a host before any instance uses it (e.g.
// so `doctor --deep`/`remote bootstrap` know about it).
func TestHostProjectsExplicitEntry(t *testing.T) {
	dir := writeFleet(t, "host_projects:\n  hostb:\n    - foxyutils\n", map[string]map[string]string{
		"hostb": {}, // no instances yet
	})
	fb, err := Load(dir, "hostb")
	if err != nil {
		t.Fatalf("Load(hostb): %v", err)
	}
	if got := fb.Projects; len(got) != 1 || got[0] != "foxyutils" {
		t.Errorf("hostb Projects = %v, want [foxyutils] from host_projects", got)
	}
}

// TestHostProjectsRejectsUnknownProject: host_projects can only grant
// access to a project already declared fleet-wide.
func TestHostProjectsRejectsUnknownProject(t *testing.T) {
	dir := writeFleet(t, "host_projects:\n  hostb:\n    - nope\n", map[string]map[string]string{
		"hostb": {},
	})
	_, err := Load(dir, "hostb")
	if err == nil || !strings.Contains(err.Error(), "not in the top-level") {
		t.Fatalf("expected a host_projects validation error, got %v", err)
	}
}

// TestInstanceProjectStillValidatedFleetWide: an instance declaring a
// project absent from fleet.yaml's top-level `projects:` list is still
// a hard error, independent of host scoping.
func TestInstanceProjectStillValidatedFleetWide(t *testing.T) {
	dir := writeFleet(t, "", map[string]map[string]string{
		"hosta": {"web-a": "not-declared"},
	})
	_, err := Load(dir, "hosta")
	if err == nil || !strings.Contains(err.Error(), "not in fleet.yaml projects list") {
		t.Fatalf("expected a projects-allowlist error, got %v", err)
	}
}

// TestHostProjectsTypoWarns: a host_projects key with no matching
// hosts/<host>/ directory is almost always a typo (the entry silently
// never applies otherwise) — it must surface as a warning, not stay quiet.
func TestHostProjectsTypoWarns(t *testing.T) {
	dir := writeFleet(t, "host_projects:\n  hosta-typo:\n    - foxyutils\n", map[string]map[string]string{
		"hosta": {"web-a": "unidoc"},
	})
	f, err := Load(dir, "hosta")
	if err != nil {
		t.Fatalf("Load(hosta): %v", err)
	}
	found := false
	for _, w := range f.Warnings {
		if strings.Contains(w, "hosta-typo") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning naming the unknown host_projects key %q, got %v", "hosta-typo", f.Warnings)
	}
}

// TestCertProjectsIsHostScoped mirrors the remote-bootstrap use: the
// cert for one host should never request access to another host's
// project.
func TestCertProjectsIsHostScoped(t *testing.T) {
	dir := writeFleet(t, "", map[string]map[string]string{
		"hosta": {"web-a": "unidoc"},
		"hostb": {"web-b": "foxyutils"},
	})
	fa, err := Load(dir, "hosta")
	if err != nil {
		t.Fatal(err)
	}
	got := fa.CertProjects()
	for _, p := range got {
		if p == "foxyutils" {
			t.Errorf("hosta CertProjects = %v, must not include foxyutils", got)
		}
	}
	if !strings.Contains(strings.Join(got, ","), "unidoc") {
		t.Errorf("hosta CertProjects = %v, want to include unidoc", got)
	}
}
