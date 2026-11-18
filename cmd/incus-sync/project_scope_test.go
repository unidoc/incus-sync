package main

// list/orphans must look in every fleet-wide project the host has, not
// only the projects this host's instance files use, so containers with
// no instance file yet still show (the case orphans exists for).

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/unidoc/incus-sync/internal/config"
)

func writeTestFleetYAML(t *testing.T, projects []string) string {
	t.Helper()
	dir := t.TempDir()
	body := "projects:\n"
	for _, p := range projects {
		body += "  - " + p + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "fleet.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type fakeLister struct {
	names []string
	err   error
	calls int
}

func (f *fakeLister) GetProjectNames() ([]string, error) {
	f.calls++
	return f.names, f.err
}

// TestProjectsToQueryDefaultChecksFleetProjectsHostHas is the F1 fix: a
// host with no instance files (narrowed set empty) still has its fleet
// projects checked, and a fleet project the host lacks is reported as
// skipped instead of queried.
func TestProjectsToQueryDefaultChecksFleetProjectsHostHas(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web", "db"})
	srv := &fakeLister{names: []string{"default", "web"}}

	query, skipped, err := projectsToQuery(dir, srv, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(query, []string{"web"}) {
		t.Errorf("query = %v, want [web]", query)
	}
	if !slices.Equal(skipped, []string{"db"}) {
		t.Errorf("skipped = %v, want [db]", skipped)
	}
}

func TestProjectsToQueryDefaultFailsWhenProjectListFails(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web"})
	_, _, err := projectsToQuery(dir, &fakeLister{err: errors.New("boom")}, "")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected the server error, got %v", err)
	}
}

// An explicit --project is queried as given, but only if the host lists
// it: Incus returns an empty instance list (no error) for a project that
// does not exist or that a restricted cert cannot see.
func TestProjectsToQueryExplicitProject(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web", "db"})

	query, skipped, err := projectsToQuery(dir, &fakeLister{names: []string{"default", "db"}}, "db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(query, []string{"db"}) || skipped != nil {
		t.Errorf("got query=%v skipped=%v, want [db] and none", query, skipped)
	}

	_, _, err = projectsToQuery(dir, &fakeLister{names: []string{"default", "web"}}, "db")
	if err == nil || !strings.Contains(err.Error(), "not visible to its cert") {
		t.Fatalf("expected an error for a project the host does not list, got %v", err)
	}
}

func TestProjectsToQueryRejectsProjectNotInFleet(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web"})
	_, _, err := projectsToQuery(dir, &fakeLister{}, "nope")
	if err == nil || !strings.Contains(err.Error(), "not in fleet.yaml's") {
		t.Fatalf("expected a fleet-wide allowlist error, got %v", err)
	}
}

func TestCheckProjects(t *testing.T) {
	lines, ok := checkProjects([]string{"web", "db"}, []string{"default", "web"})
	if ok {
		t.Error("ok = true with db not listed, want false")
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "present") || !strings.Contains(lines[1], "not visible to this cert") {
		t.Errorf("unexpected lines: %q", lines)
	}
	if _, ok := checkProjects([]string{"web"}, []string{"web"}); !ok {
		t.Error("ok = false with every project listed, want true")
	}
}

// A failed load must not leave an empty hosts/<host>/ (or hosts/)
// behind; a directory that already existed must be kept.
func TestLoadFleetForBootstrapCleansUpOnFailure(t *testing.T) {
	dir := t.TempDir() // no fleet.yaml, so Load fails
	if _, _, _, err := loadFleetForBootstrap(dir, "newhost"); err == nil {
		t.Fatal("expected Load to fail without fleet.yaml")
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts")); !os.IsNotExist(err) {
		t.Errorf("hosts/ left behind after a failed load (stat err %v)", err)
	}

	existing := filepath.Join(dir, "hosts", "oldhost")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadFleetForBootstrap(dir, "oldhost"); err == nil {
		t.Fatal("expected Load to fail without fleet.yaml")
	}
	if _, err := os.Stat(existing); err != nil {
		t.Errorf("pre-existing hosts/oldhost was removed: %v", err)
	}
}

func TestLoadFleetForBootstrapReportsCreated(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web"})
	f, hostDir, created, err := loadFleetForBootstrap(dir, "newhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{filepath.Join(dir, "hosts", "newhost"), filepath.Join(dir, "hosts")}
	if !slices.Equal(created, want) || hostDir != want[0] || len(f.Projects) != 0 {
		t.Errorf("got created=%v dir=%q projects=%v", created, hostDir, f.Projects)
	}
}

func TestShouldPrintScopeNote(t *testing.T) {
	newHost := &config.Fleet{NetworkProject: "default"}
	usedHost := &config.Fleet{NetworkProject: "default", Projects: []string{"web"}}
	cases := []struct {
		name          string
		fleet         *config.Fleet
		fleetProjects []string
		scope         []string
		extra         []string
		want          bool
	}{
		{"new host, cert misses fleet projects", newHost, []string{"web", "db"}, []string{"default"}, nil, true},
		{"new host, one-project fleet not default", newHost, []string{"web"}, []string{"default"}, nil, true},
		{"new host, cert covers the only project", newHost, []string{"default"}, []string{"default"}, nil, false},
		{"new host, --projects given", newHost, []string{"web", "db"}, []string{"default", "web"}, []string{"web"}, false},
		{"new host, blank --projects", newHost, []string{"web"}, []string{"default"}, []string{" "}, true},
		{"host with instances", usedHost, []string{"web", "db"}, []string{"default", "web"}, nil, false},
	}
	for _, c := range cases {
		if got := shouldPrintScopeNote(c.fleet, c.fleetProjects, c.scope, c.extra); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// writeHostFleet writes fleet.yaml plus one host with the given
// instance->project files.
func writeHostFleet(t *testing.T, fleetYAML, host string, instances map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fleet.yaml"), []byte(fleetYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "hosts", host), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, project := range instances {
		d := filepath.Join(dir, "hosts", host, "instances", name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "instance: " + name + "\nproject: " + project + "\n"
		if err := os.WriteFile(filepath.Join(d, "instance.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDeepProjectCheck(t *testing.T) {
	dir := writeHostFleet(t, "projects:\n  - web\n  - db\n", "h", map[string]string{"app": "web"})

	lines, ok, np, fatal := deepProjectCheck(dir, "h", &fakeLister{names: []string{"default", "web"}})
	if !ok || fatal || np != "default" || len(lines) != 1 || !strings.Contains(lines[0], "present") {
		t.Errorf("present: ok=%v fatal=%v np=%q lines=%q", ok, fatal, np, lines)
	}

	_, ok, _, _ = deepProjectCheck(dir, "h", &fakeLister{names: []string{"default"}})
	if ok {
		t.Error("ok = true with web not listed, want false")
	}

	// Fleet fails to load (unknown host): reported, not fatal, network
	// project still taken from fleet.yaml so the other checks run.
	srv := &fakeLister{}
	lines, ok, np, fatal = deepProjectCheck(dir, "nohost", srv)
	if ok || fatal || np != "default" || srv.calls != 0 || !strings.Contains(lines[0], "project check skipped") {
		t.Errorf("load failure: ok=%v fatal=%v np=%q calls=%d lines=%q", ok, fatal, np, srv.calls, lines)
	}

	// No fleet.yaml at all: fatal.
	if _, _, _, fatal := deepProjectCheck(t.TempDir(), "h", srv); !fatal {
		t.Error("fatal = false without fleet.yaml, want true")
	}

	// Nothing to check: the server is not asked.
	empty := writeHostFleet(t, "projects:\n  - web\n", "h", nil)
	srv = &fakeLister{err: errors.New("unreachable")}
	if _, ok, _, _ := deepProjectCheck(empty, "h", srv); !ok || srv.calls != 0 {
		t.Errorf("nothing to check: ok=%v calls=%d", ok, srv.calls)
	}
}

func captureStdout(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	runErr := f()
	w.Close()
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}
	return string(out)
}

// A managed instance in a project that was not queried is NOT-CHECKED,
// not MISSING.
func TestRunListNotChecked(t *testing.T) {
	dir := writeHostFleet(t, "projects:\n  - web\n  - db\n", "h", map[string]string{"a": "web", "b": "db"})
	fleet, err := config.Load(dir, "h")
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() error { return runList(fleet, nil, []string{"web"}) })
	for _, want := range []string{"a  ", "MISSING", "b  ", "NOT-CHECKED"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "MISSING") != 1 {
		t.Errorf("want exactly one MISSING row:\n%s", out)
	}
}

// orphans must not print an all-clear when it looked at no project.
func TestRunOrphansNoAllClearWhenNothingChecked(t *testing.T) {
	out := captureStdout(t, func() error { return runOrphans(&config.Fleet{}, nil, "newhost", nil) })
	if strings.Contains(out, "under fleet control") || !strings.Contains(out, "cannot say") {
		t.Errorf("unexpected output with nothing checked: %q", out)
	}
}

func TestBootstrapCertProjects(t *testing.T) {
	fleet := &config.Fleet{NetworkProject: "default"} // new host: no instances
	got, err := bootstrapCertProjects(fleet, []string{"web", "db"}, []string{"web", " web", ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(got, []string{"default", "web"}) {
		t.Errorf("got %v, want [default web]", got)
	}
	if _, err := bootstrapCertProjects(fleet, []string{"web"}, []string{"nope"}); err == nil {
		t.Error("expected an error for a --projects entry not in fleet.yaml")
	}
}

func TestCheckExplicitProjectEarly(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web"})
	if err := checkExplicitProjectEarly(dir, ""); err != nil {
		t.Errorf("empty --project: %v", err)
	}
	if err := checkExplicitProjectEarly(dir, "web"); err != nil {
		t.Errorf("--project web: %v", err)
	}
	if err := checkExplicitProjectEarly(dir, "nope"); err == nil {
		t.Error("expected an error for --project nope")
	}
}
