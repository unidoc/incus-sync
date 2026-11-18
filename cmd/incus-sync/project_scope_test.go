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

// An explicit --project is queried as given (after the fleet-wide
// allowlist check), without asking the server.
func TestProjectsToQueryExplicitProject(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web", "db"})
	srv := &fakeLister{}

	query, skipped, err := projectsToQuery(dir, srv, "db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(query, []string{"db"}) || skipped != nil {
		t.Errorf("got query=%v skipped=%v, want [db] and none", query, skipped)
	}
	if srv.calls != 0 {
		t.Errorf("explicit --project asked the server %d time(s), want 0", srv.calls)
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

// A failed load must not leave an empty hosts/<host>/ behind; a
// directory that already existed must be kept.
func TestLoadFleetForBootstrapCleansUpOnFailure(t *testing.T) {
	dir := t.TempDir() // no fleet.yaml, so Load fails
	if _, _, _, err := loadFleetForBootstrap(dir, "newhost"); err == nil {
		t.Fatal("expected Load to fail without fleet.yaml")
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts", "newhost")); !os.IsNotExist(err) {
		t.Errorf("hosts/newhost left behind after a failed load (stat err %v)", err)
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
	if !created || hostDir != filepath.Join(dir, "hosts", "newhost") || len(f.Projects) != 0 {
		t.Errorf("got created=%v dir=%q projects=%v", created, hostDir, f.Projects)
	}
}

// orphans must not print an all-clear when it looked at no project.
func TestRunOrphansNoAllClearWhenNothingChecked(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	runErr := runOrphans(&config.Fleet{}, nil, "newhost", nil)
	os.Stdout = old
	w.Close()
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatalf("runOrphans: %v", runErr)
	}
	if strings.Contains(string(out), "under fleet control") || !strings.Contains(string(out), "cannot say") {
		t.Errorf("unexpected output with nothing checked: %q", out)
	}
}
