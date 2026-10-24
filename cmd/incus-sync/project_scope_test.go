package main

// Regression: `list`/`orphans --project X` must query X directly when X
// isn't (yet) in this host's narrowed fleet.Projects, instead of
// silently filtering an empty loop and reporting "nothing found".

import (
	"os"
	"path/filepath"
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

func TestProjectsToQueryDefaultsToHostScope(t *testing.T) {
	fleet := &config.Fleet{Projects: []string{"web"}}
	got, err := projectsToQuery("", fleet, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "web" {
		t.Errorf("got %v, want [web]", got)
	}
}

// TestProjectsToQueryExplicitProjectBypassesNarrowing is the fix this
// guards: --project db must query db even though this
// host's narrowed fleet.Projects is only [web].
func TestProjectsToQueryExplicitProjectBypassesNarrowing(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web", "db"})
	fleet := &config.Fleet{Projects: []string{"web"}} // host-narrowed: no db

	got, err := projectsToQuery(dir, fleet, "db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "db" {
		t.Errorf("got %v, want [db] — an explicit --project must not be silently dropped by host narrowing", got)
	}
}

func TestProjectsToQueryRejectsProjectNotInFleet(t *testing.T) {
	dir := writeTestFleetYAML(t, []string{"web"})
	fleet := &config.Fleet{Projects: []string{"web"}}

	_, err := projectsToQuery(dir, fleet, "nope")
	if err == nil || !strings.Contains(err.Error(), "not in fleet.yaml's") {
		t.Fatalf("expected a fleet-wide allowlist error, got %v", err)
	}
}
