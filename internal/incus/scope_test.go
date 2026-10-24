package incus

// Guards the host-scoped-projects fix end-to-end: a fleet loaded via
// config.Load for one host must make ComputePlan query only the
// project(s) that host's own instances use, never a project that only
// exists because another host declares instances in it.

import (
	"os"
	"path/filepath"
	"testing"

	incusclient "github.com/lxc/incus/v7/client"
	"github.com/lxc/incus/v7/shared/api"

	"github.com/unidoc/incus-sync/internal/config"
)

// writeTwoHostFleet lays out a minimal fleet under t.TempDir() with two
// hosts in different projects: hosta/web-a in "unidoc", hostb/web-b in
// "foxyutils". Mirrors internal/config's own host_projects_test.go
// fixture, duplicated here since it's unexported in another package.
func writeTwoHostFleet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fleetYAML := "projects:\n  - unidoc\n  - foxyutils\n"
	if err := os.WriteFile(filepath.Join(dir, "fleet.yaml"), []byte(fleetYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, hip := range []struct{ host, inst, project string }{
		{"hosta", "web-a", "unidoc"},
		{"hostb", "web-b", "foxyutils"},
	} {
		instDir := filepath.Join(dir, "hosts", hip.host, "instances", hip.inst)
		if err := os.MkdirAll(instDir, 0o755); err != nil {
			t.Fatal(err)
		}
		body := "instance: " + hip.inst + "\nproject: " + hip.project + "\n"
		if err := os.WriteFile(filepath.Join(instDir, "instance.yaml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// scopeSrv records every project GetInstances is scoped to via
// UseProject, and fails the test outright if it's ever called against a
// project outside `allowed` — the regression this guards.
type scopeSrv struct {
	incusclient.InstanceServer
	t       *testing.T
	project string
	allowed map[string]bool
	queried map[string]bool
}

func (s *scopeSrv) UseProject(name string) incusclient.InstanceServer {
	return &scopeSrv{t: s.t, project: name, allowed: s.allowed, queried: s.queried}
}

func (s *scopeSrv) GetNetworkAddressSets() ([]api.NetworkAddressSet, error) { return nil, nil }
func (s *scopeSrv) GetNetworkACLs() ([]api.NetworkACL, error)               { return nil, nil }

func (s *scopeSrv) GetInstances(api.InstanceType) ([]api.Instance, error) {
	if !s.allowed[s.project] {
		s.t.Fatalf("ComputePlan queried instances in project %q — this host does not use it", s.project)
	}
	s.queried[s.project] = true
	return nil, nil
}

// TestComputePlanOnlyQueriesHostProjects is the end-to-end regression:
// loading hosta for real via config.Load (hostb owns "foxyutils", hosta
// owns "unidoc") must leave ComputePlan never touching "foxyutils" at
// all. Fails without narrowProjectsToHost, since fleet.Projects would
// then still be the fleet-wide ["unidoc", "foxyutils"] list.
func TestComputePlanOnlyQueriesHostProjects(t *testing.T) {
	dir := writeTwoHostFleet(t)
	fleet, err := config.Load(dir, "hosta")
	if err != nil {
		t.Fatalf("Load(hosta): %v", err)
	}
	if got := fleet.Projects; len(got) != 1 || got[0] != "unidoc" {
		t.Fatalf("fleet.Projects = %v, want [unidoc] (fixture/narrowing assumption broke)", got)
	}

	queried := map[string]bool{}
	srv := &scopeSrv{t: t, allowed: map[string]bool{"default": true, "unidoc": true}, queried: queried}

	if _, err := ComputePlan(srv, fleet); err != nil {
		t.Fatalf("ComputePlan: %v", err)
	}
	if !queried["unidoc"] {
		t.Error("expected ComputePlan to query the unidoc project")
	}
	if queried["foxyutils"] {
		t.Error("ComputePlan must never query a project this host doesn't list")
	}
}
