package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FleetMetaFilename is the repo-root config that declares the Incus
// projects this fleet manages. REQUIRED — the loader errors out if
// the file or the `projects:` list is missing.
const FleetMetaFilename = "fleet.yaml"

// FleetMeta is the parsed content of the fleet repo's fleet.yaml.
type FleetMeta struct {
	// Projects is the explicit list of Incus projects this fleet
	// manages. REQUIRED — no silent defaults. Every instance's
	// project: field must appear in this list.
	Projects []string `yaml:"projects"`

	// NetworkProject is where network ACLs + address-sets physically
	// live in Incus. Because bridge networks are default-project only
	// and features.networks=false on managed projects delegates to
	// the shared server-level namespace, this is "default" in the
	// vast majority of setups. The client cert MUST include this
	// project in its --projects scope so it can CRUD network resources.
	// Defaults to "default".
	NetworkProject string `yaml:"network_project,omitempty"`
}

// Validate returns nil iff the meta is complete. Called by LoadFleetMeta;
// exposed for cmd_validate.
func (m FleetMeta) Validate() error {
	if len(m.Projects) == 0 {
		return fmt.Errorf("%s: `projects:` list is required and must be non-empty", FleetMetaFilename)
	}
	return nil
}

// LoadFleetMeta reads fleet.yaml at fleetPath root. The file is
// REQUIRED — no legacy fallback. Every fleet declares its projects
// explicitly. NetworkProject defaults to "default" (server-level
// bridge namespace) but everything else must be spelled out.
func LoadFleetMeta(fleetPath string) (FleetMeta, error) {
	path := filepath.Join(fleetPath, FleetMetaFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FleetMeta{}, fmt.Errorf("%s missing — every fleet must declare `projects:` explicitly", path)
		}
		return FleetMeta{}, fmt.Errorf("%s: %w", path, err)
	}
	var m FleetMeta
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return FleetMeta{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return FleetMeta{}, err
	}
	if m.NetworkProject == "" {
		m.NetworkProject = "default"
	}
	return m, nil
}

// CertProjects returns the union of NetworkProject + Projects for the
// client TLS cert's --projects scope. The cert must access both:
// containers live in Projects, but ACLs/address-sets live in
// NetworkProject (typically "default"). Duplicates are removed.
func (m FleetMeta) CertProjects() []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(m.NetworkProject)
	for _, p := range m.Projects {
		add(p)
	}
	return out
}
