// incus-sync — declarative management for a fleet of Incus hosts.
//
// The tool operates on a fleet repo laid out as:
//
//	shared/           # objects applied to every host (address sets, ACLs)
//	hosts/<name>/     # host-specific extensions
//
// The fleet repo lives separately from this tool. Point at it with
// --fleet-path <path>, the INCUS_SYNC_FLEET_PATH env var, or run the tool
// from within the fleet repo (default: current directory).
//
// The tool reconciles YAML state to the local Incus daemon via unix socket.
// Read-only commands (validate, render, diff, adopt) are always safe;
// sync is the only writing command.
package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/vault"
)

// fleetPath is populated from --fleet-path / $INCUS_SYNC_FLEET_PATH / cwd.
// Subcommands read it after PersistentPreRun resolves the value.
// fleetPathSource records how it was resolved (for doctor).
var (
	fleetPath       string
	fleetPathSource string
)

// resolveRemoteForHost returns the Remote config to use when talking to
// Incus for `host`, or nil if the caller should use the local unix socket.
//
// Rules:
//   - host == local short hostname → nil (unix socket).
//   - hosts/<host>/remote.sops.yaml exists → decrypt and return it.
//   - Neither → error. Refuses to silently fall through to a local unix
//     socket for a foreign host name, because that has caused real
//     confusion ("I said --host web1, why did it hit localhost?").
//
// Callers that want the unix socket unconditionally should pass "" or
// the local hostname.
func resolveRemoteForHost(host string) (*config.Remote, error) {
	local := shortHostname()
	if host == "" || host == local {
		return nil, nil
	}
	// LoadRemote will call SOPS, which reads the age key. Fail fast
	// with a clear message if no backend is configured at all.
	if err := vault.EnsureUnlocked(); err != nil {
		return nil, err
	}
	r, err := config.LoadRemote(fleetPath, host)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf(
			"--host %s is not this machine (%s) and hosts/%s/remote.sops.yaml is missing. "+
				"Either run this on %s, or bootstrap the remote with `incus-sync remote bootstrap %s ...`",
			host, local, host, host, host)
	}
	return r, nil
}

// resolveProject returns a single Incus project scope for commands
// that operate on ONE project (shell, adopt, import, create). Rules:
//
//  1. Explicit --project flag wins.
//  2. Otherwise, if fleet.yaml declares exactly one project, use it
//     (unambiguous, no need to type it every time).
//  3. Otherwise, error — caller must pass --project.
//
// Multi-project commands do NOT call this: sync and diff iterate the
// host's fleet.Projects, list and orphans use projectsToQuery.
func resolveProject(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	meta, err := config.LoadFleetMeta(fleetPath)
	if err != nil {
		return "", err
	}
	if len(meta.Projects) == 1 {
		return meta.Projects[0], nil
	}
	return "", fmt.Errorf(
		"fleet manages multiple projects %v — pass --project to pick one",
		meta.Projects)
}

// projectLister is the one server call projectsToQuery needs, so tests
// can pass a fake instead of a live Incus connection.
type projectLister interface {
	GetProjectNames() ([]string, error)
}

// projectsToQuery returns the projects a read-only, multi-project command
// (list, orphans) should look in for one --host run, and the fleet-wide
// projects it skipped because the host does not have them.
//
//   - explicitProject == "": every project in fleet.yaml's fleet-wide
//     `projects:` list that the host actually has (as the server reports
//     it to this client). This is deliberately NOT the host-narrowed
//     fleet.Projects: list/orphans exist to find containers that have no
//     instance file yet, which is exactly when the narrowed set is empty
//     or missing the project. A project the host does not have (or that
//     this client's cert cannot see) is returned in skipped, so callers
//     can say what they did not look at.
//   - explicitProject != "": exactly that project, after checking it is
//     in the fleet-wide `projects:` list (a typo is a hard error). The
//     server is not asked, so a missing project fails loudly on query.
func projectsToQuery(fleetPath string, srv projectLister, explicitProject string) (query, skipped []string, err error) {
	meta, err := config.LoadFleetMeta(fleetPath)
	if err != nil {
		return nil, nil, err
	}
	if explicitProject != "" {
		if err := checkFleetProject(meta, explicitProject); err != nil {
			return nil, nil, err
		}
		return []string{explicitProject}, nil, nil
	}
	have, err := srv.GetProjectNames()
	if err != nil {
		return nil, nil, fmt.Errorf("list projects on host: %w", err)
	}
	for _, p := range meta.Projects {
		if slices.Contains(have, p) {
			query = append(query, p)
		} else {
			skipped = append(skipped, p)
		}
	}
	return query, skipped, nil
}

// checkFleetProject errors unless p is in fleet.yaml's projects list.
func checkFleetProject(meta config.FleetMeta, p string) error {
	if !slices.Contains(meta.Projects, p) {
		return fmt.Errorf("--project %q is not in fleet.yaml's `projects:` list %v", p, meta.Projects)
	}
	return nil
}

// checkExplicitProjectEarly validates --project before any remote is
// resolved or connected to, so a typo fails without a vault unlock.
func checkExplicitProjectEarly(fleetPath, p string) error {
	if p == "" {
		return nil
	}
	meta, err := config.LoadFleetMeta(fleetPath)
	if err != nil {
		return err
	}
	return checkFleetProject(meta, p)
}

// printProjectScope tells the operator which projects a list/orphans run
// looked in, and which fleet projects it could not, on stderr so stdout
// stays the table.
func printProjectScope(host string, query, skipped []string) {
	if len(query) == 0 {
		fmt.Fprintf(os.Stderr, "Checked no projects on %s.\n", host)
	} else {
		fmt.Fprintf(os.Stderr, "Checked projects on %s: %s\n", host, strings.Join(query, ", "))
	}
	if len(skipped) > 0 {
		fmt.Fprintf(os.Stderr, "Not on %s (or not visible to its cert): %s\n", host, strings.Join(skipped, ", "))
	}
}

// shortHostname returns the local short hostname, or "" if it can't be read.
func shortHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	for i := 0; i < len(h); i++ {
		if h[i] == '.' {
			return h[:i]
		}
	}
	return h
}

func main() {
	root := &cobra.Command{
		Use:   "incus-sync",
		Short: "Declarative sync of Incus network objects from a git repo",
		Long: `incus-sync reconciles Incus network address sets and ACLs
from a YAML fleet repo to the local Incus daemon.

The fleet repo is resolved in this order:
  1. --fleet-path <path>
  2. $INCUS_SYNC_FLEET_PATH
  3. current working directory`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return resolveFleetPath()
		},
	}

	root.PersistentFlags().StringVar(&fleetPath, "fleet-path", "",
		"Path to the fleet repo (default: $INCUS_SYNC_FLEET_PATH or cwd)")

	// Command groups (cobra 1.9+) — help output clusters by purpose so
	// newcomers see "Setup" and "Read-only" before the write commands.
	root.AddGroup(&cobra.Group{ID: "setup", Title: "Setup:"})
	root.AddGroup(&cobra.Group{ID: "read", Title: "Read-only (safe):"})
	root.AddGroup(&cobra.Group{ID: "write", Title: "Write (Incus-mutating):"})
	root.AddGroup(&cobra.Group{ID: "access", Title: "Container access:"})

	addWithGroup := func(cmd *cobra.Command, group string) {
		cmd.GroupID = group
		root.AddCommand(cmd)
	}
	addWithGroup(doctorCmd(), "setup")
	addWithGroup(validateCmd(), "setup")
	addWithGroup(renderCmd(), "read")
	addWithGroup(explainCmd(), "read")
	addWithGroup(refsCmd(), "read")
	addWithGroup(listCmd(), "read")
	addWithGroup(diffCmd(), "read")
	addWithGroup(syncCmd(), "write")
	addWithGroup(createCmd(), "write")
	addWithGroup(adoptCmd(), "write")
	addWithGroup(refreshNftCmd(), "write")
	addWithGroup(shellCmd(), "access")
	addWithGroup(pruneCheckCmd(), "read")
	addWithGroup(orphansCmd(), "read")
	addWithGroup(importCmd(), "write")
	addWithGroup(remoteCmd(), "setup")
	addWithGroup(vaultCmd(), "setup")
	addWithGroup(fleetCmd(), "write")
	root.AddCommand(versionCmd())

	if err := root.Execute(); err != nil {
		// SilenceErrors=true means cobra does NOT print the error itself.
		// We print once here with a stable "Error: " prefix.
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func resolveFleetPath() error {
	if fleetPath != "" {
		fleetPathSource = "--fleet-path"
	} else if v := os.Getenv("INCUS_SYNC_FLEET_PATH"); v != "" {
		fleetPath = v
		fleetPathSource = "$INCUS_SYNC_FLEET_PATH"
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine cwd: %w", err)
		}
		fleetPath = cwd
		fleetPathSource = "cwd"
	}
	info, err := os.Stat(fleetPath)
	if err != nil {
		return fmt.Errorf("fleet path %q: %w  (set INCUS_SYNC_FLEET_PATH or pass --fleet-path)", fleetPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("fleet path %q is not a directory", fleetPath)
	}
	return nil
}
