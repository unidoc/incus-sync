// incus-sync — declarative management for a fleet of Incus hosts.
//
// The tool operates on a config repository laid out as:
//
//	shared/           # objects applied to every host (address sets, ACLs)
//	hosts/<name>/     # host-specific extensions
//
// The config repository lives separately from this tool. Point at it with
// --config-dir <path>, the INCUS_SYNC_FLEET_PATH env var, or run the tool
// from within the config repo (default: current directory).
//
// The tool reconciles YAML state to the local Incus daemon via unix socket.
// Read-only commands (validate, render, diff, adopt) are always safe;
// sync is the only writing command.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/vault"
)

// configDir is populated from --config-dir / $INCUS_SYNC_FLEET_PATH / cwd.
// Subcommands read it after PersistentPreRun resolves the value.
// configDirSource records how it was resolved (for doctor).
var (
	configDir       string
	configDirSource string
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
	// LoadRemote will call SOPS, which reads the age key. Make sure
	// the vault is unlocked (auto-prompts on TTY if missing/expired).
	meta, err := config.LoadFleetMeta(configDir)
	if err != nil {
		return nil, err
	}
	if _, err := vault.EnsureUnlocked(meta.Name, promptPassphrase); err != nil {
		return nil, err
	}
	r, err := config.LoadRemote(configDir, host)
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
// Multi-project commands (sync, diff, list) do NOT call this — they
// iterate fleet.Projects internally.
func resolveProject(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	meta, err := config.LoadFleetMeta(configDir)
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
from a YAML config repository to the local Incus daemon.

The config repository is resolved in this order:
  1. --config-dir <path>
  2. $INCUS_SYNC_FLEET_PATH
  3. current working directory`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return resolveConfigDir()
		},
	}

	root.PersistentFlags().StringVar(&configDir, "config-dir", "",
		"Path to the config repo (default: $INCUS_SYNC_FLEET_PATH or cwd)")

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

func resolveConfigDir() error {
	if configDir != "" {
		configDirSource = "--config-dir"
	} else if v := os.Getenv("INCUS_SYNC_FLEET_PATH"); v != "" {
		configDir = v
		configDirSource = "$INCUS_SYNC_FLEET_PATH"
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("determine cwd: %w", err)
		}
		configDir = cwd
		configDirSource = "cwd"
	}
	info, err := os.Stat(configDir)
	if err != nil {
		return fmt.Errorf("config dir %q: %w  (set INCUS_SYNC_FLEET_PATH or pass --config-dir)", configDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("config dir %q is not a directory", configDir)
	}
	return nil
}
