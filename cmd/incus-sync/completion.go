package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
)

// Cobra completion functions are called by the __complete subcommand and
// do NOT go through PersistentPreRunE, so fleetPath may still be empty.
// Every completer starts by resolving it silently — a failure just yields
// no suggestions rather than a distracting error.

func ensureFleetPath() bool {
	if fleetPath != "" {
		return true
	}
	return resolveFleetPath() == nil
}

// hostFromFlag reads --host from the command. Empty if not set.
// We do not fall back to local hostname — on a bastion that yields
// "gateway-bastion" which is never the intended target.
func hostFromFlag(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}
	if f := cmd.Flag("host"); f != nil {
		return f.Value.String()
	}
	return ""
}

// hostCompleter suggests entries under fleetPath/hosts/*/.
func hostCompleter(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if !ensureFleetPath() {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	entries, err := os.ReadDir(filepath.Join(fleetPath, "hosts"))
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// instanceCompleter suggests instance names for the current host (or
// --host if the user specified one).
func instanceCompleter(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if !ensureFleetPath() {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	host := hostFromFlag(cmd)
	if host == "" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	fleet, err := config.Load(fleetPath, host)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for n := range fleet.Instances {
		names = append(names, n)
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// objectCompleter suggests every named object in the fleet — used by refs
// where any kind of name is a valid argument.
func objectCompleter(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if !ensureFleetPath() {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	host := hostFromFlag(cmd)
	if host == "" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	fleet, err := config.Load(fleetPath, host)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for n := range fleet.Aliases {
		names = append(names, n)
	}
	for n := range fleet.AddressSets {
		names = append(names, n)
	}
	for n := range fleet.ACLs {
		names = append(names, n)
	}
	for n := range fleet.Instances {
		names = append(names, n)
	}
	for n := range fleet.Policies {
		names = append(names, n)
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// registerHostFlag registers the standard --host string flag on cmd AND
// wires its completion to hostCompleter. Kept here so every command that
// takes --host gets consistent behaviour.
func registerHostFlag(cmd *cobra.Command, ptr *string, help string) {
	cmd.Flags().StringVar(ptr, "host", "", help)
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
}
