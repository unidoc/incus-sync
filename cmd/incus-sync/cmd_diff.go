package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/incus"
)

func diffCmd() *cobra.Command {
	var (
		host          string
		socketPath    string
		project       string
		showUnchanged bool
		showUnmanaged bool
		format        string
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare rendered YAML against live Incus state",
		Long: `Loads the config repo, resolves aliases and policies, then
fetches live Incus state and prints what a sync would change.

Never mutates Incus. Safe to run any time.

Formats:
  colored (default) — human, colored on TTY
  summary           — compact markdown suitable for a PR comment / CI post
  json              — machine-readable, stable schema for Grafana / alertmanager`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			fleet, err := config.Load(configDir, host)
			if err != nil {
				return err
			}
			if err := fleet.ValidateSemantic(); err != nil {
				return err
			}
			remote, err := resolveRemoteForHost(host)
			if err != nil {
				return err
			}
			srv, err := incus.Connect(socketPath, remote)
			if err != nil {
				return err
			}
			// srv unscoped — ComputePlan iterates projects internally.
			_ = project

			plan, err := incus.ComputePlan(srv, fleet)
			if err != nil {
				return err
			}
			switch format {
			case "summary":
				return renderPlanSummary(plan, fleet, host)
			case "json":
				return renderPlanJSON(plan, fleet, host)
			case "colored", "":
				return renderPlan(plan, showUnchanged, showUnmanaged)
			default:
				return fmt.Errorf("unknown --format %q (want colored, summary, json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required; see `remote list`)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket, "Incus unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`)")
	cmd.Flags().BoolVar(&showUnchanged, "show-unchanged", false, "Print objects that already match")
	cmd.Flags().BoolVar(&showUnmanaged, "show-unmanaged", true, "Print objects that exist in Incus but are not in the fleet")
	cmd.Flags().StringVar(&format, "format", "colored", "Output format: colored, summary, json")
	return cmd
}

// Colors are ANSI escapes; skipped when stdout is not a TTY.
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiDim    = "\033[2m"
	ansiBold   = "\033[1m"
)

func renderPlan(plan *incus.Plan, showUnchanged, showUnmanaged bool) error {
	tty := isTTY(os.Stdout) && os.Getenv("NO_COLOR") == ""
	color := func(code, s string) string {
		if !tty {
			return s
		}
		return code + s + ansiReset
	}

	for _, e := range plan.Entries {
		switch e.Action {
		case incus.ActionCreate:
			fmt.Printf("%s  %s %s\n",
				color(ansiGreen, "+ create"), e.Kind, color(ansiBold, e.Name))
			for _, d := range e.Details {
				fmt.Printf("    %s\n", d)
			}
		case incus.ActionUpdate:
			fmt.Printf("%s  %s %s\n",
				color(ansiYellow, "~ update"), e.Kind, color(ansiBold, e.Name))
			for _, d := range e.Details {
				fmt.Printf("    %s\n", d)
			}
			for _, d := range e.Dangers {
				fmt.Printf("    %s %s\n", color(ansiRed, "DANGER"), d)
			}
		case incus.ActionUnmanaged:
			if !showUnmanaged {
				continue
			}
			fmt.Printf("%s  %s %s\n",
				color(ansiDim, "? unmanaged"), e.Kind, e.Name)
			for _, d := range e.Details {
				fmt.Printf("    %s%s%s\n", ansiDim, d, ansiReset)
			}
		case incus.ActionMatch:
			if !showUnchanged {
				continue
			}
			fmt.Printf("%s  %s %s\n",
				color(ansiDim, "= match"), e.Kind, e.Name)
		}
	}
	fmt.Printf("\n%s\n", plan.Summary())
	return nil
}

// renderPlanSummary emits GitHub/Gitea-friendly Markdown for PR comments.
// Includes risk flags from fleet.Warnings — the reviewer sees widening
// changes and orphaned-tag warnings in the same block as the diff.
func renderPlanSummary(plan *incus.Plan, fleet *config.Fleet, host string) error {
	fmt.Printf("## incus-sync diff — `%s`\n\n", host)
	fmt.Printf("**%s**\n\n", plan.Summary())

	buckets := map[incus.Action][]string{}
	for _, e := range plan.Entries {
		switch e.Action {
		case incus.ActionCreate:
			buckets[e.Action] = append(buckets[e.Action],
				fmt.Sprintf("- 🆕 create %s **%s**", e.Kind, e.Name))
		case incus.ActionUpdate:
			line := fmt.Sprintf("- 🔄 update %s **%s**", e.Kind, e.Name)
			for _, d := range e.Details {
				line += "\n  - " + d
			}
			for _, d := range e.Dangers {
				line += "\n  - 🚨 **DANGER:** " + d
			}
			buckets[e.Action] = append(buckets[e.Action], line)
		case incus.ActionUnmanaged:
			buckets[e.Action] = append(buckets[e.Action],
				fmt.Sprintf("- ❓ unmanaged %s `%s`", e.Kind, e.Name))
		}
	}

	if len(buckets[incus.ActionCreate])+len(buckets[incus.ActionUpdate]) > 0 {
		fmt.Println("### Changes")
		for _, l := range buckets[incus.ActionCreate] {
			fmt.Println(l)
		}
		for _, l := range buckets[incus.ActionUpdate] {
			fmt.Println(l)
		}
		fmt.Println()
	}
	if len(buckets[incus.ActionUnmanaged]) > 0 {
		fmt.Println("### Unmanaged (left alone)")
		for _, l := range buckets[incus.ActionUnmanaged] {
			fmt.Println(l)
		}
		fmt.Println()
	}
	if len(fleet.Warnings) > 0 {
		fmt.Println("### ⚠️ Risk flags")
		for _, w := range fleet.Warnings {
			fmt.Printf("- %s\n", w)
		}
		fmt.Println()
	}
	return nil
}

// planEntryJSON is the stable serialisation of a plan entry.
// Schema version 1. Adding fields is backwards-compatible; renaming or
// removing requires bumping schemaVersion.
type planEntryJSON struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	Action  string   `json:"action"`
	Details []string `json:"details,omitempty"`
	Dangers []string `json:"dangers,omitempty"`
}

type planJSON struct {
	SchemaVersion int             `json:"schema_version"`
	Host          string          `json:"host"`
	Summary       map[string]int  `json:"summary"`
	Warnings      []string        `json:"warnings,omitempty"`
	Entries       []planEntryJSON `json:"entries"`
}

func renderPlanJSON(plan *incus.Plan, fleet *config.Fleet, host string) error {
	summary := map[string]int{"create": 0, "update": 0, "match": 0, "unmanaged": 0}
	entries := make([]planEntryJSON, 0, len(plan.Entries))
	for _, e := range plan.Entries {
		summary[string(e.Action)]++
		entries = append(entries, planEntryJSON{
			Kind:    e.Kind,
			Name:    e.Name,
			Action:  string(e.Action),
			Details: e.Details,
			Dangers: e.Dangers,
		})
	}
	doc := planJSON{
		SchemaVersion: 1,
		Host:          host,
		Summary:       summary,
		Warnings:      fleet.Warnings,
		Entries:       entries,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
