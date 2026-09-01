package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/gitcheck"
	"github.com/unidoc/incus-sync/internal/incus"
	"github.com/unidoc/incus-sync/internal/statelog"
)

func syncCmd() *cobra.Command {
	var (
		host       string
		socketPath string
		project    string
		apply      bool
		force      bool
		dirtyOK    bool
	)
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Apply YAML state to Incus (or dry-run)",
		Long: `Loads the config repo, resolves aliases and policies, then
reconciles live Incus state to match. Dry-run by default; pass --apply
to actually mutate Incus.

--apply IS the confirmation. The tool does not prompt a second time —
if you typed --apply, we assume you meant it. Run without --apply first
to see the plan.

Safety:
  - Prints target host banner before any action
  - Never deletes objects that exist in Incus but not in the fleet
  - Only patches managed device keys (see docs/schema.md)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkTargetHost(host); err != nil {
				return err
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
			// srv stays unscoped — ComputePlan and Plan.Apply switch
			// UseProject internally per resource type / instance project.
			_ = project // legacy flag retained but unused; multi-project sync ignores it

			// Decrypt shared/secrets.sops.yaml once for this sync. Vault
			// was already unlocked by resolveRemoteForHost via SOPS.
			if err := fleet.LoadSecretsInto(configDir); err != nil {
				return fmt.Errorf("load secrets: %w", err)
			}

			plan, err := incus.ComputePlan(srv, fleet)
			if err != nil {
				return err
			}

			// Git hygiene: warn if the fleet dir is dirty or behind upstream.
			// Best-effort — skipped silently if git is unavailable.
			if apply {
				gs := gitcheck.Inspect(configDir)
				warnings := gs.Warnings()
				if len(warnings) > 0 && !dirtyOK {
					fmt.Fprintln(os.Stderr, "git hygiene:")
					for _, w := range warnings {
						fmt.Fprintln(os.Stderr, "  "+w)
					}
					return fmt.Errorf("refusing to apply with dirty or stale fleet repo. Re-run with --dirty-ok to override")
				}
			}

			// Refuse to apply refuse-worthy changes without --force.
			if apply && plan.HasDangers() && !force {
				printDangers(plan)
				return fmt.Errorf("refusing to apply: dangerous changes present. Re-run with --force to override")
			}

			// Non-apply: just print dry-run and stop.
			if !apply {
				printHostBanner(host, socketPath)
				if err := plan.Apply(srv, true); err != nil {
					return err
				}
				fmt.Printf("\n%s\n\n(re-run with --apply to actually mutate Incus)\n", plan.Summary())
				return nil
			}

			// Warnings surface BEFORE apply so automation runs (CI,
			// systemd timer) also see risk flags in their logs.
			if apply && len(fleet.Warnings) > 0 {
				fmt.Fprintln(os.Stderr, "⚠️  RISK FLAGS:")
				for _, w := range fleet.Warnings {
					fmt.Fprintln(os.Stderr, "  "+w)
				}
				fmt.Fprintln(os.Stderr)
			}

			// Print the plan once before applying — no second prompt.
			// --apply IS the confirmation. Passing --apply twice on the
			// command line would be equally explicit; a type-APPLY dance
			// on top of that is theatre, not safety.
			fmt.Println("== PLAN ==")
			printHostBanner(host, socketPath)
			if err := plan.Apply(srv, true); err != nil {
				return err
			}
			fmt.Printf("\n%s\n\n", plan.Summary())

			// Acquire an advisory lock on the fleet repo so two concurrent
			// sync --apply runs serialize instead of interleaving writes.
			lock, err := statelog.Acquire(configDir, 60*time.Second)
			if err != nil {
				return err
			}
			defer lock.Release()

			// Persistent JSONL transcript so "what did sync do last Tuesday?"
			// has an answer without piping to tee.
			slog, path, sErr := statelog.Open(host)
			if sErr != nil {
				fmt.Fprintln(os.Stderr, "warning: could not open apply log:", sErr)
			} else {
				fmt.Printf("logging to %s\n", path)
			}
			defer slog.Close()
			slog.Write("apply_start", map[string]any{"host": host, "target_socket": socketPath})

			fmt.Println("== APPLYING ==")
			printHostBanner(host, socketPath)
			if err := plan.Apply(srv, false); err != nil {
				slog.Write("apply_error", map[string]any{"error": err.Error()})
				return err
			}
			slog.Write("apply_end", map[string]any{"summary": plan.Summary()})
			fmt.Printf("\n%s\n", plan.Summary())
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required; see `remote list`)")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&socketPath, "socket", incus.DefaultSocket, "Incus unix socket path")
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`)")
	cmd.Flags().BoolVar(&apply, "apply", false, "Actually apply changes (default: dry run)")
	cmd.Flags().BoolVar(&force, "force", false, "Override refuse-worthy checks (empty ACL/set, widening ingress-default)")
	cmd.Flags().BoolVar(&dirtyOK, "dirty-ok", false, "Proceed even when config repo is dirty or behind upstream")
	return cmd
}

// printDangers prints refuse-worthy changes with a red prefix so the
// operator sees exactly what tripped the guard.
func printDangers(plan *incus.Plan) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "REFUSED — dangerous changes require --force:")
	for _, e := range plan.Entries {
		for _, d := range e.Dangers {
			fmt.Fprintf(os.Stderr, "  %s %s: %s\n", e.Kind, e.Name, d)
		}
	}
	fmt.Fprintln(os.Stderr)
}

func printHostBanner(host, socketPath string) {
	fmt.Printf("target host: %s  (socket %s)\n\n", host, socketPath)
}

// checkTargetHost verifies the host directory exists in the fleet.
// The old "wrong-target" footgun (local socket applying to a remote
// host's plan) is now covered by resolveRemoteForHost — a non-local
// host either loads an HTTPS remote or errors out.
func checkTargetHost(host string) error {
	if host == "" {
		return fmt.Errorf("pass --host <name>")
	}
	dir := filepath.Join(configDir, "hosts", host)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("host %q: no %s", host, dir)
	}
	return nil
}
