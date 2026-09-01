package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
)

// printCommitReminder prints an unmissable stderr banner after any
// operation that rewrote .sops.yaml (and possibly re-wrapped
// already-encrypted files) — none of that is durable, or visible to
// any other clone, until it's committed.
func printCommitReminder(paths ...string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "════════════════════════════════════════════════════════════════")
	fmt.Fprintln(os.Stderr, "  COMMIT THIS NOW — nothing here takes effect for anyone else")
	fmt.Fprintln(os.Stderr, "  until it's committed and pushed.")
	fmt.Fprintln(os.Stderr, "════════════════════════════════════════════════════════════════")
	addArgs := append([]string{"add"}, paths...)
	fmt.Fprintf(os.Stderr, "  git %s\n", strings.Join(addArgs, " "))
	fmt.Fprintln(os.Stderr, "  git commit -m 'vault: update recipients'")
	fmt.Fprintln(os.Stderr)
}

// vaultCmd groups the age/SOPS key-management subcommands.
//
// incus-sync owns no cryptography here — see internal/vault's package
// doc. `status` reports which backend is currently resolvable;
// `list-recipients` / `add-recipient` / `remove-recipient` are a thin
// convenience layer over editing .sops.yaml and running `sops
// updatekeys`, nothing more.
func vaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Inspect the age/SOPS backend and manage .sops.yaml recipients",
		Long: `incus-sync decrypts every SOPS-encrypted file (secrets.sops.yaml,
remote.sops.yaml) using an AGE private key resolved from exactly two
of SOPS's own native env vars — nothing incus-sync-specific:

  1. SOPS_AGE_KEY       env — the key content itself
  2. SOPS_AGE_KEY_FILE  env — path to an identity file

incus-sync implements neither: no custom vault format, no cache, no
command hook, no legacy fallback. Every secret-manager integration is
an AGE PLUGIN identity in that file (AGE-PLUGIN-<NAME>-1...), chosen
and trusted entirely by the operator — incus-sync names none, depends
on none, and needs no plugin-specific code to support any of them.
SOPS resolves plugin identities natively (shells out to the matching
age-plugin-* binary on PATH). See README.md's Auth section.

Multiple people/keys are handled entirely by SOPS/age's own
mechanism: every recipient is one age public key listed in
.sops.yaml, wrapped the same way for all of them. The subcommands
below are a thin, auditable convenience layer over editing that file
and running ` + "`sops updatekeys`" + ` — they hold no secret material and do
no cryptography of their own:

  vault list-recipients    — who can currently decrypt, and where
  vault add-recipient      — add an age public key, re-wrap existing files
  vault remove-recipient   — remove one, re-wrap (real revocation)`,
	}
	cmd.AddCommand(
		vaultStatusCmd(),
		vaultListRecipientsCmd(),
		vaultAddRecipientCmd(),
		vaultRemoveRecipientCmd(),
	)
	return cmd
}

func vaultStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show which age key backend is currently resolvable",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("fleet path       %s\n", fleetPath)
			if v := os.Getenv("SOPS_AGE_KEY"); v != "" {
				fmt.Println("backend          SOPS_AGE_KEY env (key content set directly)")
				return nil
			}
			if p := os.Getenv("SOPS_AGE_KEY_FILE"); p != "" {
				fmt.Printf("backend          SOPS_AGE_KEY_FILE env → %s\n", p)
				if raw, err := os.ReadFile(p); err == nil && strings.Contains(string(raw), "AGE-PLUGIN-") {
					fmt.Println("  identity file contains an age plugin line — the matching")
					fmt.Println("  age-plugin-* binary must be on PATH to decrypt.")
				}
				return nil
			}
			fmt.Println("backend          NONE CONFIGURED")
			fmt.Println()
			fmt.Println("Set SOPS_AGE_KEY or SOPS_AGE_KEY_FILE. See README.md's Auth section.")
			return nil
		},
	}
}

func vaultListRecipientsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-recipients",
		Short: "List every age public key in .sops.yaml, and which rules it decrypts",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := config.LoadSopsPolicy(fleetPath)
			if err != nil {
				return err
			}
			recipients := p.ListRecipients()
			if len(recipients) == 0 {
				fmt.Println("(no recipients in .sops.yaml)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ANCHOR\tCOMMENT\tRULES\tPUBLIC KEY")
			for _, r := range recipients {
				comment := r.Comment
				if comment == "" {
					comment = "-"
				}
				rules := strings.Join(r.Rules, ", ")
				if rules == "" {
					rules = "(none — orphaned entry)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Anchor, comment, rules, r.PubKey)
			}
			return tw.Flush()
		},
	}
}

func vaultAddRecipientCmd() *cobra.Command {
	var (
		comment string
		rules   []string
	)
	cmd := &cobra.Command{
		Use:   "add-recipient <anchor> <age1...pubkey>",
		Short: "Add an age public key to .sops.yaml and re-wrap already-encrypted files",
		Long: `Adds <age1...pubkey> to .sops.yaml's keys: list under the given
anchor name (also its label — pick something that identifies whose
key or which machine it is, e.g. ahall_laptop or ci_runner), wires it
into every creation_rule's key_groups (or only the ones matching
--rule, given one or more times), then runs ` + "`sops updatekeys`" + ` on
every already-encrypted file those rules cover — so existing secrets
become readable by the new recipient immediately, not just new ones.

The pubkey itself is never a secret — it identifies a recipient, it
does not grant a bearer credential. How that recipient later proves
they hold the matching private key (a plain age identity, an age
plugin identity, whatever) is entirely up to them; this command knows
nothing about it.

Requires the operator running this to already be a valid recipient
(sops updatekeys must decrypt the existing data key to re-wrap it).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			anchor, pubkey := args[0], args[1]
			p, err := config.LoadSopsPolicy(fleetPath)
			if err != nil {
				return err
			}
			if err := p.AddRecipient(anchor, pubkey, comment, config.AddRecipientOptions{Rules: rules}); err != nil {
				return err
			}

			affectedRules := rules
			if len(affectedRules) == 0 {
				for _, r := range p.ListRecipients() {
					if r.Anchor == anchor {
						affectedRules = r.Rules
					}
				}
			}
			files, err := config.AffectedFiles(fleetPath, affectedRules)
			if err != nil {
				return err
			}

			if err := p.Save(); err != nil {
				return err
			}
			fmt.Printf("Added recipient %s (%s) to %s\n", anchor, pubkey, config.SopsPolicyFilename)

			if len(files) > 0 {
				if err := runSopsUpdatekeys(files); err != nil {
					return fmt.Errorf("policy updated, but re-wrapping existing files failed: %w"+
						"\n(the new recipient can decrypt anything encrypted AFTER this point regardless)", err)
				}
				fmt.Printf("Re-wrapped %d existing file(s) for the new recipient:\n", len(files))
				for _, f := range files {
					fmt.Printf("  %s\n", f)
				}
			} else {
				fmt.Println("No already-encrypted files matched — nothing to re-wrap yet.")
			}

			commitPaths := append([]string{config.SopsPolicyFilename}, files...)
			printCommitReminder(commitPaths...)
			return nil
		},
	}
	cmd.Flags().StringVar(&comment, "comment", "", `Human-readable label, e.g. "ahall's laptop key"`)
	cmd.Flags().StringArrayVar(&rules, "rule", nil, "Restrict to creation_rules whose path_regex exactly matches (repeatable; default: every rule)")
	return cmd
}

func vaultRemoveRecipientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove-recipient <anchor-or-pubkey>",
		Short: "Remove a recipient from .sops.yaml and re-wrap (real revocation)",
		Long: `Removes the given recipient (by anchor name or literal age1...
pubkey) from .sops.yaml and every creation_rule it was wired into,
then runs ` + "`sops updatekeys`" + ` on every affected already-encrypted
file — re-wrapping the data key for the REMAINING recipients only.
That re-wrap is what makes this real revocation: merely deleting the
line from .sops.yaml would leave old ciphertext still decryptable by
whoever kept a copy of the removed key.

Refuses to remove the sole recipient of any creation_rule — that
would make its files permanently undecryptable, not revoke access.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := config.LoadSopsPolicy(fleetPath)
			if err != nil {
				return err
			}
			// Capture affected rules BEFORE removal — RemoveRecipient
			// drops the alias references we'd otherwise use to find them.
			var affectedRules []string
			for _, r := range p.ListRecipients() {
				if r.Anchor == args[0] || r.PubKey == args[0] {
					affectedRules = r.Rules
				}
			}
			anchor, err := p.RemoveRecipient(args[0])
			if err != nil {
				return err
			}
			files, err := config.AffectedFiles(fleetPath, affectedRules)
			if err != nil {
				return err
			}
			if err := p.Save(); err != nil {
				return err
			}
			fmt.Printf("Removed recipient %s from %s\n", anchor, config.SopsPolicyFilename)

			if len(files) > 0 {
				if err := runSopsUpdatekeys(files); err != nil {
					return fmt.Errorf("policy updated, but re-wrapping existing files failed: %w"+
						"\n(the removed recipient can still decrypt the OLD ciphertext until this succeeds)", err)
				}
				fmt.Printf("Re-wrapped %d existing file(s) — %s can no longer decrypt them:\n", len(files), anchor)
				for _, f := range files {
					fmt.Printf("  %s\n", f)
				}
			} else {
				fmt.Println("No already-encrypted files matched.")
			}

			commitPaths := append([]string{config.SopsPolicyFilename}, files...)
			printCommitReminder(commitPaths...)
			return nil
		},
	}
	return cmd
}

// runSopsUpdatekeys shells out to the real sops binary — sops has no
// library-level "re-wrap in place" call worth depending on for this,
// and doing it via the CLI is the exact same operation an operator
// would run by hand, just automated over every affected file.
func runSopsUpdatekeys(relFiles []string) error {
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		return fmt.Errorf("sops binary not on PATH — install it, then run manually:\n  sops updatekeys -y %s", strings.Join(relFiles, " "))
	}
	for _, f := range relFiles {
		c := exec.Command(sopsPath, "updatekeys", "-y", f)
		c.Dir = fleetPath
		c.Stdout = os.Stderr
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("sops updatekeys %s: %w", f, err)
		}
	}
	return nil
}
