package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func createCmd() *cobra.Command {
	var (
		host, image, description string
		tags                     []string
		ingressDefault           string
		egressDefault            string
	)
	cmd := &cobra.Command{
		Use:   "create <instance>",
		Short: "Scaffold a new instance YAML file (does not touch Incus)",
		Long: `Scaffolds a fresh hosts/<host>/instances/<name>/ directory
with instance.yaml + empty files/ inside. Actually creating the
container happens on the next ` + "`sync --apply`" + `.

Example:
  incus-sync create wiki --host web1 --image images:alpine/3.24 --tag web --description "Public wiki"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			return runCreate(host, name, image, description, tags, ingressDefault, egressDefault)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Host name (required); places file under hosts/<name>/")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().StringVar(&image, "image", "images:alpine/3.24", "Image source")
	cmd.Flags().StringVar(&description, "description", "TODO", "One-line description of the container's purpose")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Tag (repeatable). Tag-driven policies attach ACLs automatically.")
	cmd.Flags().StringVar(&ingressDefault, "ingress-default", "reject", "Default ingress action (allow, reject, drop)")
	cmd.Flags().StringVar(&egressDefault, "egress-default", "allow", "Default egress action (allow, reject, drop)")
	return cmd
}

func runCreate(host, name, image, description string, tags []string, ingressDefault, egressDefault string) error {
	instDir := filepath.Join(fleetPath, "hosts", host, "instances", name)
	if _, err := os.Stat(instDir); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite", instDir)
	}
	if err := os.MkdirAll(filepath.Join(instDir, "files"), 0o755); err != nil {
		return err
	}
	path := filepath.Join(instDir, "instance.yaml")

	var b strings.Builder
	fmt.Fprintln(&b, "# incus-sync instance")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "instance: %s\n", name)
	fmt.Fprintf(&b, "description: %s\n", description)
	fmt.Fprintf(&b, "original_image: %s\n", image)
	if len(tags) > 0 {
		fmt.Fprintf(&b, "tags: [%s]\n", strings.Join(tags, ", "))
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "# eth0 (flat form). For multi-NIC use `devices:` block instead.")
	fmt.Fprintln(&b, "# ip6: 2001:db8:1::XX")
	fmt.Fprintln(&b, "# acls: [default-policy, generic-ssh-management]")
	fmt.Fprintf(&b, "ingress-default: %s\n", ingressDefault)
	fmt.Fprintf(&b, "egress-default: %s\n", egressDefault)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "# One-shot bootstrap at container create time. Uncomment to enable.")
	fmt.Fprintln(&b, "# Role-specific config goes in files/ and after.sh next to this yaml.")
	fmt.Fprintln(&b, "# provision:")
	fmt.Fprintln(&b, "#   interface: alpine        # or debian-networkd, debian-interfaces")
	fmt.Fprintln(&b, "#   templates: [alpine-base] # reusable bundles from <fleet-repo>/templates/")

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("Created %s\n", instDir)
	fmt.Println("Layout:")
	fmt.Printf("  %s/instance.yaml    ← edit for ACLs, ip6, provision\n", instDir)
	fmt.Printf("  %s/files/           ← optional: /etc/foo/bar.conf goes at files/etc/foo/bar.conf\n", instDir)
	fmt.Printf("  %s/after.sh         ← optional: shell script run inside the container\n", instDir)
	fmt.Println("Next steps:")
	fmt.Println("  1. Review instance.yaml, add IPv6 and ACLs.")
	fmt.Printf("  2. incus-sync diff --host %s\n", host)
	fmt.Printf("  3. incus-sync sync --host %s --apply\n", host)
	return nil
}
