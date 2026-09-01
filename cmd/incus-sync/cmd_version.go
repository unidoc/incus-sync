package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set at build time via -ldflags "-X main.version=..." if desired; defaults
// to "dev" so operators can tell a source build from a tagged release.
var version = "dev"

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print binary version and build info",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("incus-sync %s\n", version)
			if bi, ok := debug.ReadBuildInfo(); ok {
				fmt.Printf("go:      %s\n", bi.GoVersion)
				for _, s := range bi.Settings {
					switch s.Key {
					case "vcs.revision":
						fmt.Printf("commit:  %s\n", s.Value)
					case "vcs.time":
						fmt.Printf("built:   %s\n", s.Value)
					case "vcs.modified":
						fmt.Printf("dirty:   %s\n", s.Value)
					}
				}
			}
			return nil
		},
	}
}
