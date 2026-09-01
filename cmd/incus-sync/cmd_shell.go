package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

func shellCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "shell <instance>",
		Short: "Interactive shell into the container (prefers bash)",
		Long: `Wraps ` + "`incus exec`" + ` and prefers /bin/bash if the container has it,
falling back to /bin/sh otherwise. Requires the incus CLI on PATH — the
tool defers websocket wiring to it rather than reimplement.

Example:
  incus-sync shell webapp                # bash if present, else sh
  incus-sync shell webapp --project ops  # different project`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: instanceCompleter,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			if _, err := exec.LookPath("incus"); err != nil {
				return fmt.Errorf("incus CLI not on PATH — install incus-client")
			}

			proj, err := resolveProject(project)
			if err != nil {
				return err
			}
			project = proj
			shell := detectShell(name, project)
			runArgs := []string{"exec"}
			if project != "" && project != "default" {
				runArgs = append(runArgs, "--project", project)
			}
			runArgs = append(runArgs, name, "--", shell)

			c := exec.Command("incus", runArgs...)
			c.Stdin = os.Stdin
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			// exec.Cmd inherits process group; ctrl-c reaches the child correctly.
			return c.Run()
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Incus project (default: fleet.yaml or `default`) the instance lives in")
	return cmd
}

// detectShell asks the container which shell is present, preferring bash.
// Runs a quick non-interactive exec and inspects exit code. If detection
// itself fails, defaults to /bin/sh — every container has that.
func detectShell(name, project string) string {
	args := []string{"exec"}
	if project != "" && project != "default" {
		args = append(args, "--project", project)
	}
	args = append(args, name, "--", "test", "-x", "/bin/bash")
	if exec.Command("incus", args...).Run() == nil {
		return "/bin/bash"
	}
	return "/bin/sh"
}
