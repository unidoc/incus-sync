package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/incus"
)

func doctorCmd() *cobra.Command {
	var host string
	var deep bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Sanity-check tool + config-repo + Incus reachability",
		Long: `Prints everything the tool would use if you ran sync right now:
  - config-dir path and how it was resolved
  - target host (default: short hostname; --host to override)
  - whether hosts/<host>/ exists in the config
  - whether the Incus daemon for <host> is reachable:
      - target == local  → unix socket check
      - target != local  → HTTPS API via hosts/<host>/remote.sops.yaml
                           (TLS client cert + server fingerprint pinning)

Non-zero exit if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				return fmt.Errorf("pass --host <name>")
			}
			return runDoctor(host, deep)
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "Target host (required). Non-local targets connect via HTTPS using hosts/<host>/remote.sops.yaml.")
	_ = cmd.RegisterFlagCompletionFunc("host", hostCompleter)
	cmd.Flags().BoolVar(&deep, "deep", false, "Also check profile, bridge, and DNS reachability")
	return cmd
}

func runDoctor(host string, deep bool) error {
	ok := true

	fmt.Printf("config-dir       %s   (from: %s)\n", configDir, configDirSource)
	fmt.Printf("target host      %s\n", host)

	hostDir := filepath.Join(configDir, "hosts", host)
	if _, err := os.Stat(hostDir); err == nil {
		fmt.Printf("hosts/%s/  present\n", host)
	} else {
		fmt.Printf("hosts/%s/  MISSING\n", host)
		ok = false
	}

	remote, err := resolveRemoteForHost(host)
	if err != nil {
		fmt.Printf("remote config    FAIL: %v\n", err)
		ok = false
	} else if remote == nil {
		// Local target — unix socket path.
		socket := incus.DefaultSocket
		if _, err := os.Stat(socket); err == nil {
			fmt.Printf("incus socket     %s  present\n", socket)
		} else {
			fmt.Printf("incus socket     %s  MISSING\n", socket)
			ok = false
		}
		if _, err := incus.Connect(socket, nil); err == nil {
			fmt.Printf("incus daemon     reachable\n")
		} else {
			fmt.Printf("incus daemon     UNREACHABLE: %v\n", err)
			ok = false
		}
	} else {
		// Remote target — HTTPS with pinned server cert.
		fmt.Printf("remote config    %s  (fingerprint %s...%s)\n",
			remote.URL,
			remote.ServerFingerprint[:8],
			remote.ServerFingerprint[len(remote.ServerFingerprint)-8:])
		srv, err := incus.Connect("", remote)
		if err != nil {
			fmt.Printf("incus daemon     UNREACHABLE via HTTPS: %v\n", err)
			ok = false
		} else {
			info, _, err := srv.GetServer()
			if err != nil {
				fmt.Printf("incus daemon     reached, but GetServer failed: %v\n", err)
				ok = false
			} else {
				fmt.Printf("incus daemon     reachable (auth=%s, api=%s)\n", info.Auth, info.APIVersion)
			}
		}
	}

	if deep {
		fmt.Println()
		fmt.Println("== deep checks ==")
		if !runDeepChecks(host) {
			ok = false
		}
	}

	fmt.Println()
	if !ok {
		return fmt.Errorf("doctor: one or more checks failed")
	}
	fmt.Println("OK")
	return nil
}

// runDeepChecks verifies the pieces sync depends on beyond "daemon is
// running": expected profile, expected bridge, and DNS to the image
// server. Profile and bridge names come from env vars — unset by
// default, since there's no fleet-agnostic default to assume; set them
// to whatever profile/bridge names your fleet expects doctor to verify.
//
//	INCUS_SYNC_EXPECT_PROFILE — comma-separated (default: none, check skipped)
//	INCUS_SYNC_EXPECT_NETWORK — comma-separated (default: none, check skipped)
func runDeepChecks(host string) bool {
	ok := true

	expectProfiles := envListOr("INCUS_SYNC_EXPECT_PROFILE", nil)
	expectNetworks := envListOr("INCUS_SYNC_EXPECT_NETWORK", nil)

	remote, err := resolveRemoteForHost(host)
	if err != nil {
		fmt.Printf("remote           FAIL: %v\n", err)
		return false
	}
	srv, err := incus.Connect(incus.DefaultSocket, remote)
	if err != nil {
		fmt.Printf("daemon           UNREACHABLE: %v\n", err)
		return false
	}

	// Verify every project declared in fleet.yaml exists on the host.
	meta, err := config.LoadFleetMeta(configDir)
	if err != nil {
		fmt.Printf("fleet.yaml       ERROR: %v\n", err)
		return false
	}
	projects, err := srv.GetProjectNames()
	if err != nil {
		fmt.Printf("project list     ERROR: %v\n", err)
		ok = false
	} else {
		for _, want := range meta.Projects {
			if contains(projects, want) {
				fmt.Printf("project %-12s present\n", want)
			} else {
				fmt.Printf("project %-12s MISSING — run `incus project create %s` on the host\n", want, want)
				ok = false
			}
		}
	}
	// Profile / network checks run in NetworkProject scope (where
	// bridges and shared ACLs actually live).
	srv = srv.UseProject(meta.NetworkProject)

	profiles, err := srv.GetProfileNames()
	if err != nil {
		fmt.Printf("profile list     ERROR: %v\n", err)
		ok = false
	} else {
		for _, want := range expectProfiles {
			if contains(profiles, want) {
				fmt.Printf("profile %-8s present\n", want)
			} else {
				fmt.Printf("profile %-8s MISSING\n", want)
				ok = false
			}
		}
	}

	networks, err := srv.GetNetworkNames()
	if err != nil {
		fmt.Printf("network list     ERROR: %v\n", err)
		ok = false
	} else {
		for _, want := range expectNetworks {
			if contains(networks, want) {
				fmt.Printf("network %-8s present\n", want)
			} else {
				fmt.Printf("network %-8s MISSING\n", want)
				ok = false
			}
		}
	}

	if _, err := net.LookupHost("images.linuxcontainers.org"); err != nil {
		fmt.Printf("dns images.lxc   FAIL: %v — sync creates that need image pull will fail\n", err)
		ok = false
	} else {
		fmt.Println("dns images.lxc   resolves")
	}
	return ok
}

// envListOr reads a comma-separated env var, or returns fallback.
func envListOr(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var out []string
	for _, s := range splitComma(v) {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, trim(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trim(s[start:]))
	return out
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
