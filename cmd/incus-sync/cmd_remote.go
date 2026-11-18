package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/unidoc/incus-sync/internal/config"
	"github.com/unidoc/incus-sync/internal/vault"
)

func remoteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage per-host Incus HTTPS API remotes",
		Long: `The deployment model is bastion → Incus HTTPS API per host.
Each host under hosts/<name>/ has an optional remote.sops.yaml that
holds the URL, server certificate fingerprint, and SOPS-encrypted TLS
client cert + key.

Subcommands:
  remote list       — print every configured remote
  remote bootstrap  — generate cert, write encrypted remote.sops.yaml,
                      print client cert PEM to stdout for pipe-to-SSH`,
	}
	cmd.AddCommand(remoteListCmd())
	cmd.AddCommand(remoteBootstrapCmd())
	return cmd
}

func remoteListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every configured remote (hosts/<host>/remote.sops.yaml)",
		RunE: func(cmd *cobra.Command, args []string) error {
			names, err := config.ListRemotes(fleetPath)
			if err != nil {
				return err
			}
			if len(names) == 0 {
				fmt.Println("(no remotes configured)")
				return nil
			}
			// LoadRemote calls SOPS, which reads the age key. Resolve
			// it once up front rather than let every remote in the
			// loop below fail with a decrypt error — matches
			// resolveRemoteForHost's pattern in main.go.
			if err := vault.EnsureUnlocked(); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tURL\tFINGERPRINT")
			for _, n := range names {
				r, err := config.LoadRemote(fleetPath, n)
				if err != nil {
					fmt.Fprintf(tw, "%s\t<sops-decrypt-failed>\t%v\n", n, err)
					continue
				}
				fp := r.ServerFingerprint
				if len(fp) > 16 {
					fp = fp[:8] + "…" + fp[len(fp)-8:]
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", n, r.URL, fp)
			}
			return tw.Flush()
		},
	}
}

func remoteBootstrapCmd() *cobra.Command {
	var (
		url         string
		fingerprint string
		projects    []string
	)
	cmd := &cobra.Command{
		Use:   "bootstrap <host>",
		Short: "Generate a client cert, write encrypted hosts/<host>/remote.sops.yaml, print cert PEM to stdout",
		Long: `Generates an ECDSA P-256 client cert + key, writes them into
hosts/<host>/remote.sops.yaml, and encrypts in place using SOPS (per
the fleet's .sops.yaml policy).

The client CERT PEM is printed to stdout so the operator can pipe it
straight to the target host to register with Incus. The client KEY
stays in the encrypted file and is never written elsewhere.

Requires: sops binary on PATH, .sops.yaml policy in the fleet repo
with an age recipient matching the bastion's key.

Full flow:

  incus-sync remote bootstrap web1 \
      --url https://web1.example.com:22443 \
      --fingerprint <sha256-from-incus-info-on-host> \
      [--projects web] | \
      ssh -p 2282 user@web1 'sudo incus config trust add-certificate - \
          --name gateway-bastion --restricted --projects default,web'

  git add hosts/web1/remote.sops.yaml
  git commit -m "add web1 remote"

  incus-sync doctor --host web1      # verify HTTPS reachability`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			if url == "" {
				return fmt.Errorf("--url is required (e.g. https://%s.example.com:22443)", host)
			}
			if fingerprint == "" {
				return fmt.Errorf("--fingerprint is required (SHA256 from `incus info` on target host)")
			}
			return runRemoteBootstrap(host, url, fingerprint, projects)
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "Incus HTTPS URL, e.g. https://web1.example.com:22443")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "SHA256 fingerprint of the Incus server cert (from `incus info` on target)")
	cmd.Flags().StringSliceVar(&projects, "projects", nil, "Extra fleet.yaml projects to scope the cert to, beyond what this host's instances already use (comma-separated). Use on a new host so orphans/import/adopt can see its containers.")
	return cmd
}

func runRemoteBootstrap(host, url, fingerprint string, extraProjects []string) (err error) {
	// Fail fast if sops isn't on PATH — otherwise we'd write plaintext
	// certs to disk with no way to encrypt them cleanly.
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		return fmt.Errorf("sops binary not on PATH — install with `pkg install sops` (FreeBSD) or `apk add sops` (Alpine)")
	}

	// Check --projects before generating anything, so a typo fails with
	// nothing to roll back.
	meta, err := config.LoadFleetMeta(fleetPath)
	if err != nil {
		return err
	}
	for _, p := range extraProjects {
		if p = strings.TrimSpace(p); p != "" {
			if err := checkFleetProject(meta, p); err != nil {
				return err
			}
		}
	}

	// Generate ECDSA P-256 keypair.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: "incus-sync-bastion@" + host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("sign cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// Load (and compute the cert's project scope) BEFORE writing
	// remote.sops.yaml: an unrelated fleet validation error must fail
	// here, not leave a secret file written with no success message or
	// cert PEM ever printed.
	fleet, dir, created, err := loadFleetForBootstrap(fleetPath, host)
	if err != nil {
		return err
	}
	// If anything below fails, leave the fleet repo as it was: remove
	// what this run created, as long as it is still empty.
	defer func() {
		if err != nil {
			removeCreated(created)
		}
	}()
	// Cert needs access to BOTH the network project (where ACLs and
	// address-sets live) AND every project this host manages, plus any
	// --projects the operator asked for.
	scope, err := bootstrapCertProjects(fleet, meta.Projects, extraProjects)
	if err != nil {
		return err
	}
	certProjects := strings.Join(scope, ",")
	sum := sha256.Sum256(derBytes)
	clientFingerprint := hex.EncodeToString(sum[:])

	// Compose remote YAML.
	normalisedFP := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	remoteYAML := struct {
		URL               string `yaml:"url"`
		ServerFingerprint string `yaml:"server_fingerprint"`
		ClientCert        string `yaml:"client_cert"`
		ClientKey         string `yaml:"client_key"`
	}{
		URL:               url,
		ServerFingerprint: normalisedFP,
		ClientCert:        string(certPEM),
		ClientKey:         string(keyPEM),
	}
	out, err := yaml.Marshal(remoteYAML)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "remote.sops.yaml")

	// Pipe plaintext through sops stdin → capture encrypted stdout →
	// write only encrypted bytes to disk. Plaintext (which contains
	// the private key) NEVER touches the filesystem.
	//
	// --filename-override tells sops which .sops.yaml rule to apply
	// based on a virtual filename (since the real input is /dev/stdin).
	var encrypted bytes.Buffer
	encCmd := exec.Command(sopsPath,
		"-e",
		"--input-type", "yaml",
		"--output-type", "yaml",
		"--filename-override", path,
		"/dev/stdin",
	)
	encCmd.Stdin = bytes.NewReader(out)
	encCmd.Stdout = &encrypted
	encCmd.Stderr = os.Stderr
	if err := encCmd.Run(); err != nil {
		return fmt.Errorf("sops encrypt failed: %w  (plaintext never written to disk)", err)
	}
	if err := os.WriteFile(path, encrypted.Bytes(), 0o600); err != nil {
		return err
	}

	// Diagnostics to stderr, cert PEM to stdout — so caller can pipe
	// stdout to `ssh ... 'incus config trust add-certificate -'`.
	// fleet and certProjects were computed up front, before writing the
	// secret file — see the comment above.
	if shouldPrintScopeNote(fleet, meta.Projects, scope, extraProjects) {
		fmt.Fprintf(os.Stderr,
			"NOTE: %s has no instances yet, no fleet.yaml host_projects entry and no\n"+
				"--projects, so the cert below is scoped to %q only. Until it is widened,\n"+
				"orphans/list cannot see containers in other projects, import/adopt get a\n"+
				"permission error there, and sync fails once an instance lands in one.\n"+
				"To widen it: on the host, add the project to this cert's projects with\n"+
				"`incus config trust edit %s`, or re-run bootstrap with\n"+
				"--projects <project> (that makes a NEW key and cert: register it, then\n"+
				"remove the old trust entry with `incus config trust remove %s`).\n\n",
			host, fleet.NetworkProject, clientFingerprint, clientFingerprint)
	}
	fmt.Fprintf(os.Stderr, "Wrote encrypted %s\n", path)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "Client cert fingerprint: %s\n", clientFingerprint)
	fmt.Fprintln(os.Stderr, "Client cert PEM is on stdout. Register with Incus on the target host:")
	fmt.Fprintf(os.Stderr, "  incus config trust add-certificate - --name gateway-bastion --restricted --projects %s\n", certProjects)
	fmt.Fprintln(os.Stderr, "")
	var toCreate []string
	for _, p := range scope {
		if p != fleet.NetworkProject {
			toCreate = append(toCreate, p)
		}
	}
	if len(toCreate) > 0 {
		fmt.Fprintln(os.Stderr, "Ensure every managed project exists first on the target:")
		for _, p := range toCreate {
			fmt.Fprintf(os.Stderr, "  incus project create %s\n", p)
		}
		fmt.Fprintln(os.Stderr, "")
	}
	fmt.Fprintf(os.Stderr, "Then commit: git add %s && git commit -m 'add %s remote'\n", path, host)

	// Cert PEM to stdout.
	if _, err := os.Stdout.Write(certPEM); err != nil {
		return err
	}
	return nil
}

// loadFleetForBootstrap loads the fleet for a host that may not have a
// hosts/<host>/ directory yet. config.Load requires that directory, so
// it is created first (and hosts/ with it, if missing); created lists
// the directories this call made, deepest first. If the load fails they
// are removed again, so a failed bootstrap does not leave empty
// directories behind (an empty hosts/<host>/ would also hide a
// host_projects typo for that name from validate).
func loadFleetForBootstrap(fleetPath, host string) (fleet *config.Fleet, dir string, created []string, err error) {
	hostsDir := filepath.Join(fleetPath, "hosts")
	dir = filepath.Join(hostsDir, host)
	for _, d := range []string{dir, hostsDir} {
		if _, statErr := os.Stat(d); os.IsNotExist(statErr) {
			created = append(created, d)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", nil, err
	}
	fleet, err = config.Load(fleetPath, host)
	if err != nil {
		removeCreated(created)
		return nil, "", nil, err
	}
	return fleet, dir, created, nil
}

// removeCreated removes directories a bootstrap run created, deepest
// first. os.Remove only removes empty directories, so anything that
// has files in it by now is left alone.
func removeCreated(dirs []string) {
	for _, d := range dirs {
		_ = os.Remove(d)
	}
}

// shouldPrintScopeNote reports whether bootstrap should warn that the
// new cert leaves out fleet projects: the host has no instances and no
// host_projects entry, no --projects was given, and some fleet project
// is outside the cert's scope. When the operator named projects (via
// instances, host_projects or --projects), the scope is their choice.
func shouldPrintScopeNote(fleet *config.Fleet, fleetProjects, scope, extra []string) bool {
	if len(fleet.Projects) > 0 {
		return false
	}
	for _, p := range extra {
		if strings.TrimSpace(p) != "" {
			return false
		}
	}
	return slices.ContainsFunc(fleetProjects, func(p string) bool {
		return !slices.Contains(scope, p)
	})
}

// bootstrapCertProjects returns the cert's --projects scope: the
// fleet's network project, this host's effective projects, and any
// extra projects passed with --projects, de-duplicated. Each extra must
// be in fleet.yaml's fleet-wide projects list, so a typo is an error
// rather than a cert scoped to a project the fleet never manages.
func bootstrapCertProjects(fleet *config.Fleet, fleetProjects, extra []string) ([]string, error) {
	out := fleet.CertProjects()
	for _, p := range extra {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !slices.Contains(fleetProjects, p) {
			return nil, fmt.Errorf("--projects %q is not in fleet.yaml's projects list %v", p, fleetProjects)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}
