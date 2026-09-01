package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
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
			names, err := config.ListRemotes(configDir)
			if err != nil {
				return err
			}
			if len(names) == 0 {
				fmt.Println("(no remotes configured)")
				return nil
			}
			// LoadRemote calls SOPS, which reads the age key. Unlock
			// once up front (idempotent, cached) rather than let every
			// remote in the loop below fail with a decrypt error on
			// the passphrase/ssh-agent backends — matches
			// resolveRemoteForHost's pattern in main.go.
			meta, err := config.LoadFleetMeta(configDir)
			if err != nil {
				return err
			}
			if _, err := vault.EnsureUnlocked(meta.Name, promptPassphrase); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tURL\tFINGERPRINT")
			for _, n := range names {
				r, err := config.LoadRemote(configDir, n)
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
      --fingerprint <sha256-from-incus-info-on-host> | \
      ssh -p 2282 user@web1 'sudo incus config trust add-certificate - \
          --name gateway-bastion --restricted --projects default'

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
			return runRemoteBootstrap(host, url, fingerprint)
		},
	}
	cmd.Flags().StringVar(&url, "url", "", "Incus HTTPS URL, e.g. https://web1.example.com:22443")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "SHA256 fingerprint of the Incus server cert (from `incus info` on target)")
	return cmd
}

func runRemoteBootstrap(host, url, fingerprint string) error {
	// Fail fast if sops isn't on PATH — otherwise we'd write plaintext
	// certs to disk with no way to encrypt them cleanly.
	sopsPath, err := exec.LookPath("sops")
	if err != nil {
		return fmt.Errorf("sops binary not on PATH — install with `pkg install sops` (FreeBSD) or `apk add sops` (Alpine)")
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

	dir := filepath.Join(configDir, "hosts", host)
	if err := os.MkdirAll(dir, 0o755); err != nil {
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
	meta, err := config.LoadFleetMeta(configDir)
	if err != nil {
		return err
	}
	// Cert needs access to BOTH the network project (where ACLs and
	// address-sets live) AND every managed project (where containers
	// live). `CertProjects` unions them and removes duplicates.
	certProjects := strings.Join(meta.CertProjects(), ",")
	fmt.Fprintf(os.Stderr, "Wrote encrypted %s\n", path)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Client cert PEM is on stdout. Register with Incus on the target host:")
	fmt.Fprintf(os.Stderr, "  incus config trust add-certificate - --name gateway-bastion --restricted --projects %s\n", certProjects)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Ensure every managed project exists first on the target:")
	for _, p := range meta.Projects {
		fmt.Fprintf(os.Stderr, "  incus project create %s\n", p)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "Then commit: git add %s && git commit -m 'add %s remote'\n", path, host)

	// Cert PEM to stdout.
	if _, err := os.Stdout.Write(certPEM); err != nil {
		return err
	}
	return nil
}
