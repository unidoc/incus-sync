package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3/decrypt"
	"gopkg.in/yaml.v3"
)

// Remote describes one Incus host's HTTPS API endpoint and the client
// TLS material to authenticate against it. Loaded from
// `hosts/<host>/remote.sops.yaml`, which is SOPS-encrypted at rest:
// `url` and `server_fingerprint` are plaintext (public info), while
// `client_cert` and `client_key` are age-encrypted by SOPS.
//
// Never written to disk decrypted. Decrypted values live only in
// memory for the duration of one command.
type Remote struct {
	// URL is the Incus HTTPS API endpoint, e.g.
	//   https://web1.example.com:22443
	URL string `yaml:"url"`

	// ServerFingerprint pins the Incus server certificate.
	// SHA256, hex-encoded (with or without colons). If empty, the
	// tool refuses to connect — TOFU with explicit human confirm is
	// preferred to silent trust-on-first-use.
	ServerFingerprint string `yaml:"server_fingerprint"`

	// ClientCert is PEM-encoded X.509. Encrypted at rest.
	ClientCert string `yaml:"client_cert"`

	// ClientKey is PEM-encoded private key. Encrypted at rest.
	ClientKey string `yaml:"client_key"`
}

// LoadRemote reads `hosts/<host>/remote.sops.yaml`, decrypts via SOPS
// (using the bastion's age private key from SOPS_AGE_KEY_FILE or the
// default location), and returns a Remote.
//
// Returns (nil, nil) if the file does not exist — the caller falls
// back to the local unix socket. Returns an error only on decrypt or
// parse failure.
func LoadRemote(configDir, host string) (*Remote, error) {
	path := filepath.Join(configDir, "hosts", host, "remote.sops.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// If the file has no `sops:` metadata block, treat as plaintext
	// (dev convenience — never commit a plaintext remote file).
	var decrypted []byte
	if strings.Contains(string(raw), "\nsops:\n") || strings.HasPrefix(string(raw), "sops:\n") {
		decrypted, err = decrypt.Data(raw, "yaml")
		if err != nil {
			return nil, fmt.Errorf("sops decrypt %s: %w  "+
				"(check SOPS_AGE_KEY_FILE or ~/.config/sops/age/keys.txt)",
				path, err)
		}
	} else {
		decrypted = raw
	}

	var r Remote
	if err := yaml.Unmarshal(decrypted, &r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if r.URL == "" {
		return nil, fmt.Errorf("%s: missing url", path)
	}
	if r.ClientCert == "" || r.ClientKey == "" {
		return nil, fmt.Errorf("%s: missing client_cert or client_key (are they encrypted properly?)", path)
	}

	// Normalise fingerprint — accept "sha256:AA:BB:CC..." or bare hex.
	r.ServerFingerprint = strings.ToLower(r.ServerFingerprint)
	r.ServerFingerprint = strings.TrimPrefix(r.ServerFingerprint, "sha256:")
	r.ServerFingerprint = strings.ReplaceAll(r.ServerFingerprint, ":", "")

	return &r, nil
}

// ListRemotes returns every host under configDir/hosts/ that has a
// remote.sops.yaml (encrypted or not). Used by `incus-sync remote
// list` and by the `fleet` command to iterate all remotes.
func ListRemotes(configDir string) ([]string, error) {
	hostsDir := filepath.Join(configDir, "hosts")
	entries, err := os.ReadDir(hostsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(hostsDir, e.Name(), "remote.sops.yaml")); err == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
