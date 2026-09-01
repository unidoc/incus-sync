package incus

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	incusclient "github.com/lxc/incus/v7/client"

	"github.com/unidoc/incus-sync/internal/config"
)

// DefaultSocket is the standard Incus unix socket path.
const DefaultSocket = "/var/lib/incus/unix.socket"

// Connect returns an authenticated InstanceServer.
//
// If remote is nil, uses the local unix socket at socketPath.
// If remote is non-nil, uses HTTPS with TLS client cert auth and
// server-cert fingerprint pinning.
func Connect(socketPath string, remote *config.Remote) (incusclient.InstanceServer, error) {
	if remote == nil {
		if socketPath == "" {
			socketPath = DefaultSocket
		}
		srv, err := incusclient.ConnectIncusUnix(socketPath, nil)
		if err != nil {
			return nil, fmt.Errorf("connect to incus at %s: %w", socketPath, err)
		}
		return srv, nil
	}
	return connectRemote(remote)
}

// connectRemote handles the HTTPS + TLS-client-cert flow.
//
// The incus client's ConnectionInfo.Certificate is only populated if we
// pass TLSServerCert in ConnectionArgs — it does not surface the peer
// cert from the actual TLS handshake. So we do a raw tls.Dial first,
// grab the peer cert, verify the fingerprint out-of-band, then pass the
// PEM back as TLSServerCert. That way the incus client's own verifier
// enforces the pin on every subsequent request (no InsecureSkipVerify).
func connectRemote(r *config.Remote) (incusclient.InstanceServer, error) {
	if r.ServerFingerprint == "" {
		return nil, fmt.Errorf(
			"remote %s: server_fingerprint is empty. Refusing silent TOFU. "+
				"Bootstrap this remote with `incus-sync remote bootstrap <host>`.",
			r.URL)
	}
	pinnedPEM, err := fetchAndPinServerCert(r.URL, r.ServerFingerprint)
	if err != nil {
		return nil, err
	}
	args := &incusclient.ConnectionArgs{
		TLSClientCert: r.ClientCert,
		TLSClientKey:  r.ClientKey,
		TLSServerCert: pinnedPEM,
	}
	srv, err := incusclient.ConnectIncus(r.URL, args)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", r.URL, err)
	}
	return srv, nil
}

// fetchAndPinServerCert does a raw tls.Dial to the remote URL's host:port,
// extracts the peer certificate, and verifies its SHA256 DER fingerprint
// matches the expected pin. Returns the cert PEM on success. Refuses on
// mismatch (no silent TOFU — this is our root of trust for the daemon).
func fetchAndPinServerCert(remoteURL, expectedFingerprint string) (string, error) {
	u, err := url.Parse(remoteURL)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", remoteURL, err)
	}
	host := u.Host
	if u.Port() == "" {
		host = u.Hostname() + ":8443" // Incus default
	}
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // we verify by fingerprint below
			MinVersion:         tls.VersionTLS12,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", fmt.Errorf("tls dial %s: %w", host, err)
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("tls dial returned non-TLS conn (should not happen)")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates from %s", host)
	}
	leaf := state.PeerCertificates[0]
	fpr := derFingerprint(leaf.Raw)
	if fpr != expectedFingerprint {
		return "", fmt.Errorf(
			"server fingerprint mismatch at %s:\n  expected %s\n  got      %s\n"+
				"Certificate rotation or MITM. Re-bootstrap only after out-of-band verification.",
			host, expectedFingerprint, fpr)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	return string(pemBytes), nil
}

func derFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToLower(hex.EncodeToString(sum[:]))
}
