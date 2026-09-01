// Package sshagent implements a vault backend that uses an SSH
// ed25519 key as an agent-backed key derivation mechanism. A
// deterministic signature over a fixed, domain-separated challenge
// is passed through HKDF-SHA256 to derive an AES-256-GCM key that
// encrypts the age private key. The SSH private key never leaves
// the agent.
//
// The security model rests on TWO assumptions that must both hold:
//
//  1. Ed25519 signatures are deterministic (RFC 8032). Same key +
//     same challenge → same 64 bytes, always. Verified at init
//     time by signing the challenge twice and refusing to proceed
//     unless the results match byte-for-byte.
//
//  2. The ssh-agent PROMPTS the operator for confirmation on every
//     SIGN. Without per-op confirmation, security degrades to
//     "any process with SSH_AUTH_SOCK can invoke SIGN silently and
//     derive the same AES key". This vault is only meaningful with
//     agents that enforce approval — 1Password SSH agent, YubiKey
//     via PIV-agent with touch policy, or `ssh-add -c` loaded keys.
//     A vanilla ssh-agent with a key loaded via plain `ssh-add`
//     offers no better protection than a plaintext key at rest.
//
// Design:
//
//	Init:
//	  1. Enumerate keys the ssh-agent can sign with.
//	  2. Operator picks an ssh-ed25519 key (only key type with
//	     guaranteed deterministic signatures per RFC 8032).
//	  3. SIGN a fixed challenge twice — refuse to proceed if the two
//	     signatures differ. Catches non-deterministic keys (FIDO2/sk,
//	     RSA-PSS, malfunctioning agents).
//	  4. Generate a random data-encryption-key (DEK).
//	  5. Wrap DEK for each recipient: key = HKDF(signature, salt),
//	     wrapped_dek = AES-256-GCM(DEK, key).
//	  6. Encrypt age key: ciphertext = AES-256-GCM(age_key, DEK).
//	  7. Persist recipients + ciphertext to disk (public data — only
//	     the signature is secret, and only the agent can produce it).
//
//	Unlock:
//	  1. Read vault file.
//	  2. For each recipient whose key IS in the ssh-agent right now,
//	     try SIGN + HKDF + unwrap. First success wins.
//	  3. Decrypt ciphertext with the recovered DEK.
//
//	Add/remove/rotate keys: revoking a recipient rotates the DEK so
//	the previous ciphertext is worthless to the removed key.
//
// Only ssh-ed25519 is accepted. RSA (deterministic PKCS#1 v1.5 but
// signature length varies with padding), ECDSA (non-deterministic by
// default in OpenSSH), and sk-ed25519 (FIDO2 counter → non-deterministic)
// are rejected at init and add-key time.
package sshagent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Challenge is signed by the agent to derive the wrap key. Domain-
// separated so this signature use cannot collide with any other use
// of the same SSH key (e.g. logging into a server, other vault tools).
// If we ever change the crypto scheme, bump the version suffix here
// AND the vault file version.
const Challenge = "github.com/unidoc/incus-sync/age-vault/v1"

// KeyAlgoEd25519 is the only accepted key algorithm. All others fail
// closed at init/add-key time — see file docstring.
const KeyAlgoEd25519 = "ssh-ed25519"

// ErrAgentUnavailable is returned when SSH_AUTH_SOCK is empty or the
// agent socket refuses connections. Callers translate this into an
// operator-friendly "SSH in with ForwardAgent yes and retry" hint.
var ErrAgentUnavailable = errors.New("ssh-agent unavailable (SSH_AUTH_SOCK empty or socket unreachable)")

// Client wraps a connected ssh-agent for the operations this package
// needs. Kept small so tests can supply an in-memory agent.NewKeyring()
// via the same interface.
type Client interface {
	List() ([]*agent.Key, error)
	Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error)
	Close() error
}

// realClient wraps a live socket connection.
type realClient struct {
	conn net.Conn
	ag   agent.ExtendedAgent
}

func (c *realClient) List() ([]*agent.Key, error) { return c.ag.List() }
func (c *realClient) Sign(k ssh.PublicKey, d []byte) (*ssh.Signature, error) {
	return c.ag.Sign(k, d)
}
func (c *realClient) Close() error { return c.conn.Close() }

// Dial connects to the agent at $SSH_AUTH_SOCK. Callers must Close().
func Dial() (Client, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, ErrAgentUnavailable
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentUnavailable, err)
	}
	return &realClient{conn: conn, ag: agent.NewClient(conn)}, nil
}

// Fingerprint returns the standard SHA256:xxx representation of a
// public key — matches what `ssh-add -l` prints and what users see in
// 1Password's SSH keys UI.
func Fingerprint(k ssh.PublicKey) string {
	return ssh.FingerprintSHA256(k)
}

// FindKey selects a key from the agent by fingerprint. Returns
// ErrKeyNotInAgent if no match — the caller distinguishes this from
// other failures so it can print "the vault was initialised with key
// SHA256:xxx which is not currently loaded in your ssh-agent".
func FindKey(c Client, fingerprint string) (*agent.Key, error) {
	keys, err := c.List()
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if Fingerprint(k) == fingerprint {
			return k, nil
		}
	}
	return nil, ErrKeyNotInAgent
}

// ErrKeyNotInAgent means the vault was created for a key that is not
// currently loaded in the agent. Recoverable — plug in the YubiKey,
// re-forward the agent, etc.
var ErrKeyNotInAgent = errors.New("required ssh key is not loaded in ssh-agent")

// RequireEd25519 rejects non-ed25519 keys. Only ed25519 signatures are
// guaranteed deterministic per RFC 8032 without additional work.
// Rejecting others is a fail-safe: if a user tries to init with an
// RSA/ECDSA/sk-ed25519 key by mistake, they'd end up with a vault
// they can never re-unlock (subsequent SIGN produces a different sig).
func RequireEd25519(k *agent.Key) error {
	if k.Type() != KeyAlgoEd25519 {
		return fmt.Errorf(
			"only ssh-ed25519 keys are supported (got %q). ed25519 has "+
				"deterministic signatures per RFC 8032 — RSA-PSS, ECDSA, "+
				"and sk-ed25519 FIDO2 keys sign differently every time, "+
				"which would produce a vault that cannot be re-unlocked",
			k.Type())
	}
	return nil
}

// VerifyDeterministic signs the challenge twice and refuses to return
// unless both signature blobs are byte-identical. Belt-and-suspenders
// on top of RequireEd25519 — catches bugs like an agent that adds
// framing entropy, or a misdeclared key type.
func VerifyDeterministic(c Client, k ssh.PublicKey) ([]byte, error) {
	sig1, err := c.Sign(k, []byte(Challenge))
	if err != nil {
		return nil, err
	}
	sig2, err := c.Sign(k, []byte(Challenge))
	if err != nil {
		return nil, err
	}
	if !bytesEqual(sig1.Blob, sig2.Blob) || sig1.Format != sig2.Format {
		return nil, fmt.Errorf(
			"agent produced two different signatures for the same challenge "+
				"(format1=%s bloblen1=%d format2=%s bloblen2=%d) — the key "+
				"is not deterministic. sk-ed25519 (FIDO2 with counter), "+
				"RSA-PSS, or a broken agent implementation is the usual cause",
			sig1.Format, len(sig1.Blob), sig2.Format, len(sig2.Blob))
	}
	return sig1.Blob, nil
}

// SignChallenge is the operational form once we trust the key is
// deterministic. Returns just the signature blob (raw ed25519 sig).
func SignChallenge(c Client, k ssh.PublicKey) ([]byte, error) {
	sig, err := c.Sign(k, []byte(Challenge))
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

// randomBytes returns n bytes of cryptographic randomness. Panic on
// error — /dev/urandom failing means the kernel is on fire.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("crypto/rand.Reader failed: " + err.Error())
	}
	return b
}

// bytesEqual is subtle package constant-time not needed here (both
// values come from OUR agent, no attacker manipulation), but we keep
// it constant-time-ish as a habit.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// commentFromKey returns the agent's comment for a key if present,
// stripped of surrounding whitespace. Used in list output.
func commentFromKey(k *agent.Key) string {
	return strings.TrimSpace(k.Comment)
}
