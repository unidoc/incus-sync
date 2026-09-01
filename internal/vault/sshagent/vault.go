package sshagent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
)

func sha256New() hash.Hash { return sha256.New() }

// FileFormatVersion is the on-disk format version. Bumped when the
// wire format or crypto scheme changes in a non-backward-compatible
// way. Also bake into the challenge string so old signatures cannot
// decrypt new-format vaults.
const FileFormatVersion = 1

// File is the on-disk representation of the vault. Every field except
// the SSH signature that produces the wrap key is public.
//
// Recovery: even without any recipient private key, the file leaks
// nothing about the plaintext beyond its length — AES-256-GCM is
// IND-CCA and authenticated.
type File struct {
	Version         int         `yaml:"version"`
	Challenge       string      `yaml:"challenge"`
	KDF             string      `yaml:"kdf"`              // must be "hkdf-sha256"
	AEAD            string      `yaml:"aead"`             // must be "aes-256-gcm"
	Salt            string      `yaml:"salt"`             // b64, 32 bytes
	CiphertextNonce string      `yaml:"ciphertext_nonce"` // b64, 12 bytes
	Ciphertext      string      `yaml:"ciphertext"`       // b64, AES-GCM(age_key, DEK)
	Recipients      []Recipient `yaml:"recipients"`
}

// Recipient is one wrapped copy of the DEK. Any recipient whose SSH
// key is present in the agent can unwrap.
type Recipient struct {
	Fingerprint string `yaml:"fingerprint"`       // SHA256:...
	Comment     string `yaml:"comment,omitempty"` // agent-provided key comment
	KeyBlob     string `yaml:"key_blob"`          // b64 SSH wire-format pubkey
	DEKNonce    string `yaml:"dek_nonce"`         // b64, 12 bytes
	WrappedDEK  string `yaml:"wrapped_dek"`       // b64, AES-GCM(DEK, KEK)
}

// DefaultPath is where the named vault's file lives. Kept short and
// predictable. Each name is fully independent — see the vault package
// doc for why vaults are named per fleet rather than shared.
func DefaultPath(name string) string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return filepath.Join(v, "incus-sync", name, "vault.ssh")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "incus-sync", name, "vault.ssh")
}

// Load reads the vault file from path. Returns nil,nil if the file
// does not exist so callers can fall through to another backend.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.Version != FileFormatVersion {
		return nil, fmt.Errorf("%s: unsupported version %d (expected %d)", path, f.Version, FileFormatVersion)
	}
	if f.Challenge != Challenge {
		return nil, fmt.Errorf("%s: challenge %q does not match expected %q — vault was init'd for a different scheme", path, f.Challenge, Challenge)
	}
	if f.KDF != "hkdf-sha256" {
		return nil, fmt.Errorf("%s: unsupported KDF %q", path, f.KDF)
	}
	if f.AEAD != "aes-256-gcm" {
		return nil, fmt.Errorf("%s: unsupported AEAD %q", path, f.AEAD)
	}
	return &f, nil
}

// Save writes the vault file atomically with mode 0600.
func Save(path string, f *File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Init creates a new vault protecting `agePlaintext` for the single
// key `k` in agent `c`. Verifies the key is deterministic and ed25519
// before writing anything.
func Init(c Client, k *agent.Key, agePlaintext []byte) (*File, error) {
	if err := RequireEd25519(k); err != nil {
		return nil, err
	}
	pub, err := ssh.ParsePublicKey(k.Blob)
	if err != nil {
		return nil, fmt.Errorf("parse agent pubkey: %w", err)
	}
	sig, err := VerifyDeterministic(c, pub)
	if err != nil {
		return nil, err
	}

	salt := randomBytes(32)
	dek := randomBytes(32)      // master data-encryption-key
	ctNonce := randomBytes(12)  // AES-GCM nonce for ciphertext
	dekNonce := randomBytes(12) // AES-GCM nonce for wrapped DEK

	kek := deriveKEK(sig, salt)
	wrapped, err := aeadSeal(dek, kek, dekNonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := aeadSeal(agePlaintext, dek, ctNonce)
	if err != nil {
		return nil, err
	}

	f := &File{
		Version:         FileFormatVersion,
		Challenge:       Challenge,
		KDF:             "hkdf-sha256",
		AEAD:            "aes-256-gcm",
		Salt:            b64(salt),
		CiphertextNonce: b64(ctNonce),
		Ciphertext:      b64(ciphertext),
		Recipients: []Recipient{{
			Fingerprint: Fingerprint(pub),
			Comment:     commentFromKey(k),
			KeyBlob:     b64(k.Blob),
			DEKNonce:    b64(dekNonce),
			WrappedDEK:  b64(wrapped),
		}},
	}
	return f, nil
}

// Unlock returns the plaintext age key. Tries every recipient whose
// key is currently loaded in the agent; first successful unwrap wins.
// If none of the recipients' keys are in the agent, returns an error
// listing what would need to be plugged in.
func Unlock(c Client, f *File) ([]byte, error) {
	salt, err := unb64(f.Salt)
	if err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}

	agentKeys, err := c.List()
	if err != nil {
		return nil, fmt.Errorf("list agent keys: %w", err)
	}
	agentByFP := map[string]*agent.Key{}
	for _, k := range agentKeys {
		agentByFP[Fingerprint(k)] = k
	}

	var attempted []string
	for _, r := range f.Recipients {
		attempted = append(attempted, r.Fingerprint)
		ak, ok := agentByFP[r.Fingerprint]
		if !ok {
			continue
		}
		pub, err := ssh.ParsePublicKey(ak.Blob)
		if err != nil {
			continue
		}
		sig, err := SignChallenge(c, pub)
		if err != nil {
			return nil, fmt.Errorf("sign with %s: %w", r.Fingerprint, err)
		}
		kek := deriveKEK(sig, salt)

		wrapped, err := unb64(r.WrappedDEK)
		if err != nil {
			continue
		}
		dekNonce, err := unb64(r.DEKNonce)
		if err != nil {
			continue
		}
		dek, err := aeadOpen(wrapped, kek, dekNonce)
		if err != nil {
			// Wrong key or corrupted file — try next recipient.
			continue
		}

		ct, err := unb64(f.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("ciphertext: %w", err)
		}
		ctNonce, err := unb64(f.CiphertextNonce)
		if err != nil {
			return nil, fmt.Errorf("ciphertext_nonce: %w", err)
		}
		plaintext, err := aeadOpen(ct, dek, ctNonce)
		if err != nil {
			return nil, fmt.Errorf("decrypt ciphertext (vault corrupted?): %w", err)
		}
		return plaintext, nil
	}

	return nil, fmt.Errorf(
		"no vault recipient is present in ssh-agent. vault has recipients: %v",
		attempted)
}

// AddKey wraps the DEK for an additional recipient. Requires access
// to an existing recipient's key to first recover the DEK.
func AddKey(c Client, f *File, newKey *agent.Key) (*File, error) {
	if err := RequireEd25519(newKey); err != nil {
		return nil, err
	}
	newPub, err := ssh.ParsePublicKey(newKey.Blob)
	if err != nil {
		return nil, err
	}
	newFP := Fingerprint(newPub)
	for _, r := range f.Recipients {
		if r.Fingerprint == newFP {
			return nil, fmt.Errorf("key %s is already a recipient", newFP)
		}
	}
	// Recover DEK via existing recipient.
	dek, err := recoverDEK(c, f)
	if err != nil {
		return nil, err
	}
	// Sanity-check the new key is deterministic before we bake it in.
	newSig, err := VerifyDeterministic(c, newPub)
	if err != nil {
		return nil, err
	}
	salt, err := unb64(f.Salt)
	if err != nil {
		return nil, err
	}
	kek := deriveKEK(newSig, salt)
	newDEKNonce := randomBytes(12)
	wrapped, err := aeadSeal(dek, kek, newDEKNonce)
	if err != nil {
		return nil, err
	}
	f.Recipients = append(f.Recipients, Recipient{
		Fingerprint: newFP,
		Comment:     commentFromKey(newKey),
		KeyBlob:     b64(newKey.Blob),
		DEKNonce:    b64(newDEKNonce),
		WrappedDEK:  b64(wrapped),
	})
	return f, nil
}

// RemoveKey drops a recipient AND rotates the DEK. Without rotation,
// the removed recipient (if they still have the old file and their
// key) could decrypt — so removal is only a real revocation if we
// re-encrypt with a new DEK.
func RemoveKey(c Client, f *File, fingerprint string) (*File, error) {
	// Confirm the fingerprint is a current recipient.
	found := -1
	for i, r := range f.Recipients {
		if r.Fingerprint == fingerprint {
			found = i
			break
		}
	}
	if found < 0 {
		return nil, fmt.Errorf("no recipient with fingerprint %s", fingerprint)
	}
	if len(f.Recipients) == 1 {
		return nil, fmt.Errorf("cannot remove the sole recipient — would lock everyone out")
	}
	// Recover current plaintext age key using a remaining recipient
	// (not the one being removed).
	plaintext, err := Unlock(c, f)
	if err != nil {
		return nil, err
	}
	// Drop the target recipient.
	remaining := make([]Recipient, 0, len(f.Recipients)-1)
	for _, r := range f.Recipients {
		if r.Fingerprint != fingerprint {
			remaining = append(remaining, r)
		}
	}
	// Rotate DEK + ciphertext. Re-wrap for every remaining recipient.
	nf, err := rewrapAll(c, plaintext, remaining)
	if err != nil {
		return nil, err
	}
	return nf, nil
}

// Rotate generates a new DEK and re-wraps for all current recipients.
// Useful after a suspected exposure or on a routine cadence.
func Rotate(c Client, f *File) (*File, error) {
	plaintext, err := Unlock(c, f)
	if err != nil {
		return nil, err
	}
	return rewrapAll(c, plaintext, f.Recipients)
}

// rewrapAll builds a fresh vault (new salt + DEK + ciphertext) and
// re-wraps for the given recipient list. Requires every recipient's
// key to be in the agent — otherwise we would silently drop them.
func rewrapAll(c Client, plaintext []byte, recipients []Recipient) (*File, error) {
	agentKeys, err := c.List()
	if err != nil {
		return nil, err
	}
	agentByFP := map[string]*agent.Key{}
	for _, k := range agentKeys {
		agentByFP[Fingerprint(k)] = k
	}

	salt := randomBytes(32)
	dek := randomBytes(32)
	ctNonce := randomBytes(12)
	ciphertext, err := aeadSeal(plaintext, dek, ctNonce)
	if err != nil {
		return nil, err
	}

	newRecipients := make([]Recipient, 0, len(recipients))
	var missing []string
	for _, r := range recipients {
		ak, ok := agentByFP[r.Fingerprint]
		if !ok {
			missing = append(missing, r.Fingerprint)
			continue
		}
		pub, err := ssh.ParsePublicKey(ak.Blob)
		if err != nil {
			return nil, err
		}
		sig, err := SignChallenge(c, pub)
		if err != nil {
			return nil, fmt.Errorf("sign with %s: %w", r.Fingerprint, err)
		}
		kek := deriveKEK(sig, salt)
		dekNonce := randomBytes(12)
		wrapped, err := aeadSeal(dek, kek, dekNonce)
		if err != nil {
			return nil, err
		}
		newRecipients = append(newRecipients, Recipient{
			Fingerprint: r.Fingerprint,
			Comment:     commentFromKey(ak),
			KeyBlob:     b64(ak.Blob),
			DEKNonce:    b64(dekNonce),
			WrappedDEK:  b64(wrapped),
		})
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"cannot rotate — the following recipients' keys are not in the "+
				"agent (rotation would silently drop them): %v", missing)
	}

	return &File{
		Version:         FileFormatVersion,
		Challenge:       Challenge,
		KDF:             "hkdf-sha256",
		AEAD:            "aes-256-gcm",
		Salt:            b64(salt),
		CiphertextNonce: b64(ctNonce),
		Ciphertext:      b64(ciphertext),
		Recipients:      newRecipients,
	}, nil
}

// recoverDEK unwraps the DEK using the first recipient whose key is
// currently in the agent. Used by AddKey (which needs the plaintext
// DEK to wrap for one more recipient) — Unlock is the fuller version
// that also decrypts the ciphertext.
func recoverDEK(c Client, f *File) ([]byte, error) {
	salt, err := unb64(f.Salt)
	if err != nil {
		return nil, err
	}
	agentKeys, err := c.List()
	if err != nil {
		return nil, err
	}
	agentByFP := map[string]*agent.Key{}
	for _, k := range agentKeys {
		agentByFP[Fingerprint(k)] = k
	}
	for _, r := range f.Recipients {
		ak, ok := agentByFP[r.Fingerprint]
		if !ok {
			continue
		}
		pub, err := ssh.ParsePublicKey(ak.Blob)
		if err != nil {
			continue
		}
		sig, err := SignChallenge(c, pub)
		if err != nil {
			return nil, err
		}
		kek := deriveKEK(sig, salt)
		wrapped, err := unb64(r.WrappedDEK)
		if err != nil {
			continue
		}
		nonce, err := unb64(r.DEKNonce)
		if err != nil {
			continue
		}
		dek, err := aeadOpen(wrapped, kek, nonce)
		if err != nil {
			continue
		}
		return dek, nil
	}
	return nil, errors.New("no recipient key in agent")
}

// deriveKEK returns 32 bytes from HKDF-SHA256(ikm=signature, salt=salt,
// info="incus-sync/dek-wrap/v1"). The info string domain-separates
// this derivation from any other use of the same signature bytes.
func deriveKEK(sig, salt []byte) []byte {
	r := hkdf.New(sha256New, sig, salt, []byte("incus-sync/dek-wrap/v1"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf failed: " + err.Error())
	}
	return out
}

// aeadSeal encrypts pt with AES-256-GCM. key must be 32 bytes, nonce
// 12 bytes. Output is ciphertext || tag (16 bytes tag appended).
func aeadSeal(pt, key, nonce []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce must be 12 bytes, got %d", len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, pt, nil), nil
}

// aeadOpen decrypts + authenticates.
func aeadOpen(ct, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, nil)
}

func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
