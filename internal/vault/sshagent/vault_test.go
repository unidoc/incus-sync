package sshagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// keyringClient adapts agent.Keyring (in-memory agent) to our Client
// interface. Used everywhere in tests so we don't need a live socket.
type keyringClient struct{ ag agent.Agent }

func (k *keyringClient) List() ([]*agent.Key, error) { return k.ag.List() }
func (k *keyringClient) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return k.ag.Sign(key, data)
}
func (k *keyringClient) Close() error { return nil }

// newTestAgent builds an in-memory ssh-agent holding a fresh ed25519
// key. The returned Client behaves the same as a real agent socket.
func newTestAgent(t *testing.T, comment string) (Client, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv, Comment: comment}); err != nil {
		t.Fatalf("add key to keyring: %v", err)
	}
	return &keyringClient{ag: kr}, pub, priv
}

func TestInitAndUnlock_RoundTrips(t *testing.T) {
	c, _, _ := newTestAgent(t, "primary")
	agePlaintext := []byte("AGE-SECRET-KEY-1TEST-CONTENT-XYZ\n")

	keys, err := c.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("list: %v (len=%d)", err, len(keys))
	}
	f, err := Init(c, keys[0], agePlaintext)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	got, err := Unlock(c, f)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !bytes.Equal(got, agePlaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, agePlaintext)
	}
}

func TestInit_RejectsRSA(t *testing.T) {
	// Bypass ed25519 by manually crafting an agent.Key with wrong Type.
	c, pub, _ := newTestAgent(t, "primary")
	keys, _ := c.List()
	fake := &agent.Key{
		Format:  "ssh-rsa",
		Blob:    keys[0].Blob,
		Comment: "faked",
	}
	_ = pub
	_, err := Init(c, fake, []byte("secret"))
	if err == nil {
		t.Fatal("expected rejection for non-ed25519 key")
	}
}

func TestAddKey_LetsSecondKeyUnlock(t *testing.T) {
	// Build agent with two ed25519 keys and one shared ciphertext.
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	_ = kr.Add(agent.AddedKey{PrivateKey: priv1, Comment: "primary"})
	_ = kr.Add(agent.AddedKey{PrivateKey: priv2, Comment: "backup"})
	c := &keyringClient{ag: kr}

	keys, _ := c.List()
	agePlaintext := []byte("AGE-SECRET-KEY-1TEST\n")

	f, err := Init(c, keys[0], agePlaintext)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	f, err = AddKey(c, f, keys[1])
	if err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	if len(f.Recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(f.Recipients))
	}

	// Remove the first key from the agent — only backup remains.
	kr2 := agent.NewKeyring()
	_ = kr2.Add(agent.AddedKey{PrivateKey: priv2, Comment: "backup"})
	c2 := &keyringClient{ag: kr2}

	got, err := Unlock(c2, f)
	if err != nil {
		t.Fatalf("Unlock with backup key: %v", err)
	}
	if !bytes.Equal(got, agePlaintext) {
		t.Fatalf("backup unlock mismatch")
	}
	_ = pub1
	_ = pub2
}

func TestRemoveKey_RotatesDEKAndRevokes(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	kr := agent.NewKeyring()
	_ = kr.Add(agent.AddedKey{PrivateKey: priv1, Comment: "primary"})
	_ = kr.Add(agent.AddedKey{PrivateKey: priv2, Comment: "to-remove"})
	c := &keyringClient{ag: kr}

	keys, _ := c.List()
	f, _ := Init(c, keys[0], []byte("plaintext"))
	f, _ = AddKey(c, f, keys[1])

	sshPub2, _ := ssh.NewPublicKey(pub2)
	toRemove := Fingerprint(sshPub2)

	oldCiphertext := f.Ciphertext

	f, err := RemoveKey(c, f, toRemove)
	if err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if len(f.Recipients) != 1 {
		t.Fatalf("expected 1 recipient after remove, got %d", len(f.Recipients))
	}
	// DEK must have rotated — ciphertext should differ.
	if f.Ciphertext == oldCiphertext {
		t.Fatal("expected ciphertext to change after remove (DEK rotation)")
	}
	// Removed key alone can't unlock the NEW file.
	krJustRemoved := agent.NewKeyring()
	_ = krJustRemoved.Add(agent.AddedKey{PrivateKey: priv2, Comment: "to-remove"})
	if _, err := Unlock(&keyringClient{ag: krJustRemoved}, f); err == nil {
		t.Fatal("removed key should not unlock rotated vault")
	}
	// Primary still works.
	if _, err := Unlock(c, f); err != nil {
		t.Fatalf("primary should still unlock: %v", err)
	}
	_ = pub1
}

func TestRemoveKey_RefusesToRemoveLastRecipient(t *testing.T) {
	c, _, _ := newTestAgent(t, "sole")
	keys, _ := c.List()
	f, _ := Init(c, keys[0], []byte("secret"))
	_, err := RemoveKey(c, f, f.Recipients[0].Fingerprint)
	if err == nil {
		t.Fatal("expected refusal on removing the only recipient")
	}
}

func TestUnlock_FailsWhenNoRecipientInAgent(t *testing.T) {
	c, _, _ := newTestAgent(t, "primary")
	keys, _ := c.List()
	f, _ := Init(c, keys[0], []byte("secret"))

	// Switch to a different empty agent.
	empty := &keyringClient{ag: agent.NewKeyring()}
	_, err := Unlock(empty, f)
	if err == nil {
		t.Fatal("expected error when no recipient key is in agent")
	}
}

func TestDeriveKEK_IsDeterministic(t *testing.T) {
	sig := bytes.Repeat([]byte{0xAA}, 64)
	salt := bytes.Repeat([]byte{0x11}, 32)
	a := deriveKEK(sig, salt)
	b := deriveKEK(sig, salt)
	if !bytes.Equal(a, b) {
		t.Fatal("KEK derivation must be deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("KEK must be 32 bytes, got %d", len(a))
	}
	// Different salt → different KEK.
	saltAlt := bytes.Repeat([]byte{0x22}, 32)
	c := deriveKEK(sig, saltAlt)
	if bytes.Equal(a, c) {
		t.Fatal("different salt must produce different KEK")
	}
}
