// Package crypto implements Next.Panel's credential encryption.
//
// This is the ONLY package permitted to perform encryption or decryption
// (Design Spec §3.2). Application code reaches it through
// internal/credentials, never directly.
//
// Ciphertext blob layout (Design Spec §15.1):
//
//	┌────────┬───────────┬──────────┬──────────────────────┐
//	│ ver(1) │ nonce(12) │ key_id(1)│ ciphertext || tag(16)│
//	└────────┴───────────┴──────────┴──────────────────────┘
//
// The version byte and key id are bound as additional authenticated data, so
// a blob cannot be reinterpreted under a different key id or format version.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	// FormatVersion is the current ciphertext layout version.
	FormatVersion byte = 1

	// KeySize is the required AES-256 key length in bytes.
	KeySize = 32

	// NonceSize is the AES-GCM nonce length in bytes.
	NonceSize = 12

	// TagSize is the AES-GCM authentication tag length in bytes.
	TagSize = 16

	// overhead is ver + nonce + key_id.
	overhead = 1 + NonceSize + 1
)

// ErrDecryptFailed is returned for every decryption failure: malformed,
// truncated, wrong key, or tampered ciphertext. Callers must not attempt to
// distinguish these cases in user-facing output.
var ErrDecryptFailed = errors.New("crypto: decryption failed")

// Encryptor performs authenticated encryption of credential material.
//
// It is safe for concurrent use: it holds only immutable key material.
type Encryptor struct {
	active uint8
	aeads  map[uint8]cipher.AEAD
}

// NewEncryptor builds an encryptor from a base64-encoded 32-byte active key.
// previousKeys maps key id -> base64 key, used to decrypt existing ciphertext
// during key rotation (Design Spec §15.2). It returns an error rather than
// generating a fallback key: silently inventing a key would make stored
// credentials permanently undecryptable.
func NewEncryptor(activeKeyB64 string, activeID uint8, previous map[uint8]string) (*Encryptor, error) {
	if activeID == 0 {
		return nil, errors.New("crypto: active key id must not be 0")
	}

	aeads := make(map[uint8]cipher.AEAD, len(previous)+1)

	for id, enc := range previous {
		if id == activeID {
			continue
		}
		aead, err := newAEADFromBase64(enc)
		if err != nil {
			return nil, fmt.Errorf("crypto: previous key %d: %w", id, err)
		}
		aeads[id] = aead
	}

	activeAEAD, err := newAEADFromBase64(activeKeyB64)
	if err != nil {
		return nil, fmt.Errorf("crypto: active key: %w", err)
	}
	aeads[activeID] = activeAEAD

	return &Encryptor{active: activeID, aeads: aeads}, nil
}

func newAEADFromBase64(encoded string) (cipher.AEAD, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try URL-safe / unpadded variants, which operators commonly paste.
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("not valid base64")
		}
	}
	if len(raw) != KeySize {
		return nil, fmt.Errorf("must decode to exactly %d bytes, got %d", KeySize, len(raw))
	}
	return newAEAD(raw)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds the version and key id into the authentication tag.
func aad(version, keyID byte) []byte {
	return []byte{version, keyID}
}

// Encrypt seals plaintext under the active key. A fresh random nonce is
// generated for every call; nonces are never derived from the plaintext and
// never reused (nonce reuse is catastrophic for GCM).
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	aead := e.aeads[e.active]

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce generation failed: %w", err)
	}

	out := make([]byte, 0, overhead+len(plaintext)+TagSize)
	out = append(out, FormatVersion)
	out = append(out, nonce...)
	out = append(out, e.active)
	out = aead.Seal(out, nonce, plaintext, aad(FormatVersion, e.active))
	return out, nil
}

// Decrypt opens a ciphertext produced by Encrypt. Every failure returns
// ErrDecryptFailed; callers translate that into a typed error and audit it as
// a security event. There is no fallback path that returns plaintext.
func (e *Encryptor) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) < overhead+TagSize {
		return nil, ErrDecryptFailed
	}

	version := blob[0]
	if version != FormatVersion {
		return nil, ErrDecryptFailed
	}

	nonce := blob[1 : 1+NonceSize]
	keyID := blob[1+NonceSize]

	aead, ok := e.aeads[keyID]
	if !ok {
		// Unknown key id: the operator removed a key that is still in use.
		return nil, ErrDecryptFailed
	}

	ct := blob[overhead:]
	pt, err := aead.Open(nil, nonce, ct, aad(version, keyID))
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

// KeyID reports the key id that would be used for new ciphertext.
func (e *Encryptor) KeyID() uint8 { return e.active }

// NeedsRotation reports whether a blob was encrypted under a key other than
// the active one, so a rotation sweep can find it (Design Spec §15.2).
func (e *Encryptor) NeedsRotation(blob []byte) bool {
	if len(blob) < overhead+TagSize {
		return false
	}
	return blob[1+NonceSize] != e.active
}

// ConstantTimeEqual compares two byte slices without leaking length-dependent
// timing beyond the length check itself.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GenerateKey returns a new random base64-encoded 32-byte key, for the
// `nextpanel crypto generate-key` bootstrap path.
func GenerateKey() (string, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
