package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T, fill byte) string {
	t.Helper()
	key := bytes.Repeat([]byte{fill}, KeySize)
	return base64.StdEncoding.EncodeToString(key)
}

func newTestEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	e, err := NewEncryptor(testKey(t, 0x01), 1, nil)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return e
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	e := newTestEncryptor(t)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"ascii", []byte("super-secret-password")},
		{"binary", []byte{0x00, 0xff, 0x10, 0x00, 0x7f}},
		{"utf8", []byte("пароль-🔐-密码")},
		{"long", bytes.Repeat([]byte("k"), 8192)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := e.Encrypt(tc.data)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			got, err := e.Decrypt(blob)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("round trip mismatch: got %q want %q", got, tc.data)
			}
			// Plaintext must never appear in the ciphertext.
			if len(tc.data) > 0 && bytes.Contains(blob, tc.data) {
				t.Fatal("plaintext is present in the ciphertext blob")
			}
		})
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	e := newTestEncryptor(t)
	plain := []byte("identical input")

	a, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := e.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext are byte-identical; nonce is being reused")
	}
	if bytes.Equal(a[1:1+NonceSize], b[1:1+NonceSize]) {
		t.Fatal("nonce repeated across encryptions")
	}
}

func TestBlobLayout(t *testing.T) {
	e := newTestEncryptor(t)
	blob, err := e.Encrypt([]byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if blob[0] != FormatVersion {
		t.Errorf("version byte = %d, want %d", blob[0], FormatVersion)
	}
	if blob[1+NonceSize] != e.KeyID() {
		t.Errorf("key id = %d, want %d", blob[1+NonceSize], e.KeyID())
	}
	if want := overhead + 1 + TagSize; len(blob) != want {
		t.Errorf("blob length = %d, want %d", len(blob), want)
	}
}

func TestDecryptRejectsTampering(t *testing.T) {
	e := newTestEncryptor(t)
	blob, err := e.Encrypt([]byte("sensitive credential material"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		mut := bytes.Clone(blob)
		mut[len(mut)-1] ^= 0x01
		if _, err := e.Decrypt(mut); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("flipped nonce bit", func(t *testing.T) {
		mut := bytes.Clone(blob)
		mut[1] ^= 0x01
		if _, err := e.Decrypt(mut); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("flipped key id bit", func(t *testing.T) {
		mut := bytes.Clone(blob)
		mut[1+NonceSize] ^= 0x01
		if _, err := e.Decrypt(mut); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("flipped version bit", func(t *testing.T) {
		mut := bytes.Clone(blob)
		mut[0] = 0x7f
		if _, err := e.Decrypt(mut); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		if _, err := e.Decrypt(blob[:len(blob)-1]); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("too short", func(t *testing.T) {
		if _, err := e.Decrypt([]byte{1, 2, 3}); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("nil", func(t *testing.T) {
		if _, err := e.Decrypt(nil); !errors.Is(err, ErrDecryptFailed) {
			t.Fatalf("got %v, want ErrDecryptFailed", err)
		}
	})
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	a := newTestEncryptor(t)
	blob, err := a.Encrypt([]byte("credential"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	b, err := NewEncryptor(testKey(t, 0x02), 1, nil)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	if _, err := b.Decrypt(blob); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("decrypting with a different key: got %v, want ErrDecryptFailed", err)
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey := testKey(t, 0x0a)
	newKey := testKey(t, 0x0b)

	old, err := NewEncryptor(oldKey, 1, nil)
	if err != nil {
		t.Fatalf("NewEncryptor(old): %v", err)
	}
	legacy, err := old.Encrypt([]byte("written under key 1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Rotate: key 2 becomes active, key 1 retained for decryption.
	rotated, err := NewEncryptor(newKey, 2, map[uint8]string{1: oldKey})
	if err != nil {
		t.Fatalf("NewEncryptor(rotated): %v", err)
	}

	got, err := rotated.Decrypt(legacy)
	if err != nil {
		t.Fatalf("old ciphertext must still decrypt after rotation: %v", err)
	}
	if string(got) != "written under key 1" {
		t.Fatalf("got %q", got)
	}

	if !rotated.NeedsRotation(legacy) {
		t.Error("NeedsRotation should report true for ciphertext under the old key")
	}

	fresh, err := rotated.Encrypt([]byte("written under key 2"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if rotated.NeedsRotation(fresh) {
		t.Error("NeedsRotation should report false for ciphertext under the active key")
	}

	// A key that was dropped cannot decrypt anything.
	pruned, err := NewEncryptor(newKey, 2, nil)
	if err != nil {
		t.Fatalf("NewEncryptor(pruned): %v", err)
	}
	if _, err := pruned.Decrypt(legacy); !errors.Is(err, ErrDecryptFailed) {
		t.Fatalf("after dropping key 1: got %v, want ErrDecryptFailed", err)
	}
}

func TestNewEncryptorRejectsBadKeys(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		id      uint8
		wantSub string
	}{
		{"empty", "", 1, "32 bytes"},
		{"not base64", "!!!not-base64!!!", 1, "base64"},
		{"too short", base64.StdEncoding.EncodeToString([]byte("short")), 1, "32 bytes"},
		{"too long", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)), 1, "32 bytes"},
		{"zero key id", testKey(t, 0x01), 0, "must not be 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEncryptor(tc.key, tc.id, nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestDecryptErrorIsOpaque(t *testing.T) {
	// The error must not reveal which stage failed, so it cannot be used as an
	// oracle by an attacker probing stored blobs.
	e := newTestEncryptor(t)
	blob, _ := e.Encrypt([]byte("x"))

	_, errShort := e.Decrypt([]byte{1})
	mut := bytes.Clone(blob)
	mut[len(mut)-1] ^= 1
	_, errTamper := e.Decrypt(mut)

	if errShort.Error() != errTamper.Error() {
		t.Fatalf("distinct error messages leak failure stage: %q vs %q", errShort, errTamper)
	}
	if errShort.Error() != ErrDecryptFailed.Error() {
		t.Fatalf("error %q is not opaque", errShort)
	}
}

func TestGenerateKey(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if a == b {
		t.Fatal("GenerateKey returned the same key twice")
	}
	if _, err := NewEncryptor(a, 1, nil); err != nil {
		t.Fatalf("generated key is not usable: %v", err)
	}
}
