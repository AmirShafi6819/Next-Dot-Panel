// Package credentials is the only boundary that turns stored credential
// ciphertext back into plaintext (Design Spec §14). Application code calls
// Unwrap as late as possible and Closes the result immediately after use; raw
// material never leaves this package except through an Unwrapped value.
package credentials

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ashaibery/Next-Dot-Panel/internal/crypto"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/secret"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Sentinel errors.
var (
	// ErrNoCredential means the server has no stored credential.
	ErrNoCredential = errors.New("credentials: no credential stored")

	// ErrDecrypt means the stored ciphertext could not be decrypted. It is a
	// security event: the key may be wrong or the data tampered with.
	ErrDecrypt = errors.New("credentials: stored credential could not be decrypted")

	// ErrEmpty means a credential payload carried no material.
	ErrEmpty = errors.New("credentials: credential material is empty")
)

// Material is plaintext credential material supplied by a caller. The zero
// value of each field means "not set".
type Material struct {
	Password   secret.Secret
	PrivateKey secret.Secret
	Passphrase secret.Secret
}

// Empty reports whether no material is set.
func (m Material) Empty() bool {
	return !m.Password.IsSet() && !m.PrivateKey.IsSet() && !m.Passphrase.IsSet()
}

// Store persists and unwraps credentials.
type Store struct {
	q   repos.Queries
	enc *crypto.Encryptor
}

// New builds a credential store over the query surface and encryptor.
func New(q repos.Queries, enc *crypto.Encryptor) *Store {
	return &Store{q: q, enc: enc}
}

// payload is the JSON shape sealed into the ciphertext. Empty fields are
// omitted so a password-only credential carries no key placeholder.
type payload struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// Put stores the first credential for a server.
func (s *Store) Put(ctx context.Context, serverID domain.ServerID, kind domain.AuthMethod, m Material) (domain.CredentialID, error) {
	blob, err := s.seal(m)
	if err != nil {
		return 0, err
	}
	c, err := s.q.CreateCredential(ctx, repos.CreateCredentialParams{
		ServerID: serverID, Kind: kind, Ciphertext: blob, Version: 1,
	})
	if err != nil {
		return 0, fmt.Errorf("credentials: store: %w", err)
	}
	return c.ID, nil
}

// Rotate stores a new credential version, invalidating pooled connections
// keyed to the old version.
func (s *Store) Rotate(ctx context.Context, serverID domain.ServerID, kind domain.AuthMethod, m Material) (domain.CredentialID, error) {
	blob, err := s.seal(m)
	if err != nil {
		return 0, err
	}
	c, err := s.q.RotateCredential(ctx, repos.CreateCredentialParams{
		ServerID: serverID, Kind: kind, Ciphertext: blob,
	})
	if err != nil {
		return 0, fmt.Errorf("credentials: rotate: %w", err)
	}
	return c.ID, nil
}

// Delete removes every credential for a server.
func (s *Store) Delete(ctx context.Context, serverID domain.ServerID) error {
	if err := s.q.DeleteServerCredentials(ctx, serverID); err != nil {
		return fmt.Errorf("credentials: delete: %w", err)
	}
	return nil
}

// Unwrapped is decrypted credential material. Close zeroes it.
type Unwrapped struct {
	password   secret.Secret
	privateKey secret.Secret
	passphrase secret.Secret
	Version    int64
}

// Password returns the password, if any.
func (u *Unwrapped) Password() secret.Secret { return u.password }

// PrivateKey returns the private key, if any.
func (u *Unwrapped) PrivateKey() secret.Secret { return u.privateKey }

// Passphrase returns the key passphrase, if any.
func (u *Unwrapped) Passphrase() secret.Secret { return u.passphrase }

// Close zeroes the material. It is safe to call more than once.
func (u *Unwrapped) Close() {
	if u == nil {
		return
	}
	u.password.Clear()
	u.privateKey.Clear()
	u.passphrase.Clear()
}

// Unwrap decrypts the server's current credential. The caller must Close the
// result.
func (s *Store) Unwrap(ctx context.Context, serverID domain.ServerID) (*Unwrapped, error) {
	c, err := s.q.GetCredential(ctx, serverID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoCredential
	}
	if err != nil {
		return nil, fmt.Errorf("credentials: load: %w", err)
	}
	plaintext, err := s.enc.Decrypt(c.Ciphertext)
	if err != nil {
		return nil, ErrDecrypt
	}
	var p payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, ErrDecrypt
	}
	return &Unwrapped{
		password:   secret.New(p.Password),
		privateKey: secret.New(p.PrivateKey),
		passphrase: secret.New(p.Passphrase),
		Version:    c.Version,
	}, nil
}

func (s *Store) seal(m Material) ([]byte, error) {
	if m.Empty() {
		return nil, ErrEmpty
	}
	raw, err := json.Marshal(payload{
		Password:   m.Password.Reveal(),
		PrivateKey: m.PrivateKey.Reveal(),
		Passphrase: m.Passphrase.Reveal(),
	})
	if err != nil {
		return nil, fmt.Errorf("credentials: encode: %w", err)
	}
	blob, err := s.enc.Encrypt(raw)
	if err != nil {
		return nil, fmt.Errorf("credentials: encrypt: %w", err)
	}
	return blob, nil
}
