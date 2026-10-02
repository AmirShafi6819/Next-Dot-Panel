// Package auth implements the local authentication and session model from
// Design Spec sections 11 and 13: Argon2id password storage, opaque
// server-side sessions with immediate revocation, the bootstrap administrator,
// re-authentication, and the audit/login-history records those actions write.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are Argon2id cost parameters. The PHC encoding carries its own
// parameters, so the policy can be raised later without invalidating existing
// hashes.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams is the OWASP-aligned baseline from Design Spec section 11.1.
var DefaultParams = Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

const argon2idVersion = 19

var phcEncoding = base64.RawStdEncoding

// Hash derives a PHC-encoded Argon2id hash with the default parameters.
func Hash(password string) (string, error) {
	return HashWith(password, DefaultParams)
}

// HashWith derives a PHC-encoded Argon2id hash with explicit parameters.
func HashWith(password string, p Params) (string, error) {
	if password == "" {
		return "", errors.New("auth: refusing to hash an empty password")
	}
	if p.SaltLength == 0 || p.KeyLength == 0 || p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return "", errors.New("auth: incomplete argon2id parameters")
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}
	sum := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2idVersion, p.Memory, p.Iterations, p.Parallelism,
		phcEncoding.EncodeToString(salt), phcEncoding.EncodeToString(sum)), nil
}

// VerifyResult reports the outcome of a password check.
type VerifyResult struct {
	// Valid is true when the password matches the stored hash.
	Valid bool
	// NeedsRehash is true when the password matched but the stored hash uses
	// parameters below the current policy, so the caller should upgrade it.
	NeedsRehash bool
}

// Verify checks a password against a PHC-encoded Argon2id hash. The comparison
// is constant-time. A malformed hash is an error, never a silent success.
func Verify(password, encoded string) (VerifyResult, error) {
	p, salt, want, err := decodePHC(encoded)
	if err != nil {
		return VerifyResult{}, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(want)))
	valid := subtle.ConstantTimeCompare(got, want) == 1
	needs := p.Memory < DefaultParams.Memory ||
		p.Iterations < DefaultParams.Iterations ||
		p.Parallelism < DefaultParams.Parallelism
	return VerifyResult{Valid: valid, NeedsRehash: valid && needs}, nil
}

// decodePHC parses $argon2id$v=19$m=…,t=…,p=…$<salt>$<hash>.
func decodePHC(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, errors.New("auth: malformed password hash")
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != argon2idVersion {
		return Params{}, nil, nil, errors.New("auth: unsupported password hash version")
	}

	var p Params
	for _, field := range strings.Split(parts[3], ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return Params{}, nil, nil, errors.New("auth: malformed password hash parameters")
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return Params{}, nil, nil, errors.New("auth: malformed password hash parameters")
		}
		switch key {
		case "m":
			p.Memory = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			p.Parallelism = uint8(n)
		default:
			return Params{}, nil, nil, errors.New("auth: unknown password hash parameter")
		}
	}
	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return Params{}, nil, nil, errors.New("auth: incomplete password hash parameters")
	}

	salt, err := phcEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return Params{}, nil, nil, errors.New("auth: malformed password salt")
	}
	sum, err := phcEncoding.DecodeString(parts[5])
	if err != nil || len(sum) == 0 {
		return Params{}, nil, nil, errors.New("auth: malformed password hash")
	}
	return p, salt, sum, nil
}
