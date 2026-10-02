package auth

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	hash, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("unexpected PHC prefix: %q", hash)
	}
	res, err := Verify("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Fatal("correct password did not verify")
	}
	if res.NeedsRehash {
		t.Fatal("default-parameter hash should not need a rehash")
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := Hash("correct horse battery staple")
	b, _ := Hash("correct horse battery staple")
	if a == b {
		t.Fatal("two hashes of the same password are identical; salt is not random")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	hash, _ := Hash("correct horse battery staple")
	res, err := Verify("wrong horse battery staple", hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Fatal("wrong password verified")
	}
}

func TestVerifyMalformedHash(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$m=65536,t=3,p=2$onlyfourparts",
		"$argon2id$v=99$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"$argon2i$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if _, err := Verify("whatever", bad); err == nil {
			t.Fatalf("Verify(%q) succeeded, want error", bad)
		}
	}
}

func TestVerifyDetectsNeedsRehash(t *testing.T) {
	weak := Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	hash, err := HashWith("correct horse battery staple", weak)
	if err != nil {
		t.Fatalf("HashWith: %v", err)
	}
	res, err := Verify("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid || !res.NeedsRehash {
		t.Fatalf("weak hash result = %+v, want valid+needs-rehash", res)
	}
}

func TestHashRejectsEmptyPassword(t *testing.T) {
	if _, err := Hash(""); err == nil {
		t.Fatal("Hash(\"\") succeeded, want error")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("short"); err != ErrPasswordTooShort {
		t.Fatalf("short password err = %v, want ErrPasswordTooShort", err)
	}
	if err := ValidatePassword("password1234"); err != ErrPasswordTooCommon {
		t.Fatalf("common password err = %v, want ErrPasswordTooCommon", err)
	}
	if err := ValidatePassword("Correct-Horse-Battery-9"); err != nil {
		t.Fatalf("strong password rejected: %v", err)
	}
	// Exactly the minimum length is accepted.
	if err := ValidatePassword("abcdefghijkl"); err != nil {
		t.Fatalf("minimum-length password rejected: %v", err)
	}
}
