package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestPasswordHashRoundTripAndSalt(t *testing.T) {
	const password = "long-enough-test-password"
	first, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("independent passwords must use independent salts")
	}
	for _, candidate := range []struct {
		password string
		expected bool
	}{{password, true}, {"a-different-password", false}, {password + " ", false}} {
		valid, err := VerifyPassword(candidate.password, first)
		if err != nil || valid != candidate.expected {
			t.Fatalf("verification: got %v, error %v", valid, err)
		}
	}
}

func TestPasswordHashRejectsUntrustedParameters(t *testing.T) {
	encoded, err := HashPassword("long-enough-test-password")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(encoded, "$")
	malformed := []string{
		"", "$argon2id$", strings.Replace(encoded, "argon2id", "argon2i", 1),
		strings.Replace(encoded, "v=19", "v=16", 1),
		strings.Replace(encoded, "m=19456", "m=4294967295", 1),
		strings.Replace(encoded, "t=2", "t=0", 1),
		strings.Replace(encoded, "p=1", "p=0", 1),
		strings.Replace(encoded, parts[4], "a", 1),
		strings.Replace(encoded, parts[5], "!!!", 1),
		encoded + "$trailing",
	}
	for i, value := range malformed {
		if valid, err := VerifyPassword("long-enough-test-password", value); valid || !errors.Is(err, ErrPasswordHash) {
			t.Fatalf("malformed case %d was accepted", i)
		}
	}
}
