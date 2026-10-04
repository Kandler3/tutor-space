package auth

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

func TestOpaqueSessionToken(t *testing.T) {
	first, hash, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != 43 {
		t.Fatal("invalid independent session token")
	}
	if hash != sha256.Sum256([]byte(first)) {
		t.Fatal("stored token hash differs")
	}
	if actual, valid := TokenHash(first); !valid || actual != hash {
		t.Fatal("generated token does not validate")
	}
	for _, token := range []string{"", "fake", first + "=", first[:42], strings.Repeat("!", 43)} {
		if _, valid := TokenHash(token); valid {
			t.Fatal("malformed token accepted")
		}
	}
	if SessionTTL != 24*time.Hour {
		t.Fatal("unexpected session lifetime")
	}
}

func TestGeneratedUserID(t *testing.T) {
	id, err := NewUserID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 || id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
		t.Fatal("not a UUIDv4")
	}
}
