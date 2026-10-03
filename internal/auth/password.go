// Package auth contains password hashing and opaque session primitives.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory  = 19 * 1024 // KiB: 19 MiB, t=2, p=1.
	argonTime    = 2
	argonThreads = 1
	saltLength   = 16
	keyLength    = 32
)

var ErrPasswordHash = errors.New("unsupported or malformed password hash")

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(password, encoded string) (bool, error) {
	// Only the supported, bounded profile is accepted. Database corruption must
	// never control Argon2's memory allocation, iterations or parallelism.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=19456,t=2,p=1" {
		return false, ErrPasswordHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != saltLength || base64.RawStdEncoding.EncodeToString(salt) != parts[4] {
		return false, ErrPasswordHash
	}
	expected, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expected) != keyLength || base64.RawStdEncoding.EncodeToString(expected) != parts[5] {
		return false, ErrPasswordHash
	}
	actual := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLength)
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}
