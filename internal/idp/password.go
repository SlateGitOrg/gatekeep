package idp

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DefaultPBKDF2Iterations follows OWASP's 2023 guidance for PBKDF2-SHA256.
const DefaultPBKDF2Iterations = 600_000

// HashPassword returns "pbkdf2-sha256$<iter>$<salt>$<hash>".
func HashPassword(password string, iterations int) (string, error) {
	if iterations <= 0 {
		iterations = DefaultPBKDF2Iterations
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("idp: salt: %w", err)
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", fmt.Errorf("idp: pbkdf2: %w", err)
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iterations, enc.EncodeToString(salt), enc.EncodeToString(dk)), nil
}

// ErrBadHash is returned for an unparseable password hash.
var ErrBadHash = errors.New("idp: malformed password hash")

// CheckPassword verifies password against an encoded hash in constant time.
func CheckPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false, ErrBadHash
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 10_000_000 {
		return false, ErrBadHash
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false, ErrBadHash
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false, fmt.Errorf("idp: pbkdf2: %w", err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// hashIterations returns the iteration count encoded in a hash.
func hashIterations(encoded string) (int, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return 0, false
	}
	n, err := strconv.Atoi(parts[1])
	return n, err == nil && n > 0
}
