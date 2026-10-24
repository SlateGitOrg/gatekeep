// Package oidc is gatekeep's OpenID Connect relying party: discovery,
// authorization-code + PKCE (RFC 7636, S256 only), code exchange and strict
// ID-token validation against a rotating remote JWKS.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// NewCodeVerifier returns a 43-character PKCE code verifier (256 bits).
func NewCodeVerifier() (string, error) {
	return randomToken(32)
}

// CodeChallengeS256 derives the S256 code challenge for verifier.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidVerifier reports whether v satisfies RFC 7636 §4.1 syntax.
func ValidVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidc: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewState returns a random OAuth state value.
func NewState() (string, error) { return randomToken(24) }

// NewNonce returns a random OIDC nonce.
func NewNonce() (string, error) { return randomToken(24) }
