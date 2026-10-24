package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// Errors for lifecycle checks.
var (
	ErrExpired = errors.New("session: expired")
	ErrIdle    = errors.New("session: idle timeout")
)

// Session is the identity state carried in the encrypted session cookie.
// It is deliberately small: only what policy evaluation and upstream headers
// need, never the raw ID token.
type Session struct {
	ID            string    `json:"sid"`
	Subject       string    `json:"sub"`
	Email         string    `json:"email,omitempty"`
	EmailVerified bool      `json:"ev,omitempty"`
	Name          string    `json:"name,omitempty"`
	Groups        []string  `json:"groups,omitempty"`
	Issuer        string    `json:"iss"`
	AuthTime      time.Time `json:"at"`
	IssuedAt      time.Time `json:"iat"`
	LastSeen      time.Time `json:"seen"`
	ExpiresAt     time.Time `json:"exp"`
}

// Lifetimes configures absolute and idle session timeouts.
type Lifetimes struct {
	Absolute time.Duration
	Idle     time.Duration
	// TouchInterval: LastSeen is refreshed (and the cookie re-issued) only
	// when it is older than this, to avoid a Set-Cookie on every request.
	TouchInterval time.Duration
}

// Check validates the session's lifetime at now.
func (s *Session) Check(now time.Time, l Lifetimes) error {
	if !now.Before(s.ExpiresAt) {
		return ErrExpired
	}
	if l.Idle > 0 && now.Sub(s.LastSeen) > l.Idle {
		return ErrIdle
	}
	return nil
}

// NeedsTouch reports whether LastSeen should be refreshed.
func (s *Session) NeedsTouch(now time.Time, l Lifetimes) bool {
	return l.Idle > 0 && now.Sub(s.LastSeen) >= l.TouchInterval
}

// LoginState is sealed into the short-lived login cookie between the
// redirect to the IdP and the callback. It carries the PKCE verifier, so it
// never leaves the browser in plaintext and is bound to this user agent.
type LoginState struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"cv"`
	ReturnTo     string    `json:"rt"`
	CreatedAt    time.Time `json:"ct"`
}

// RandomID returns a 256-bit URL-safe random identifier.
func RandomID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
