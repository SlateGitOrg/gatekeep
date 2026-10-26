package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/jose"
)

// Validation errors. Each maps to a stable audit reason via Reason.
var (
	ErrNonce        = errors.New("oidc: nonce mismatch")
	ErrAZP          = errors.New("oidc: authorized party mismatch")
	ErrNoSubject    = errors.New("oidc: missing subject")
	ErrAuthTooOld   = errors.New("oidc: authentication too old")
	ErrAlgNotPinned = errors.New("oidc: algorithm not accepted for id tokens")
)

// IDTokenClaims are the ID-token claims gatekeep consumes.
type IDTokenClaims struct {
	jose.RegisteredClaims
	Nonce         string            `json:"nonce,omitempty"`
	AuthTime      *jose.NumericDate `json:"auth_time,omitempty"`
	AZP           string            `json:"azp,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified bool              `json:"email_verified,omitempty"`
	Name          string            `json:"name,omitempty"`
	Groups        []string          `json:"groups,omitempty"`
}

// KeySource resolves verification keys (implemented by RemoteKeySet).
type KeySource interface {
	Key(ctx context.Context, kid string, alg jose.Algorithm) (jose.JWK, error)
}

// Verifier validates ID tokens per OIDC Core §3.1.3.7.
type Verifier struct {
	Issuer   string
	ClientID string
	Keys     KeySource
	// Algorithms accepted for ID tokens. EdDSA is intentionally not in the
	// default set: OIDC providers sign with RS256/ES256.
	Algorithms []jose.Algorithm
	Leeway     time.Duration
	// MaxAuthAge, when > 0, rejects tokens whose auth_time is older.
	MaxAuthAge time.Duration
	// MaxTokenAge bounds now-iat so a captured token cannot be redeemed long
	// after issuance even if its exp is generous.
	MaxTokenAge time.Duration
	Now         func() time.Time
}

// Verify parses rawToken, checks its signature and claims, and requires its
// nonce to equal expectedNonce.
func (v *Verifier) Verify(ctx context.Context, rawToken, expectedNonce string) (*IDTokenClaims, error) {
	p, err := jose.Parse(rawToken)
	if err != nil {
		return nil, err
	}
	algs := v.Algorithms
	if len(algs) == 0 {
		algs = []jose.Algorithm{jose.RS256, jose.ES256}
	}
	if !slices.Contains(algs, p.Header.Alg) {
		return nil, fmt.Errorf("%w: %s", ErrAlgNotPinned, p.Header.Alg)
	}
	key, err := v.Keys.Key(ctx, p.Header.Kid, p.Header.Alg)
	if err != nil {
		return nil, err
	}
	if err := p.Verify(key); err != nil {
		return nil, err
	}
	var c IDTokenClaims
	if err := p.DecodeClaims(&c); err != nil {
		return nil, err
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if c.IssuedAt == nil {
		return nil, fmt.Errorf("%w: iat", jose.ErrMissingClaim)
	}
	if err := c.Validate(jose.Expectations{
		Issuer: v.Issuer, Audience: v.ClientID, Now: now, Leeway: v.Leeway, MaxAge: v.MaxTokenAge,
	}); err != nil {
		return nil, err
	}
	// §3.1.3.7 (4)/(5): with multiple audiences azp must be present; if
	// present it must be our client id.
	if (len(c.Audience) > 1 && c.AZP == "") || (c.AZP != "" && c.AZP != v.ClientID) {
		return nil, ErrAZP
	}
	if c.Subject == "" {
		return nil, ErrNoSubject
	}
	if expectedNonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(expectedNonce)) != 1 {
		return nil, ErrNonce
	}
	if v.MaxAuthAge > 0 {
		if c.AuthTime == nil {
			return nil, fmt.Errorf("%w: auth_time", jose.ErrMissingClaim)
		}
		if now.Sub(c.AuthTime.Time()) > v.MaxAuthAge+v.Leeway {
			return nil, ErrAuthTooOld
		}
	}
	return &c, nil
}

// Reason maps a validation error to a short, stable audit reason code.
func Reason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, jose.ErrExpired):
		return "token_expired"
	case errors.Is(err, jose.ErrNotYetValid), errors.Is(err, jose.ErrIssuedFuture):
		return "token_not_yet_valid"
	case errors.Is(err, jose.ErrAudience):
		return "wrong_audience"
	case errors.Is(err, jose.ErrIssuer):
		return "wrong_issuer"
	case errors.Is(err, ErrAZP):
		return "wrong_azp"
	case errors.Is(err, ErrNonce):
		return "nonce_mismatch"
	case errors.Is(err, jose.ErrSignature), errors.Is(err, jose.ErrKeyMismatch):
		return "bad_signature"
	case errors.Is(err, ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, jose.ErrAlgorithm), errors.Is(err, ErrAlgNotPinned):
		return "bad_algorithm"
	case errors.Is(err, jose.ErrMissingClaim), errors.Is(err, ErrNoSubject):
		return "missing_claim"
	case errors.Is(err, ErrAuthTooOld):
		return "auth_too_old"
	case errors.Is(err, jose.ErrMalformed), errors.Is(err, jose.ErrCritical), errors.Is(err, jose.ErrTokenTooLong):
		return "malformed_token"
	}
	return "verification_error"
}
