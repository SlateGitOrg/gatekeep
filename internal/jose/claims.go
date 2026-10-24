package jose

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"
)

// Errors returned by claim validation.
var (
	ErrExpired      = errors.New("jose: token expired")
	ErrNotYetValid  = errors.New("jose: token not yet valid")
	ErrIssuedFuture = errors.New("jose: token issued in the future")
	ErrMissingClaim = errors.New("jose: required claim missing")
	ErrIssuer       = errors.New("jose: issuer mismatch")
	ErrAudience     = errors.New("jose: audience mismatch")
)

// NumericDate is a JWT NumericDate (seconds since the epoch).
type NumericDate int64

// NewNumericDate converts a time to a NumericDate.
func NewNumericDate(t time.Time) *NumericDate {
	n := NumericDate(t.Unix())
	return &n
}

// Time converts back to time.Time.
func (n NumericDate) Time() time.Time { return time.Unix(int64(n), 0) }

// UnmarshalJSON accepts integer or fractional seconds; fractions are truncated.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("jose: NumericDate: %w", err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1<<40 {
		return errors.New("jose: NumericDate out of range")
	}
	*n = NumericDate(int64(f))
	return nil
}

// Audience is the "aud" claim, which may be a string or an array.
type Audience []string

// UnmarshalJSON accepts both representations defined by RFC 7519.
func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return fmt.Errorf("jose: aud: %w", err)
	}
	*a = l
	return nil
}

// MarshalJSON emits a single string when there is exactly one audience.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Contains reports whether aud is one of the audiences.
func (a Audience) Contains(aud string) bool { return slices.Contains(a, aud) }

// RegisteredClaims holds the RFC 7519 registered claims.
type RegisteredClaims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  Audience     `json:"aud,omitempty"`
	Expiry    *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
}

// Expectations are the checks applied by Validate.
type Expectations struct {
	Issuer   string        // required exact match when non-empty
	Audience string        // must be contained in aud when non-empty
	Now      time.Time     // evaluation time
	Leeway   time.Duration // tolerated clock skew
	// MaxAge, when > 0, requires iat and rejects tokens older than this.
	MaxAge time.Duration
}

// Validate applies issuer, audience and time checks. exp is always required.
func (c RegisteredClaims) Validate(e Expectations) error {
	if e.Issuer != "" && c.Issuer != e.Issuer {
		return fmt.Errorf("%w: got %q", ErrIssuer, c.Issuer)
	}
	if e.Audience != "" && !c.Audience.Contains(e.Audience) {
		return fmt.Errorf("%w: %v does not contain %q", ErrAudience, []string(c.Audience), e.Audience)
	}
	if c.Expiry == nil {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if !e.Now.Before(c.Expiry.Time().Add(e.Leeway)) {
		return ErrExpired
	}
	if c.NotBefore != nil && e.Now.Add(e.Leeway).Before(c.NotBefore.Time()) {
		return ErrNotYetValid
	}
	if c.IssuedAt != nil && e.Now.Add(e.Leeway).Before(c.IssuedAt.Time()) {
		return ErrIssuedFuture
	}
	if e.MaxAge > 0 {
		if c.IssuedAt == nil {
			return fmt.Errorf("%w: iat", ErrMissingClaim)
		}
		if e.Now.Sub(c.IssuedAt.Time()) > e.MaxAge+e.Leeway {
			return ErrExpired
		}
	}
	return nil
}
