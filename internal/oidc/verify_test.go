package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/jose"
)

type staticKeys struct{ set jose.JWKSet }

func (s staticKeys) Key(_ context.Context, kid string, alg jose.Algorithm) (jose.JWK, error) {
	if k, ok := s.set.Lookup(kid); ok && k.Algorithm() == alg {
		return k, nil
	}
	return jose.JWK{}, ErrUnknownKey
}

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func signer(t *testing.T, alg jose.Algorithm, kid string) *jose.Signer {
	t.Helper()
	k, err := jose.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(k, kid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func goodClaims() IDTokenClaims {
	return IDTokenClaims{
		RegisteredClaims: jose.RegisteredClaims{
			Issuer: "https://idp.test", Subject: "u1", Audience: jose.Audience{"gatekeep"},
			IssuedAt: jose.NewNumericDate(now.Add(-10 * time.Second)), Expiry: jose.NewNumericDate(now.Add(5 * time.Minute)),
		},
		Nonce: "n-123", AuthTime: jose.NewNumericDate(now.Add(-time.Minute)), Email: "a@example.test",
	}
}

func TestVerifier(t *testing.T) {
	es := signer(t, jose.ES256, "es")
	rs := signer(t, jose.RS256, "rs")
	ed := signer(t, jose.EdDSA, "ed")
	other := signer(t, jose.ES256, "es") // same kid, different key
	keys := staticKeys{jose.JWKSet{Keys: []jose.JWK{es.Public(), rs.Public(), ed.Public()}}}
	v := &Verifier{Issuer: "https://idp.test", ClientID: "gatekeep", Keys: keys, Leeway: 5 * time.Second,
		MaxTokenAge: 10 * time.Minute, MaxAuthAge: time.Hour, Now: func() time.Time { return now }}

	tok := func(s *jose.Signer, mut func(*IDTokenClaims)) string {
		c := goodClaims()
		if mut != nil {
			mut(&c)
		}
		out, err := s.Sign("JWT", c)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, s := range []*jose.Signer{es, rs} {
		c, err := v.Verify(context.Background(), tok(s, nil), "n-123")
		if err != nil || c.Subject != "u1" || c.Email != "a@example.test" {
			t.Fatalf("%s: %v", s.KeyID(), err)
		}
	}
	cases := []struct {
		name   string
		token  string
		nonce  string
		reason string
	}{
		{"expired", tok(es, func(c *IDTokenClaims) { c.Expiry = jose.NewNumericDate(now.Add(-time.Minute)) }), "n-123", "token_expired"},
		{"too old", tok(es, func(c *IDTokenClaims) { c.IssuedAt = jose.NewNumericDate(now.Add(-time.Hour)) }), "n-123", "token_expired"},
		{"wrong aud", tok(es, func(c *IDTokenClaims) { c.Audience = jose.Audience{"someone-else"} }), "n-123", "wrong_audience"},
		{"wrong iss", tok(es, func(c *IDTokenClaims) { c.Issuer = "https://evil.test" }), "n-123", "wrong_issuer"},
		{"nonce", tok(es, nil), "other-nonce", "nonce_mismatch"},
		{"empty expected nonce", tok(es, func(c *IDTokenClaims) { c.Nonce = "" }), "", "nonce_mismatch"},
		{"multi aud no azp", tok(es, func(c *IDTokenClaims) { c.Audience = jose.Audience{"gatekeep", "x"} }), "n-123", "wrong_azp"},
		{"foreign azp", tok(es, func(c *IDTokenClaims) { c.AZP = "x" }), "n-123", "wrong_azp"},
		{"no sub", tok(es, func(c *IDTokenClaims) { c.Subject = "" }), "n-123", "missing_claim"},
		{"no iat", tok(es, func(c *IDTokenClaims) { c.IssuedAt = nil }), "n-123", "missing_claim"},
		{"future iat", tok(es, func(c *IDTokenClaims) { c.IssuedAt = jose.NewNumericDate(now.Add(time.Hour)) }), "n-123", "token_not_yet_valid"},
		{"auth too old", tok(es, func(c *IDTokenClaims) { c.AuthTime = jose.NewNumericDate(now.Add(-2 * time.Hour)) }), "n-123", "auth_too_old"},
		{"no auth_time", tok(es, func(c *IDTokenClaims) { c.AuthTime = nil }), "n-123", "missing_claim"},
		{"eddsa not pinned", tok(ed, nil), "n-123", "bad_algorithm"},
		{"forged key same kid", tok(other, nil), "n-123", "bad_signature"},
		{"unknown kid", tok(signer(t, jose.ES256, "zz"), nil), "n-123", "unknown_key"},
		{"garbage", "a.b.c", "n-123", "malformed_token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), c.token, c.nonce)
			if err == nil {
				t.Fatal("accepted")
			}
			if got := Reason(err); got != c.reason {
				t.Fatalf("reason %q (%v), want %q", got, err, c.reason)
			}
		})
	}
	// azp equal to client id with multiple audiences is fine.
	if _, err := v.Verify(context.Background(), tok(es, func(c *IDTokenClaims) {
		c.Audience = jose.Audience{"gatekeep", "x"}
		c.AZP = "gatekeep"
	}), "n-123"); err != nil {
		t.Fatal(err)
	}
}

func TestReasonFallbacks(t *testing.T) {
	if Reason(nil) != "" || Reason(errors.New("x")) != "verification_error" {
		t.Fatal("fallbacks")
	}
}

func TestPKCE(t *testing.T) {
	// RFC 7636 Appendix B.
	if got := CodeChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %s", got)
	}
	v, err := NewCodeVerifier()
	if err != nil || !ValidVerifier(v) {
		t.Fatalf("verifier %q %v", v, err)
	}
	for _, bad := range []string{"short", string(make([]byte, 129)), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+"} {
		if ValidVerifier(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	s1, _ := NewState()
	s2, _ := NewNonce()
	if s1 == s2 || len(s1) != 32 {
		t.Fatal("random tokens")
	}
}

func TestCacheTTL(t *testing.T) {
	cases := map[string]time.Duration{
		"":                    DefaultKeyTTL,
		"public, max-age=300": 5 * time.Minute,
		"max-age=1":           MinKeyTTL,
		"max-age=99999999":    MaxKeyTTL,
		"no-store":            MinKeyTTL,
		"max-age=abc":         DefaultKeyTTL,
	}
	for h, want := range cases {
		if got := cacheTTL(h); got != want {
			t.Errorf("%q: %v want %v", h, got, want)
		}
	}
}
