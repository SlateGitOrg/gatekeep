package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustSigner(t *testing.T, alg Algorithm, kid string) *Signer {
	t.Helper()
	k, err := GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(k, kid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{RS256, ES256, EdDSA} {
		t.Run(string(alg), func(t *testing.T) {
			s := mustSigner(t, alg, "k1")
			tok, err := s.Sign("JWT", map[string]any{"sub": "alice", "n": 1})
			if err != nil {
				t.Fatal(err)
			}
			p, err := Parse(tok)
			if err != nil {
				t.Fatal(err)
			}
			if p.Header.Alg != alg || p.Header.Kid != "k1" || p.Header.Typ != "JWT" {
				t.Fatalf("header = %+v", p.Header)
			}
			if err := p.Verify(s.Public()); err != nil {
				t.Fatalf("verify: %v", err)
			}
			var c struct{ Sub string }
			if err := p.DecodeClaims(&c); err != nil || c.Sub != "alice" {
				t.Fatalf("claims %+v %v", c, err)
			}
			// JWK JSON round trip keeps the key usable.
			b, err := json.Marshal(s.Public())
			if err != nil {
				t.Fatal(err)
			}
			var back JWK
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatal(err)
			}
			if err := p.Verify(back); err != nil {
				t.Fatalf("verify with decoded jwk: %v", err)
			}
			if back.Thumbprint() != s.Public().Thumbprint() {
				t.Fatal("thumbprint changed across serialisation")
			}
		})
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	for _, alg := range []Algorithm{RS256, ES256, EdDSA} {
		s := mustSigner(t, alg, "k")
		tok, _ := s.Sign("JWT", map[string]string{"sub": "alice"})
		parts := strings.Split(tok, ".")
		parts[1] = b64([]byte(`{"sub":"mallory"}`))
		p, err := Parse(strings.Join(parts, "."))
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Verify(s.Public()); !errors.Is(err, ErrSignature) {
			t.Fatalf("%s: want ErrSignature, got %v", alg, err)
		}
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, b := mustSigner(t, ES256, "a"), mustSigner(t, ES256, "b")
	tok, _ := a.Sign("JWT", map[string]string{})
	p, _ := Parse(tok)
	if err := p.Verify(b.Public()); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

func TestAlgorithmConfusionRejected(t *testing.T) {
	// A token claiming EdDSA must not verify against an RSA key and vice versa.
	ed := mustSigner(t, EdDSA, "k")
	rs := mustSigner(t, RS256, "k")
	tok, _ := ed.Sign("JWT", map[string]string{})
	p, _ := Parse(tok)
	if err := p.Verify(rs.Public()); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("want ErrKeyMismatch, got %v", err)
	}
	if _, err := rs.SignRaw(Header{Alg: EdDSA}, []byte("{}")); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("SignRaw with wrong alg: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	cases := map[string]struct {
		tok  string
		want error
	}{
		"none alg":     {enc(`{"alg":"none"}`) + "." + enc(`{}`) + ".", ErrAlgorithm},
		"HS256":        {enc(`{"alg":"HS256"}`) + "." + enc(`{}`) + "." + enc("x"), ErrAlgorithm},
		"two parts":    {"a.b", ErrMalformed},
		"bad b64":      {"!!.e30.e30", ErrMalformed},
		"padded b64":   {enc(`{"alg":"ES256"}`) + "==." + enc(`{}`) + "." + enc("x"), ErrMalformed},
		"crit":         {enc(`{"alg":"ES256","crit":["exp"]}`) + "." + enc(`{}`) + "." + enc("x"), ErrCritical},
		"header array": {enc(`[]`) + "." + enc(`{}`) + "." + enc("x"), ErrMalformed},
		"too long":     {strings.Repeat("a", MaxTokenSize+1), ErrTokenTooLong},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(c.tok); !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func TestES256BadSignatureLength(t *testing.T) {
	s := mustSigner(t, ES256, "k")
	tok, _ := s.Sign("JWT", map[string]string{})
	parts := strings.Split(tok, ".")
	parts[2] = b64(make([]byte, 63))
	p, _ := Parse(strings.Join(parts, "."))
	if err := p.Verify(s.Public()); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestDecodeClaimsTrailingData(t *testing.T) {
	s := mustSigner(t, EdDSA, "k")
	tok, _ := s.SignRaw(Header{Alg: EdDSA}, []byte(`{"a":1} {"b":2}`))
	p, _ := Parse(tok)
	if err := p.DecodeClaims(&map[string]any{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
}

func TestJWKValidation(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewJWK(&small.PublicKey, "x"); err == nil {
		t.Fatal("1024-bit RSA accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewJWK(&p384.PublicKey, "x"); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("P-384 accepted: %v", err)
	}
	bad := []string{
		`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}`,
		`{"kty":"EC","crv":"P-256","x":"` + b64(make([]byte, 32)) + `","y":"` + b64(make([]byte, 32)) + `"}`, // not on curve
		`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		`{"kty":"RSA","n":"AQAB","e":"AQAB"}`,
		`{"kty":"OKP","crv":"Ed25519","alg":"RS256","x":"` + b64(make([]byte, 32)) + `"}`,
		`{"kty":"EC","crv":"P-521","x":"AA","y":"AA"}`,
	}
	for _, j := range bad {
		var k JWK
		if err := json.Unmarshal([]byte(j), &k); err == nil {
			t.Errorf("accepted bad jwk %s", j)
		}
	}
}

func TestParseJWKSet(t *testing.T) {
	a := mustSigner(t, ES256, "a")
	b := mustSigner(t, RS256, "b")
	ka, _ := json.Marshal(a.Public())
	kb, _ := json.Marshal(b.Public())
	doc := `{"keys":[` + string(ka) + `,` + string(kb) +
		`,{"kty":"oct","k":"c2VjcmV0"},{"kty":"EC","crv":"P-256","use":"enc","x":"` +
		a.Public().X + `","y":"` + a.Public().Y + `","kid":"enc"}]}`
	set, err := ParseJWKSet([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("want 2 signing keys, got %d", len(set.Keys))
	}
	if _, ok := set.Lookup("b"); !ok {
		t.Fatal("lookup b")
	}
	if _, ok := set.Lookup("enc"); ok {
		t.Fatal("encryption key must be skipped")
	}
	if _, err := ParseJWKSet([]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"zz"}]}`)); err == nil {
		t.Fatal("malformed supported key accepted")
	}
	if _, err := ParseJWKSet([]byte(`nope`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

// kb2 returns the n and e members of an RSA signer's public JWK, formatted
// to be spliced into a JSON object after `"n":"`.
func kb2(t *testing.T, s *Signer) string {
	t.Helper()
	pub := s.Public()
	return pub.N + `","e":"` + pub.E + `"}`
}

// A realistic IdP JWKS (Keycloak publishes an RSA-OAEP encryption key next to
// its RS256 signing key) must not lose the signing key because of keys
// gatekeep does not use.
func TestParseJWKSetSkipsForeignKeys(t *testing.T) {
	sig := mustSigner(t, RS256, "sig")
	ks, _ := json.Marshal(sig.Public())
	rsaMembers := kb2(t, sig)
	doc := `{"keys":[` + string(ks) +
		`,{"kid":"enc","kty":"RSA","use":"enc","alg":"RSA-OAEP","n":"` + rsaMembers +
		`,{"kid":"enc-junk","kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"AA","e":"AA"}` +
		`,{"kid":"ps","kty":"RSA","use":"sig","alg":"PS256","n":"` + rsaMembers +
		`,{"kid":"rs384","kty":"RSA","alg":"RS384","n":"` + rsaMembers +
		`,{"kid":"es384","kty":"EC","crv":"P-256","alg":"ES384","x":"AA","y":"AA"}` +
		`,{"kid":"confused","kty":"RSA","alg":"ES256","n":"` + rsaMembers +
		`]}`
	set, err := ParseJWKSet([]byte(doc))
	if err != nil {
		t.Fatalf("whole set rejected: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want only the RS256 signing key, got %d keys", len(set.Keys))
	}
	if _, ok := set.Lookup("sig"); !ok {
		t.Fatal("signing key lost")
	}
	// The standalone decoder still refuses a mismatched key, as unsupported.
	var k JWK
	err = json.Unmarshal([]byte(`{"kty":"RSA","alg":"PS256","n":"`+rsaMembers), &k)
	if !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("PS256 jwk: %v", err)
	}
}

func TestPEMRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{RS256, ES256, EdDSA} {
		k, _ := GenerateKey(alg)
		b, err := MarshalPrivateKeyPEM(k)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParsePrivateKeyPEM(b)
		if err != nil {
			t.Fatal(err)
		}
		pb, err := MarshalPublicKeyPEM(back.Public())
		if err != nil {
			t.Fatal(err)
		}
		j, err := ParsePublicKeyPEM(pb, "kid")
		if err != nil || j.Algorithm() != alg {
			t.Fatalf("%s: %v %v", alg, j.Algorithm(), err)
		}
	}
	if _, err := ParsePrivateKeyPEM([]byte("junk")); err == nil {
		t.Fatal("junk private key accepted")
	}
	if _, err := ParsePublicKeyPEM([]byte("junk"), "k"); err == nil {
		t.Fatal("junk public key accepted")
	}
	if _, err := GenerateKey("HS256"); !errors.Is(err, ErrAlgorithm) {
		t.Fatal("HS256 key generated")
	}
}

func TestClaimsValidate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := func() RegisteredClaims {
		return RegisteredClaims{
			Issuer: "https://idp", Audience: Audience{"app", "other"},
			IssuedAt: NewNumericDate(now.Add(-time.Minute)), Expiry: NewNumericDate(now.Add(time.Minute)),
		}
	}
	exp := Expectations{Issuer: "https://idp", Audience: "app", Now: now, Leeway: 5 * time.Second}
	if err := base().Validate(exp); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}
	cases := map[string]struct {
		mut  func(*RegisteredClaims)
		e    func(*Expectations)
		want error
	}{
		"expired":        {func(c *RegisteredClaims) { c.Expiry = NewNumericDate(now.Add(-6 * time.Second)) }, nil, ErrExpired},
		"no exp":         {func(c *RegisteredClaims) { c.Expiry = nil }, nil, ErrMissingClaim},
		"issuer":         {func(c *RegisteredClaims) { c.Issuer = "https://evil" }, nil, ErrIssuer},
		"audience":       {func(c *RegisteredClaims) { c.Audience = Audience{"other"} }, nil, ErrAudience},
		"nbf":            {func(c *RegisteredClaims) { c.NotBefore = NewNumericDate(now.Add(time.Minute)) }, nil, ErrNotYetValid},
		"iat future":     {func(c *RegisteredClaims) { c.IssuedAt = NewNumericDate(now.Add(time.Minute)) }, nil, ErrIssuedFuture},
		"max age":        {nil, func(e *Expectations) { e.MaxAge = 30 * time.Second }, ErrExpired},
		"max age no iat": {func(c *RegisteredClaims) { c.IssuedAt = nil }, func(e *Expectations) { e.MaxAge = time.Hour }, ErrMissingClaim},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cl, ex := base(), exp
			if c.mut != nil {
				c.mut(&cl)
			}
			if c.e != nil {
				c.e(&ex)
			}
			if err := cl.Validate(ex); !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
	// Leeway tolerates small skew.
	cl := base()
	cl.Expiry = NewNumericDate(now.Add(-3 * time.Second))
	if err := cl.Validate(exp); err != nil {
		t.Fatalf("leeway not applied: %v", err)
	}
}

func TestAudienceAndNumericDateJSON(t *testing.T) {
	var c RegisteredClaims
	if err := json.Unmarshal([]byte(`{"aud":"one","exp":1700000000.9}`), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "one" || int64(*c.Expiry) != 1700000000 {
		t.Fatalf("%+v", c)
	}
	if err := json.Unmarshal([]byte(`{"aud":["a","b"]}`), &c); err != nil || len(c.Audience) != 2 {
		t.Fatalf("%v %v", c.Audience, err)
	}
	for _, bad := range []string{`{"aud":5}`, `{"exp":-1}`, `{"exp":"x"}`, `{"exp":1e30}`} {
		if err := json.Unmarshal([]byte(bad), &RegisteredClaims{}); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	b, _ := json.Marshal(Audience{"x"})
	if string(b) != `"x"` {
		t.Fatalf("single aud marshals as %s", b)
	}
	b, _ = json.Marshal(Audience{"x", "y"})
	if string(b) != `["x","y"]` {
		t.Fatalf("multi aud marshals as %s", b)
	}
}
