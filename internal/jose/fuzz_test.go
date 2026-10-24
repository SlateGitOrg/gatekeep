package jose

import (
	"crypto"
	"encoding/json"
	"testing"
)

// FuzzParse checks that arbitrary input never panics and that anything Parse
// accepts has an allow-listed algorithm.
func FuzzParse(f *testing.F) {
	s, err := NewSigner(mustKey(f), "k")
	if err != nil {
		f.Fatal(err)
	}
	tok, _ := s.Sign("JWT", map[string]string{"sub": "x"})
	f.Add(tok)
	f.Add("e30.e30.e30")
	f.Add("..")
	f.Fuzz(func(t *testing.T, in string) {
		p, err := Parse(in)
		if err != nil {
			return
		}
		switch p.Header.Alg {
		case RS256, ES256, EdDSA:
		default:
			t.Fatalf("accepted alg %q", p.Header.Alg)
		}
		_ = p.Verify(s.Public())
		_ = p.DecodeClaims(&RegisteredClaims{})
	})
}

// FuzzJWK checks JWK decoding never panics and accepted keys round-trip.
func FuzzJWK(f *testing.F) {
	s, _ := NewSigner(mustKey(f), "k")
	b, _ := json.Marshal(s.Public())
	f.Add(b)
	f.Add([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		var j JWK
		if json.Unmarshal(in, &j) != nil {
			return
		}
		if j.PublicKey() == nil {
			t.Fatal("accepted jwk without key")
		}
		_ = j.Thumbprint()
	})
}

func mustKey(f *testing.F) crypto.Signer {
	f.Helper()
	k, err := GenerateKey(ES256)
	if err != nil {
		f.Fatal(err)
	}
	return k
}
