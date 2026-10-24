// Package jose implements the subset of JOSE (RFC 7515 JWS, RFC 7517 JWK,
// RFC 7519 JWT, RFC 7638 thumbprints, RFC 8037 OKP keys) that gatekeep needs:
// compact JWS signing and verification with RS256, ES256 and EdDSA.
//
// The package is deliberately strict: it has a closed algorithm allow-list,
// never accepts "none", binds every algorithm to exactly one key type (so
// algorithm-confusion attacks fail), rejects unknown critical headers and caps
// token size before decoding anything.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// MinRSABits is the smallest RSA modulus accepted for verification.
const MinRSABits = 2048

// JWK is a public JSON Web Key. Private key material is never serialised.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	key crypto.PublicKey
}

// ErrUnsupportedKey is returned for key types or curves gatekeep does not handle.
var ErrUnsupportedKey = errors.New("jose: unsupported key type")

// NewJWK wraps a public key as a JWK with the given key id.
func NewJWK(pub crypto.PublicKey, kid string) (JWK, error) {
	j := JWK{Kid: kid, Use: "sig"}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return JWK{}, fmt.Errorf("jose: RSA key too small (%d bits)", k.N.BitLen())
		}
		j.Kty, j.Alg = "RSA", string(RS256)
		j.N = b64(k.N.Bytes())
		j.E = b64(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return JWK{}, ErrUnsupportedKey
		}
		raw, err := k.Bytes()
		if err != nil {
			return JWK{}, fmt.Errorf("jose: encode EC key: %w", err)
		}
		j.Kty, j.Alg, j.Crv = "EC", string(ES256), "P-256"
		j.X = b64(raw[1:33])
		j.Y = b64(raw[33:65])
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return JWK{}, ErrUnsupportedKey
		}
		j.Kty, j.Alg, j.Crv = "OKP", string(EdDSA), "Ed25519"
		j.X = b64(k)
	default:
		return JWK{}, ErrUnsupportedKey
	}
	j.key = pub
	return j, nil
}

// PublicKey returns the parsed public key.
func (j JWK) PublicKey() crypto.PublicKey { return j.key }

// Algorithm returns the single JWS algorithm this key may be used with.
func (j JWK) Algorithm() Algorithm {
	switch j.Kty {
	case "RSA":
		return RS256
	case "EC":
		return ES256
	case "OKP":
		return EdDSA
	}
	return ""
}

// UnmarshalJSON parses and validates a JWK, rejecting malformed or weak keys.
func (j *JWK) UnmarshalJSON(b []byte) error {
	type plain JWK
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("jose: decode jwk: %w", err)
	}
	*j = JWK(p)
	// The alg check comes first and reports ErrUnsupportedKey: a key bound to
	// an algorithm gatekeep does not use with this kty (RSA-OAEP, PS256,
	// ES384, ...) is a key gatekeep cannot use, not a malformed one.
	if j.Alg != "" && Algorithm(j.Alg) != j.Algorithm() {
		return fmt.Errorf("%w: jwk alg %q with kty %q", ErrUnsupportedKey, j.Alg, j.Kty)
	}
	key, err := j.parse()
	if err != nil {
		return err
	}
	j.key = key
	return nil
}

func (j JWK) parse() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := unb64(j.N)
		if err != nil || len(n) == 0 {
			return nil, errors.New("jose: bad RSA modulus")
		}
		e, err := unb64(j.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("jose: bad RSA exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("jose: RSA key too small (%d bits)", pub.N.BitLen())
		}
		if pub.E < 3 || pub.E%2 == 0 {
			return nil, errors.New("jose: bad RSA exponent")
		}
		return pub, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, fmt.Errorf("%w: curve %q", ErrUnsupportedKey, j.Crv)
		}
		x, errX := unb64(j.X)
		y, errY := unb64(j.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("jose: bad EC coordinates")
		}
		raw := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
		if err != nil {
			return nil, fmt.Errorf("jose: EC point: %w", err)
		}
		return pub, nil
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("%w: curve %q", ErrUnsupportedKey, j.Crv)
		}
		x, err := unb64(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("jose: bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("%w: kty %q", ErrUnsupportedKey, j.Kty)
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of the key.
func (j JWK) Thumbprint() string {
	var members string
	switch j.Kty {
	case "RSA":
		members = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	case "EC":
		members = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	case "OKP":
		members = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, j.Crv, j.X)
	}
	sum := sha256.Sum256([]byte(members))
	return b64(sum[:])
}

// JWKSet is a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// ParseJWKSet decodes a key set. Keys gatekeep cannot use are skipped
// (forward compatibility): a "use" other than "sig" (checked before the key
// material is even parsed), an unsupported kty or curve, and an "alg" that
// gatekeep does not pair with the key's kty (for example RSA-OAEP or PS256 on
// an RSA key). Malformed key material on a usable signing key is an error,
// because silently dropping it hides misconfiguration.
func ParseJWKSet(b []byte) (*JWKSet, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("jose: decode jwks: %w", err)
	}
	set := &JWKSet{}
	for _, r := range raw.Keys {
		var hdr struct {
			Use string `json:"use"`
		}
		if err := json.Unmarshal(r, &hdr); err != nil {
			return nil, fmt.Errorf("jose: decode jwk: %w", err)
		}
		if hdr.Use != "" && hdr.Use != "sig" {
			continue
		}
		var j JWK
		if err := json.Unmarshal(r, &j); err != nil {
			if errors.Is(err, ErrUnsupportedKey) {
				continue
			}
			return nil, err
		}
		set.Keys = append(set.Keys, j)
	}
	return set, nil
}

// Lookup returns the key with the given kid.
func (s *JWKSet) Lookup(kid string) (JWK, bool) {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return JWK{}, false
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("jose: base64url: %w", err)
	}
	return b, nil
}
