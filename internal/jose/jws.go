package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Algorithm is a JWS signature algorithm identifier.
type Algorithm string

// Supported algorithms. Every algorithm is bound to exactly one key type.
const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
	EdDSA Algorithm = "EdDSA"
)

// MaxTokenSize bounds the compact serialisation accepted by Parse.
const MaxTokenSize = 16 << 10

// Errors returned by Parse and Verify.
var (
	ErrMalformed    = errors.New("jose: malformed token")
	ErrAlgorithm    = errors.New("jose: algorithm not allowed")
	ErrSignature    = errors.New("jose: signature verification failed")
	ErrCritical     = errors.New("jose: unsupported critical header")
	ErrKeyMismatch  = errors.New("jose: key type does not match algorithm")
	ErrTokenTooLong = errors.New("jose: token too large")
)

// Header is the protected JOSE header.
type Header struct {
	Alg  Algorithm `json:"alg"`
	Kid  string    `json:"kid,omitempty"`
	Typ  string    `json:"typ,omitempty"`
	Crit []string  `json:"crit,omitempty"`
}

// Signer produces compact JWS tokens with a private key.
type Signer struct {
	alg Algorithm
	kid string
	key crypto.Signer
	pub JWK
}

// NewSigner returns a signer for an RSA (RS256), P-256 ECDSA (ES256) or
// Ed25519 (EdDSA) private key.
func NewSigner(key crypto.Signer, kid string) (*Signer, error) {
	pub, err := NewJWK(key.Public(), kid)
	if err != nil {
		return nil, err
	}
	return &Signer{alg: pub.Algorithm(), kid: kid, key: key, pub: pub}, nil
}

// KeyID returns the signer's key id.
func (s *Signer) KeyID() string { return s.kid }

// Public returns the verification key as a JWK.
func (s *Signer) Public() JWK { return s.pub }

// Sign serialises claims as JSON and signs them with the given "typ" header.
func (s *Signer) Sign(typ string, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jose: encode claims: %w", err)
	}
	return s.SignRaw(Header{Alg: s.alg, Kid: s.kid, Typ: typ}, payload)
}

// SignRaw signs an arbitrary payload with an explicit header. The header's
// algorithm must match the key. It exists so tests and the demo IdP can build
// unusual (but well-formed) tokens.
func (s *Signer) SignRaw(h Header, payload []byte) (string, error) {
	if h.Alg != s.alg {
		return "", ErrKeyMismatch
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("jose: encode header: %w", err)
	}
	input := b64(hb) + "." + b64(payload)
	sig, err := s.signBytes([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

func (s *Signer) signBytes(input []byte) ([]byte, error) {
	switch s.alg {
	case RS256:
		d := sha256.Sum256(input)
		sig, err := s.key.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("jose: rsa sign: %w", err)
		}
		return sig, nil
	case ES256:
		d := sha256.Sum256(input)
		der, err := s.key.Sign(rand.Reader, d[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("jose: ecdsa sign: %w", err)
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			return nil, fmt.Errorf("jose: ecdsa signature: %w", err)
		}
		out := make([]byte, 64)
		rs.R.FillBytes(out[:32])
		rs.S.FillBytes(out[32:])
		return out, nil
	case EdDSA:
		sig, err := s.key.Sign(rand.Reader, input, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("jose: ed25519 sign: %w", err)
		}
		return sig, nil
	}
	return nil, ErrAlgorithm
}

// Parsed is a structurally valid, not yet verified, compact JWS.
type Parsed struct {
	Header  Header
	Payload []byte

	signingInput []byte
	signature    []byte
}

// Parse decodes a compact JWS without verifying it. The algorithm must be in
// the allow-list and no critical header extensions may be present.
func Parse(token string) (*Parsed, error) {
	if len(token) > MaxTokenSize {
		return nil, ErrTokenTooLong
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hb, err := unb64(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	payload, err := unb64(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := unb64(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	var h Header
	dec := json.NewDecoder(bytes.NewReader(hb))
	if err := dec.Decode(&h); err != nil {
		return nil, ErrMalformed
	}
	switch h.Alg {
	case RS256, ES256, EdDSA:
	default:
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, h.Alg)
	}
	if len(h.Crit) > 0 {
		return nil, ErrCritical
	}
	return &Parsed{
		Header:       h,
		Payload:      payload,
		signingInput: []byte(parts[0] + "." + parts[1]),
		signature:    sig,
	}, nil
}

// Verify checks the signature against key. The key's type must match the
// header algorithm exactly; an RSA key can never verify an EdDSA header etc.
func (p *Parsed) Verify(key JWK) error {
	if key.Algorithm() != p.Header.Alg {
		return ErrKeyMismatch
	}
	switch p.Header.Alg {
	case RS256:
		pub, ok := key.key.(*rsa.PublicKey)
		if !ok {
			return ErrKeyMismatch
		}
		d := sha256.Sum256(p.signingInput)
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], p.signature) != nil {
			return ErrSignature
		}
		return nil
	case ES256:
		pub, ok := key.key.(*ecdsa.PublicKey)
		if !ok {
			return ErrKeyMismatch
		}
		if len(p.signature) != 64 {
			return ErrSignature
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{
			new(big.Int).SetBytes(p.signature[:32]),
			new(big.Int).SetBytes(p.signature[32:]),
		})
		if err != nil {
			return ErrSignature
		}
		d := sha256.Sum256(p.signingInput)
		if !ecdsa.VerifyASN1(pub, d[:], der) {
			return ErrSignature
		}
		return nil
	case EdDSA:
		pub, ok := key.key.(ed25519.PublicKey)
		if !ok {
			return ErrKeyMismatch
		}
		if !ed25519.Verify(pub, p.signingInput, p.signature) {
			return ErrSignature
		}
		return nil
	}
	return ErrAlgorithm
}

// DecodeClaims unmarshals the payload into v. Unknown fields are allowed
// (JWT claim sets are open) but the payload must be a single JSON object.
func (p *Parsed) DecodeClaims(v any) error {
	dec := json.NewDecoder(bytes.NewReader(p.Payload))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: claims: %w", ErrMalformed, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after claims", ErrMalformed)
	}
	return nil
}
