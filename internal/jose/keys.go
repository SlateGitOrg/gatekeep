package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// GenerateKey creates a fresh private key for alg.
func GenerateKey(alg Algorithm) (crypto.Signer, error) {
	switch alg {
	case RS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("jose: generate rsa: %w", err)
		}
		return k, nil
	case ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("jose: generate ecdsa: %w", err)
		}
		return k, nil
	case EdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("jose: generate ed25519: %w", err)
		}
		return k, nil
	}
	return nil, ErrAlgorithm
}

// MarshalPrivateKeyPEM encodes a private key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("jose: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 PEM private key.
func ParsePrivateKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("jose: expected PKCS#8 PRIVATE KEY PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jose: parse key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	return s, nil
}

// MarshalPublicKeyPEM encodes a public key as PKIX PEM.
func MarshalPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("jose: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicKeyPEM decodes a PKIX PEM public key into a JWK with the given kid.
func ParsePublicKeyPEM(b []byte, kid string) (JWK, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return JWK{}, errors.New("jose: expected PUBLIC KEY PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return JWK{}, fmt.Errorf("jose: parse public key: %w", err)
	}
	return NewJWK(pub, kid)
}
