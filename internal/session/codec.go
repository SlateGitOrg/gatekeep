// Package session implements gatekeep's authenticated-encryption cookie
// codec and the session payload it carries.
//
// Wire format (before base64url):
//
//	version(1) || keyID(1) || nonce(12) || AES-256-GCM(ciphertext||tag)
//
// The cookie name and purpose are bound as additional authenticated data, so
// a valid login-state cookie can never be replayed as a session cookie (or
// vice versa) even though both are sealed by the same key ring.
package session

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	formatVersion = 1
	nonceSize     = 12
	// MaxCookieSize is the largest encoded value the codec will produce or
	// accept; browsers drop cookies over ~4096 bytes.
	MaxCookieSize = 3800
)

// Errors returned by the codec.
var (
	ErrInvalid  = errors.New("session: invalid or tampered cookie")
	ErrTooLarge = errors.New("session: cookie too large")
	ErrNoKeys   = errors.New("session: key ring is empty")
)

// KeyRing holds one primary key used for sealing and any number of older keys
// still accepted for opening, enabling zero-downtime key rotation.
type KeyRing struct {
	primary byte
	aeads   map[byte]cipher.AEAD
}

// NewKeyRing derives AES-256-GCM keys from 32+ byte master secrets. The first
// secret is primary (id 0); the rest are accepted for decryption only.
func NewKeyRing(secrets ...[]byte) (*KeyRing, error) {
	if len(secrets) == 0 {
		return nil, ErrNoKeys
	}
	if len(secrets) > 255 {
		return nil, errors.New("session: too many keys")
	}
	kr := &KeyRing{aeads: make(map[byte]cipher.AEAD, len(secrets))}
	for i, s := range secrets {
		if len(s) < 32 {
			return nil, fmt.Errorf("session: secret %d shorter than 32 bytes", i)
		}
		// Key id is derived from the secret, not its position, so reordering
		// the ring during rotation never mislabels a key.
		id := sha256.Sum256(append([]byte("gatekeep-key-id\x00"), s...))
		key, err := hkdf.Key(sha256.New, s, nil, "gatekeep cookie aes-256-gcm v1", 32)
		if err != nil {
			return nil, fmt.Errorf("session: derive key: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("session: cipher: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("session: gcm: %w", err)
		}
		if _, dup := kr.aeads[id[0]]; dup {
			return nil, fmt.Errorf("session: key id collision for secret %d; regenerate it", i)
		}
		kr.aeads[id[0]] = aead
		if i == 0 {
			kr.primary = id[0]
		}
	}
	return kr, nil
}

// Seal encrypts v (JSON-encoded) bound to aad.
func (k *KeyRing) Seal(aad string, v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("session: encode: %w", err)
	}
	aead := k.aeads[k.primary]
	out := make([]byte, 2+nonceSize, 2+nonceSize+len(plain)+aead.Overhead())
	out[0], out[1] = formatVersion, k.primary
	if _, err := rand.Read(out[2 : 2+nonceSize]); err != nil {
		return "", fmt.Errorf("session: nonce: %w", err)
	}
	out = aead.Seal(out, out[2:2+nonceSize], plain, k.additional(aad))
	enc := base64.RawURLEncoding.EncodeToString(out)
	if len(enc) > MaxCookieSize {
		return "", ErrTooLarge
	}
	return enc, nil
}

// Open authenticates and decrypts a value sealed with aad into v.
func (k *KeyRing) Open(aad, value string, v any) error {
	if len(value) > MaxCookieSize {
		return ErrTooLarge
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) < 2+nonceSize+16 || raw[0] != formatVersion {
		return ErrInvalid
	}
	aead, ok := k.aeads[raw[1]]
	if !ok {
		return ErrInvalid
	}
	plain, err := aead.Open(nil, raw[2:2+nonceSize], raw[2+nonceSize:], k.additional(aad))
	if err != nil {
		return ErrInvalid
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return ErrInvalid
	}
	return nil
}

func (k *KeyRing) additional(aad string) []byte {
	return append([]byte{formatVersion}, aad...)
}
