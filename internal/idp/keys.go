package idp

import (
	"fmt"
	"sync"

	"github.com/SlateGitOrg/gatekeep/internal/jose"
)

// KeyRing holds the IdP's signing keys. The newest key signs; up to
// keepRetired previous keys stay published in the JWKS so tokens they signed
// remain verifiable during the rotation overlap window.
type KeyRing struct {
	mu          sync.RWMutex
	alg         jose.Algorithm
	keepRetired int
	signers     []*jose.Signer // newest first
	serial      int
}

// NewKeyRing creates a ring with one fresh key.
func NewKeyRing(alg jose.Algorithm, keepRetired int) (*KeyRing, error) {
	kr := &KeyRing{alg: alg, keepRetired: keepRetired}
	if _, err := kr.Rotate(); err != nil {
		return nil, err
	}
	return kr, nil
}

// Rotate generates a new active key and returns its kid. Keys beyond the
// retention window are dropped from the JWKS.
func (k *KeyRing) Rotate() (string, error) {
	key, err := jose.GenerateKey(k.alg)
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.serial++
	pub, err := jose.NewJWK(key.Public(), "")
	if err != nil {
		return "", err
	}
	kid := fmt.Sprintf("k%d-%s", k.serial, pub.Thumbprint()[:8])
	s, err := jose.NewSigner(key, kid)
	if err != nil {
		return "", err
	}
	k.signers = append([]*jose.Signer{s}, k.signers...)
	if len(k.signers) > k.keepRetired+1 {
		k.signers = k.signers[:k.keepRetired+1]
	}
	return kid, nil
}

// Active returns the current signing key.
func (k *KeyRing) Active() *jose.Signer {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.signers[0]
}

// JWKS returns the published key set.
func (k *KeyRing) JWKS() jose.JWKSet {
	k.mu.RLock()
	defer k.mu.RUnlock()
	set := jose.JWKSet{Keys: make([]jose.JWK, 0, len(k.signers))}
	for _, s := range k.signers {
		set.Keys = append(set.Keys, s.Public())
	}
	return set
}
