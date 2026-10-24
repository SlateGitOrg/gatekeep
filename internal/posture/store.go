package posture

import (
	"crypto/subtle"
	"sync"
	"time"
)

// Record is the latest verified posture for a session.
type Record struct {
	DeviceID   string
	Facts      Facts
	VerifiedAt time.Time
}

// Age returns how old the record is at now.
func (r Record) Age(now time.Time) time.Duration { return now.Sub(r.VerifiedAt) }

type pairing struct {
	sid     string
	subject string
	expires time.Time
}

type binding struct {
	sid      string
	subject  string
	deviceID string
	expires  time.Time
}

// Store links device posture to browser sessions. It is in-memory: a
// multi-instance deployment would back it with a shared store (see
// docs/ARCHITECTURE.md).
type Store struct {
	mu       sync.Mutex
	now      func() time.Time
	pairings map[string]pairing
	bindings map[string]binding
	records  map[string]Record
}

// NewStore returns an empty store.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		now:      now,
		pairings: map[string]pairing{},
		bindings: map[string]binding{},
		records:  map[string]Record{},
	}
}

// NewPairing issues a single-use 10-character pairing code (~49 bits) for
// the session sid of subject.
func (s *Store) NewPairing(sid, subject string, ttl time.Duration) (string, error) {
	code, err := randomCode(10, alphabetHuman)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	s.pairings[code] = pairing{sid: sid, subject: subject, expires: s.now().Add(ttl)}
	return code, nil
}

// Accept stores verified claims from dev. A pairing-code nonce creates a new
// binding valid until bindingTTL; a binding nonce refreshes posture for the
// same device. It returns the binding ID the agent should use next time.
func (s *Store) Accept(c *Claims, dev Device, bindingTTL time.Duration) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.gc()
	if p, ok := s.pairings[c.Nonce]; ok && now.Before(p.expires) {
		if subtle.ConstantTimeCompare([]byte(p.subject), []byte(dev.Owner)) != 1 {
			return "", "", ErrOwner
		}
		delete(s.pairings, c.Nonce)
		id, err := randomCode(32, alphabetURL)
		if err != nil {
			return "", "", err
		}
		s.bindings[id] = binding{sid: p.sid, subject: p.subject, deviceID: dev.ID, expires: now.Add(bindingTTL)}
		s.records[p.sid] = Record{DeviceID: dev.ID, Facts: c.Facts, VerifiedAt: now}
		return id, p.sid, nil
	}
	if b, ok := s.bindings[c.Nonce]; ok && now.Before(b.expires) {
		if b.deviceID != dev.ID {
			return "", "", ErrDeviceSwap
		}
		s.records[b.sid] = Record{DeviceID: dev.ID, Facts: c.Facts, VerifiedAt: now}
		return c.Nonce, b.sid, nil
	}
	return "", "", ErrUnknownNonce
}

// Lookup returns the posture record for a session.
func (s *Store) Lookup(sid string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[sid]
	return r, ok
}

// Revoke forgets all posture, bindings and pairings for a session (logout).
func (s *Store) Revoke(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, sid)
	for k, b := range s.bindings {
		if b.sid == sid {
			delete(s.bindings, k)
		}
	}
	for k, p := range s.pairings {
		if p.sid == sid {
			delete(s.pairings, k)
		}
	}
}

// gc removes expired pairings and bindings (and records of dead bindings).
// Caller holds s.mu.
func (s *Store) gc() {
	now := s.now()
	for k, p := range s.pairings {
		if !now.Before(p.expires) {
			delete(s.pairings, k)
		}
	}
	for k, b := range s.bindings {
		if !now.Before(b.expires) {
			delete(s.bindings, k)
			delete(s.records, b.sid)
		}
	}
}
