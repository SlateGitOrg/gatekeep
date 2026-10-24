package session

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func secret(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestSealOpenRoundTrip(t *testing.T) {
	kr, err := NewKeyRing(secret(1))
	if err != nil {
		t.Fatal(err)
	}
	in := Session{ID: "sid", Subject: "alice", Groups: []string{"eng"}, ExpiresAt: time.Unix(99, 0).UTC()}
	v, err := kr.Seal("session", in)
	if err != nil {
		t.Fatal(err)
	}
	var out Session
	if err := kr.Open("session", v, &out); err != nil {
		t.Fatal(err)
	}
	if out.Subject != "alice" || out.Groups[0] != "eng" || !out.ExpiresAt.Equal(in.ExpiresAt) {
		t.Fatalf("got %+v", out)
	}
	// Each seal uses a fresh nonce.
	v2, _ := kr.Seal("session", in)
	if v == v2 {
		t.Fatal("nonce reuse")
	}
}

func TestTamperDetected(t *testing.T) {
	kr, _ := NewKeyRing(secret(1))
	v, _ := kr.Seal("session", Session{Subject: "alice"})
	raw, _ := base64.RawURLEncoding.DecodeString(v)
	for i := range raw {
		mut := bytes.Clone(raw)
		mut[i] ^= 0x01
		var s Session
		if err := kr.Open("session", base64.RawURLEncoding.EncodeToString(mut), &s); !errors.Is(err, ErrInvalid) {
			t.Fatalf("flip at byte %d accepted: %v", i, err)
		}
	}
	for _, bad := range []string{"", "!!!", "AAAA", v[:len(v)-4]} {
		if err := kr.Open("session", bad, &Session{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q: %v", bad, err)
		}
	}
}

func TestPurposeBinding(t *testing.T) {
	kr, _ := NewKeyRing(secret(1))
	v, _ := kr.Seal("login", LoginState{State: "s"})
	if err := kr.Open("session", v, &Session{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("login cookie accepted as session cookie")
	}
}

func TestKeyRotation(t *testing.T) {
	old, _ := NewKeyRing(secret(1))
	v, _ := old.Seal("session", Session{Subject: "alice"})
	rotated, err := NewKeyRing(secret(2), secret(1))
	if err != nil {
		t.Fatal(err)
	}
	var s Session
	if err := rotated.Open("session", v, &s); err != nil || s.Subject != "alice" {
		t.Fatalf("old-key cookie rejected after rotation: %v", err)
	}
	nv, _ := rotated.Seal("session", s)
	if err := old.Open("session", nv, &s); !errors.Is(err, ErrInvalid) {
		t.Fatal("new primary key is not the sealing key")
	}
	retired, _ := NewKeyRing(secret(2))
	if err := retired.Open("session", v, &s); !errors.Is(err, ErrInvalid) {
		t.Fatal("cookie under retired key still accepted")
	}
}

func TestKeyRingErrors(t *testing.T) {
	if _, err := NewKeyRing(); !errors.Is(err, ErrNoKeys) {
		t.Fatal(err)
	}
	if _, err := NewKeyRing([]byte("short")); err == nil {
		t.Fatal("short secret accepted")
	}
	if _, err := NewKeyRing(secret(1), secret(1)); err == nil {
		t.Fatal("duplicate secret accepted")
	}
}

func TestTooLarge(t *testing.T) {
	kr, _ := NewKeyRing(secret(1))
	big := Session{Groups: []string{strings.Repeat("g", 4000)}}
	if _, err := kr.Seal("session", big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if err := kr.Open("session", strings.Repeat("A", MaxCookieSize+1), &Session{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v", err)
	}
	if _, err := kr.Seal("session", func() {}); err == nil {
		t.Fatal("unencodable value sealed")
	}
}

func TestLifetimes(t *testing.T) {
	now := time.Unix(10_000, 0)
	l := Lifetimes{Absolute: time.Hour, Idle: 10 * time.Minute, TouchInterval: time.Minute}
	s := Session{LastSeen: now.Add(-5 * time.Minute), ExpiresAt: now.Add(time.Minute)}
	if err := s.Check(now, l); err != nil {
		t.Fatal(err)
	}
	if !s.NeedsTouch(now, l) {
		t.Fatal("should touch")
	}
	s.LastSeen = now.Add(-11 * time.Minute)
	if err := s.Check(now, l); !errors.Is(err, ErrIdle) {
		t.Fatalf("idle: %v", err)
	}
	s.LastSeen, s.ExpiresAt = now, now
	if err := s.Check(now, l); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if s.NeedsTouch(now, l) {
		t.Fatal("fresh session should not touch")
	}
	id, err := RandomID()
	if err != nil || len(id) != 43 {
		t.Fatalf("id %q %v", id, err)
	}
}

func FuzzOpen(f *testing.F) {
	kr, _ := NewKeyRing(secret(1))
	v, _ := kr.Seal("session", Session{Subject: "a"})
	f.Add(v)
	f.Fuzz(func(t *testing.T, in string) {
		var s Session
		if kr.Open("session", in, &s) == nil && in != v {
			// Only genuinely sealed values may open; a random string doing so
			// would be a GCM forgery.
			if _, err := base64.RawURLEncoding.DecodeString(in); err != nil {
				t.Fatal("non-base64 opened")
			}
		}
	})
}
