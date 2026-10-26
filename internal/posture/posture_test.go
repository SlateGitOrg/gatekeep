package posture

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/jose"
	"github.com/SlateGitOrg/gatekeep/internal/replay"
)

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func deviceSigner(t *testing.T, alg jose.Algorithm, id string) (*jose.Signer, Device) {
	t.Helper()
	k, err := jose.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(k, id)
	if err != nil {
		t.Fatal(err)
	}
	return s, Device{ID: id, Owner: "user-alice", Key: s.Public()}
}

func newVerifier(now *time.Time, devs ...Device) *Verifier {
	m := map[string]Device{}
	for _, d := range devs {
		m[d.ID] = d
	}
	return &Verifier{Devices: m, Audience: "gatekeep", Leeway: 5 * time.Second, MaxAge: time.Minute,
		Replay: replay.New(100, func() time.Time { return *now }), Now: func() time.Time { return *now }}
}

var facts = Facts{OS: "linux", DiskEncrypted: true, FirewallEnabled: true, ScreenLock: true, PatchAgeDays: 3}

func TestVerifyAccepts(t *testing.T) {
	now := t0
	for _, alg := range []jose.Algorithm{jose.EdDSA, jose.ES256} {
		s, dev := deviceSigner(t, alg, "dev-"+string(alg))
		v := newVerifier(&now, dev)
		tok, err := Sign(s, dev.ID, "gatekeep", "CODE", facts, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		c, d, err := v.Verify(tok)
		if err != nil || d.ID != dev.ID || !c.Facts.DiskEncrypted || c.Nonce != "CODE" {
			t.Fatalf("%s: %v", alg, err)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	now := t0
	s, dev := deviceSigner(t, jose.EdDSA, "laptop")
	other, _ := deviceSigner(t, jose.EdDSA, "laptop")
	v := newVerifier(&now, dev)
	sign := func(sg *jose.Signer, id, aud string, at time.Time, ttl time.Duration) string {
		tok, err := Sign(sg, id, aud, "CODE", facts, at, ttl)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	idTok, _ := s.Sign("JWT", map[string]any{"iss": "laptop"})
	noJTI, _ := s.Sign(TokenType, Claims{Nonce: "CODE"})
	cases := map[string]struct {
		tok    string
		reason string
	}{
		"unknown device": {sign(s, "phone", "gatekeep", now, time.Minute), "unknown_device"},
		"forged":         {sign(other, "laptop", "gatekeep", now, time.Minute), "bad_signature"},
		"wrong aud":      {sign(s, "laptop", "other-proxy", now, time.Minute), "wrong_audience"},
		"expired":        {sign(s, "laptop", "gatekeep", now.Add(-3*time.Minute), time.Minute), "posture_expired"},
		"stale iat":      {sign(s, "laptop", "gatekeep", now.Add(-90*time.Second), 2*time.Minute), "posture_expired"},
		"wrong typ":      {idTok, "invalid_assertion"},
		"no claims":      {noJTI, "unknown_device"},
		"garbage":        {"x.y.z", "invalid_assertion"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := v.Verify(c.tok)
			if err == nil || Reason(err) != c.reason {
				t.Fatalf("reason %q (%v), want %q", Reason(err), err, c.reason)
			}
		})
	}
	// Excessive lifetime: hand-built token with exp-iat > MaxLifetime.
	long, _ := s.Sign(TokenType, Claims{RegisteredClaims: jose.RegisteredClaims{
		Issuer: "laptop", Audience: jose.Audience{"gatekeep"}, ID: "j1",
		IssuedAt: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(time.Hour)),
	}})
	if _, _, err := v.Verify(long); !errors.Is(err, ErrLifetime) {
		t.Fatalf("long lifetime: %v", err)
	}
	missingJTI, _ := s.Sign(TokenType, Claims{RegisteredClaims: jose.RegisteredClaims{
		Issuer: "laptop", Audience: jose.Audience{"gatekeep"},
		IssuedAt: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(time.Minute)),
	}})
	if _, _, err := v.Verify(missingJTI); !errors.Is(err, ErrNoJTI) {
		t.Fatalf("missing jti: %v", err)
	}
	noIAT, _ := s.Sign(TokenType, Claims{RegisteredClaims: jose.RegisteredClaims{
		Issuer: "laptop", Audience: jose.Audience{"gatekeep"}, ID: "j2", Expiry: jose.NewNumericDate(now.Add(time.Minute)),
	}})
	if _, _, err := v.Verify(noIAT); !errors.Is(err, jose.ErrMissingClaim) {
		t.Fatalf("missing iat: %v", err)
	}
}

func TestReplayRejected(t *testing.T) {
	now := t0
	s, dev := deviceSigner(t, jose.EdDSA, "laptop")
	v := newVerifier(&now, dev)
	tok, _ := Sign(s, dev.ID, "gatekeep", "CODE", facts, now, time.Minute)
	if _, _, err := v.Verify(tok); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Verify(tok); Reason(err) != "posture_replay" {
		t.Fatalf("replay: %v", err)
	}
}

func TestStorePairingAndBinding(t *testing.T) {
	now := t0
	st := NewStore(func() time.Time { return now })
	_, dev := deviceSigner(t, jose.EdDSA, "laptop")
	code, err := st.NewPairing("sid-1", "user-alice", 5*time.Minute)
	if err != nil || len(code) != 10 {
		t.Fatalf("%q %v", code, err)
	}
	// Wrong owner cannot pair.
	mallory := dev
	mallory.Owner = "user-mallory"
	if _, _, err := st.Accept(&Claims{Nonce: code, Facts: facts}, mallory, time.Hour); !errors.Is(err, ErrOwner) {
		t.Fatalf("owner: %v", err)
	}
	binding, sid, err := st.Accept(&Claims{Nonce: code, Facts: facts}, dev, time.Hour)
	if err != nil || sid != "sid-1" || binding == "" {
		t.Fatalf("pair: %v", err)
	}
	// Pairing codes are single use.
	if _, _, err := st.Accept(&Claims{Nonce: code}, dev, time.Hour); !errors.Is(err, ErrUnknownNonce) {
		t.Fatalf("code reuse: %v", err)
	}
	rec, ok := st.Lookup("sid-1")
	if !ok || rec.DeviceID != "laptop" || rec.Age(now) != 0 {
		t.Fatalf("%+v", rec)
	}
	now = now.Add(time.Minute)
	f2 := facts
	f2.PatchAgeDays = 40
	if _, _, err := st.Accept(&Claims{Nonce: binding, Facts: f2}, dev, time.Hour); err != nil {
		t.Fatal(err)
	}
	if rec, _ := st.Lookup("sid-1"); rec.Facts.PatchAgeDays != 40 || !rec.VerifiedAt.Equal(now) {
		t.Fatalf("refresh not stored: %+v", rec)
	}
	other := dev
	other.ID = "phone"
	if _, _, err := st.Accept(&Claims{Nonce: binding}, other, time.Hour); !errors.Is(err, ErrDeviceSwap) {
		t.Fatalf("swap: %v", err)
	}
	// Binding expiry drops the posture record.
	now = now.Add(2 * time.Hour)
	if _, _, err := st.Accept(&Claims{Nonce: binding}, dev, time.Hour); !errors.Is(err, ErrUnknownNonce) {
		t.Fatalf("expired binding: %v", err)
	}
	if _, ok := st.Lookup("sid-1"); ok {
		t.Fatal("record outlived binding")
	}
	// Expired pairing codes are rejected.
	code, _ = st.NewPairing("sid-2", "user-alice", time.Minute)
	now = now.Add(2 * time.Minute)
	if _, _, err := st.Accept(&Claims{Nonce: code}, dev, time.Hour); !errors.Is(err, ErrUnknownNonce) {
		t.Fatalf("expired code: %v", err)
	}
	// Revoke clears everything for the session.
	code, _ = st.NewPairing("sid-3", "user-alice", time.Minute)
	b3, _, _ := st.Accept(&Claims{Nonce: code}, dev, time.Hour)
	_, _ = st.NewPairing("sid-3", "user-alice", time.Minute)
	st.Revoke("sid-3")
	if _, ok := st.Lookup("sid-3"); ok {
		t.Fatal("revoke")
	}
	if _, _, err := st.Accept(&Claims{Nonce: b3}, dev, time.Hour); !errors.Is(err, ErrUnknownNonce) {
		t.Fatal("binding survived revoke")
	}
}

func TestRandomCodeDistribution(t *testing.T) {
	seen := map[byte]int{}
	for range 200 {
		c, err := randomCode(10, alphabetHuman)
		if err != nil {
			t.Fatal(err)
		}
		for i := range len(c) {
			if !strings.ContainsRune(alphabetHuman, rune(c[i])) {
				t.Fatalf("symbol %q outside alphabet", c[i])
			}
			seen[c[i]]++
		}
	}
	if len(seen) != len(alphabetHuman) {
		t.Fatalf("only %d of %d symbols drawn", len(seen), len(alphabetHuman))
	}
}

func TestSystemCollector(t *testing.T) {
	files := map[string]string{
		"/proc/sys/kernel/osrelease": "6.1.0-test\n",
		"facts.json":                 `{"disk_encrypted":true,"patch_age_days":4,"os_version":"14.5"}`,
		"bad.json":                   `{"disk_encryptd":true}`,
	}
	read := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
	host := func() (string, error) { return "host-1", nil }
	f, err := SystemCollector{ReadFile: read, Hostname: host}.Collect(context.Background())
	if err != nil || f.OSVersion != "6.1.0-test" || f.Hostname != "host-1" || f.OS == "" || f.AgentVersion != AgentVersion {
		t.Fatalf("%+v %v", f, err)
	}
	f, err = SystemCollector{FactsFile: "facts.json", ReadFile: read, Hostname: host}.Collect(context.Background())
	if err != nil || !f.DiskEncrypted || f.PatchAgeDays != 4 || f.OSVersion != "14.5" {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := (SystemCollector{FactsFile: "bad.json", ReadFile: read, Hostname: host}).Collect(context.Background()); err == nil {
		t.Fatal("unknown fact accepted")
	}
	if _, err := (SystemCollector{FactsFile: "missing.json", ReadFile: read, Hostname: host}).Collect(context.Background()); err == nil {
		t.Fatal("missing file accepted")
	}
}

type staticCollector Facts

func (s staticCollector) Collect(context.Context) (Facts, error) { return Facts(s), nil }

func TestAgentReportAndRun(t *testing.T) {
	now := t0
	s, dev := deviceSigner(t, jose.EdDSA, "laptop")
	v := newVerifier(&now, dev)
	st := NewStore(func() time.Time { return now })
	code, _ := st.NewPairing("sid", "user-alice", time.Minute)
	var reports atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c, d, err := v.Verify(string(body))
		if err == nil {
			var b string
			b, _, err = st.Accept(c, d, time.Hour)
			if err == nil {
				reports.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"accepted":true,"binding":"` + b + `"}`))
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"accepted":false,"reason":"` + Reason(err) + `"}`))
	}))
	defer ts.Close()
	a := &Agent{DeviceID: "laptop", Signer: s, Collector: staticCollector(facts), ProxyURL: ts.URL,
		Audience: "gatekeep", Client: ts.Client(), Now: func() time.Time { return now }}
	rr, err := a.Report(context.Background(), code)
	if err != nil || rr.Binding == "" {
		t.Fatalf("%+v %v", rr, err)
	}
	if _, err := a.Report(context.Background(), "WRONGCODE1"); err == nil {
		t.Fatal("bad code accepted")
	}
	// Run: pairs, refreshes until the binding is revoked, then stops.
	code, _ = st.NewPairing("sid2", "user-alice", time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx, code, 20*time.Millisecond) }()
	deadline := time.Now().Add(3 * time.Second)
	for reports.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st.Revoke("sid2")
	if err := <-done; err == nil || !strings.Contains(err.Error(), "pair again") {
		t.Fatalf("run: %v", err)
	}
}
