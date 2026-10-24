package bench

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/archit2501/gatekeep/internal/audit"
	"github.com/archit2501/gatekeep/internal/gateway"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/oidc"
	"github.com/archit2501/gatekeep/internal/policy"
	"github.com/archit2501/gatekeep/internal/posture"
	"github.com/archit2501/gatekeep/internal/replay"
	"github.com/archit2501/gatekeep/internal/session"
)

var now = time.Date(2026, 10, 24, 14, 0, 0, 0, time.UTC)

func clock() time.Time { return now }

const adminRule = `"admins" in identity.groups && device.disk_encrypted && device.firewall_enabled
	&& device.patch_age_days <= 14 && identity.auth_age < duration("12h")`

func adminPolicy(b *testing.B) *policy.Policy {
	b.Helper()
	e, err := policy.NewEngine(0)
	if err != nil {
		b.Fatal(err)
	}
	p, err := e.Compile([]policy.RuleSpec{
		{Name: "admins", Effect: policy.Allow, Expr: adminRule},
		{Name: "no-deletes", Effect: policy.Deny, Expr: `request.method == "DELETE" && !device.screen_lock`},
		{Name: "office", Effect: policy.Deny, Expr: `request.method != "GET" && !request.ip.in_cidr("10.0.0.0/8")`},
	})
	if err != nil {
		b.Fatal(err)
	}
	return p
}

func BenchmarkPolicyEvaluate(b *testing.B) {
	p := adminPolicy(b)
	in := policy.Input{
		Identity: policy.Identity{Authenticated: true, Subject: "u", Groups: []string{"eng", "admins"}, AuthAge: time.Hour},
		Device:   policy.Device{Present: true, DiskEncrypted: true, FirewallEnabled: true, ScreenLock: true, PatchAgeDays: 3},
		Request:  policy.Request{Method: "GET", Path: "/admin/", ClientIP: "10.1.2.3", Time: now},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if !p.Evaluate(ctx, in).Allowed {
			b.Fatal("denied")
		}
	}
}

func BenchmarkSessionSealOpen(b *testing.B) {
	kr, err := session.NewKeyRing(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		b.Fatal(err)
	}
	s := session.Session{ID: "sid", Subject: "user-alice", Email: "alice@example.test", Groups: []string{"eng", "admins"},
		Issuer: "https://idp", AuthTime: now, IssuedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)}
	b.ReportAllocs()
	for b.Loop() {
		v, err := kr.Seal("s", s)
		if err != nil {
			b.Fatal(err)
		}
		var out session.Session
		if err := kr.Open("s", v, &out); err != nil {
			b.Fatal(err)
		}
	}
}

type staticKeys struct{ k jose.JWK }

func (s staticKeys) Key(context.Context, string, jose.Algorithm) (jose.JWK, error) { return s.k, nil }

func BenchmarkIDTokenVerifyES256(b *testing.B) {
	k, _ := jose.GenerateKey(jose.ES256)
	sg, _ := jose.NewSigner(k, "k1")
	tok, _ := sg.Sign("JWT", oidc.IDTokenClaims{
		RegisteredClaims: jose.RegisteredClaims{Issuer: "https://idp", Subject: "u", Audience: jose.Audience{"gk"},
			IssuedAt: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(time.Minute))},
		Nonce: "n",
	})
	v := &oidc.Verifier{Issuer: "https://idp", ClientID: "gk", Keys: staticKeys{sg.Public()}, Now: clock}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Verify(context.Background(), tok, "n"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPostureVerifyEdDSA(b *testing.B) {
	k, _ := jose.GenerateKey(jose.EdDSA)
	sg, _ := jose.NewSigner(k, "dev")
	// Replay tracking is measured separately (BenchmarkReplayCacheUse), so
	// one token can be verified repeatedly here.
	v := &posture.Verifier{Devices: map[string]posture.Device{"dev": {ID: "dev", Owner: "u", Key: sg.Public()}},
		Audience: "gk", Now: clock}
	tok, _ := posture.Sign(sg, "dev", "gk", "nonce", posture.Facts{OS: "linux", DiskEncrypted: true}, now, time.Minute)
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := v.Verify(tok); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplayCacheUse(b *testing.B) {
	c := replay.New(1<<30, clock)
	exp := now.Add(time.Hour)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		_ = c.Use(strconv.Itoa(i), exp)
		i++
	}
}

// fakeAuth satisfies gateway.Authenticator; the benchmark never logs in.
type fakeAuth struct{}

func (fakeAuth) AuthCodeURL(string, string, string) string { return "https://idp/authorize" }
func (fakeAuth) Exchange(context.Context, string, string) (*oidc.TokenResponse, error) {
	return nil, io.EOF
}
func (fakeAuth) VerifyIDToken(context.Context, string, string) (*oidc.IDTokenClaims, error) {
	return nil, io.EOF
}
func (fakeAuth) Issuer() string { return "https://idp" }

type okTransport struct{}

func (okTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}},
		Body: io.NopCloser(bytes.NewReader([]byte("ok"))), Request: r}, nil
}

// BenchmarkGatewayAuthorizedRequest measures gatekeep's per-request overhead
// for an authenticated, policy-allowed request: cookie decrypt + lifetime
// checks, posture lookup, CEL evaluation, upstream assertion signing (ES256),
// reverse-proxy rewrite and a chained audit write. The upstream is an
// in-memory RoundTripper, so network time is excluded.
func BenchmarkGatewayAuthorizedRequest(b *testing.B) {
	secret := bytes.Repeat([]byte{9}, 32)
	kr, _ := session.NewKeyRing(secret)
	uk, _ := jose.GenerateKey(jose.ES256)
	us, _ := jose.NewSigner(uk, "up")
	up, _ := url.Parse("http://upstream.internal")
	rt, err := gateway.NewRouter([]*gateway.Route{{Name: "admin", PathPrefix: "/admin/", Upstream: up, Policy: adminPolicy(b)}})
	if err != nil {
		b.Fatal(err)
	}
	store := posture.NewStore(clock)
	pub, _ := url.Parse("https://gk.test")
	g, err := gateway.New(gateway.Options{
		PublicURL: pub, Auth: fakeAuth{}, Cookies: kr, CSRFKey: secret, Router: rt,
		Lifetimes: session.Lifetimes{Absolute: 8 * time.Hour, Idle: time.Hour, TouchInterval: time.Minute},
		Posture:   &posture.Verifier{}, PostureStore: store, UpstreamSigner: us,
		Audit: audit.NewLogger(io.Discard, clock), Now: clock, Transport: okTransport{},
	})
	if err != nil {
		b.Fatal(err)
	}
	code, _ := store.NewPairing("sid-1", "user-alice", time.Minute)
	if _, _, err := store.Accept(&posture.Claims{Nonce: code, Facts: posture.Facts{DiskEncrypted: true, FirewallEnabled: true, ScreenLock: true, PatchAgeDays: 1}},
		posture.Device{ID: "laptop", Owner: "user-alice"}, time.Hour); err != nil {
		b.Fatal(err)
	}
	cookie, _ := kr.Seal("gatekeep/session/v1", session.Session{ID: "sid-1", Subject: "user-alice", Groups: []string{"admins"},
		Issuer: "https://idp", AuthTime: now, IssuedAt: now, LastSeen: now, ExpiresAt: now.Add(time.Hour)})
	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://gk.test/admin/x", nil)
		req.AddCookie(&http.Cookie{Name: "__Host-gatekeep", Value: cookie})
		w := httptest.NewRecorder()
		g.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
	}
}
