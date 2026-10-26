package idp_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/idp"
	"github.com/SlateGitOrg/gatekeep/internal/idp/idptest"
	"github.com/SlateGitOrg/gatekeep/internal/jose"
	"github.com/SlateGitOrg/gatekeep/internal/oidc"
)

const cb = "https://rp.test/cb"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func authURL(s *idptest.Server, mut func(url.Values)) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {"gatekeep"}, "redirect_uri": {cb}, "scope": {"openid email"},
		"state": {"st"}, "nonce": {"nn"}, "code_challenge": {oidc.CodeChallengeS256(strings.Repeat("v", 43))},
		"code_challenge_method": {"S256"},
	}
	if mut != nil {
		mut(q)
	}
	return s.Issuer + "/authorize?" + q.Encode()
}

func TestAuthorizeValidation(t *testing.T) {
	s := idptest.Start(t, []string{cb}, nil)
	hc := idptest.NoRedirect(s.TS.Client())
	// Unknown client / unregistered redirect: error page, no redirect.
	for _, mut := range []func(url.Values){
		func(q url.Values) { q.Set("client_id", "nope") },
		func(q url.Values) { q.Set("redirect_uri", "https://evil.test/cb") },
	} {
		resp, err := hc.Get(authURL(s, mut))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	// Protocol errors redirect back with error + state.
	for want, mut := range map[string]func(url.Values){
		"unsupported_response_type": func(q url.Values) { q.Set("response_type", "token") },
		"invalid_scope":             func(q url.Values) { q.Set("scope", "email") },
		"invalid_request":           func(q url.Values) { q.Set("code_challenge_method", "plain") },
	} {
		resp, err := hc.Get(authURL(s, mut))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		loc, _ := resp.Location()
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != want || loc.Query().Get("state") != "st" {
			t.Fatalf("%s: %d %v", want, resp.StatusCode, loc)
		}
	}
	resp, _ := hc.Get(authURL(s, func(q url.Values) { q.Del("nonce") }))
	_ = resp.Body.Close()
	if loc, _ := resp.Location(); loc == nil || loc.Query().Get("error") != "invalid_request" {
		t.Fatal("missing nonce accepted")
	}
	// Security headers on IdP pages.
	resp, _ = hc.Get(authURL(s, nil))
	_ = resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("headers %v", resp.Header)
	}
}

func TestLoginFailuresAndLockout(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	s := idptest.Start(t, []string{cb}, func(o *idp.Options) { o.Now = clk.Now; o.MaxFailures = 3; o.Lockout = time.Minute })
	hc := idptest.NoRedirect(s.TS.Client())
	for range 3 {
		if _, err := idptest.Login(hc, authURL(s, nil), "alice", "wrong"); !errors.Is(err, idptest.ErrLoginFailed) {
			t.Fatalf("wrong password: %v", err)
		}
	}
	if _, err := idptest.Login(hc, authURL(s, nil), "alice", "password-alice"); !errors.Is(err, idptest.ErrLoginFailed) {
		t.Fatalf("locked-out user logged in: %v", err)
	}
	clk.Add(2 * time.Minute)
	if _, err := idptest.Login(hc, authURL(s, nil), "alice", "password-alice"); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
	if _, err := idptest.Login(hc, authURL(s, nil), "mallory", "x"); !errors.Is(err, idptest.ErrLoginFailed) {
		t.Fatalf("unknown user: %v", err)
	}
	// Expired / unknown login request id.
	resp, err := hc.PostForm(s.Issuer+"/login", url.Values{"req": {"bogus"}, "username": {"alice"}, "password": {"password-alice"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bogus req: %d", resp.StatusCode)
	}
}

func token(t *testing.T, s *idptest.Server, form url.Values, user, pass string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, s.Issuer+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := s.TS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func TestTokenEndpoint(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	var mutated bool
	s := idptest.Start(t, []string{cb}, func(o *idp.Options) {
		o.Now = clk.Now
		o.MutateIDToken = func(*oidc.IDTokenClaims) { mutated = true }
	})
	hc := idptest.NoRedirect(s.TS.Client())
	verifier := strings.Repeat("v", 43)
	getCode := func() string {
		loc, err := idptest.Login(hc, authURL(s, nil), "bob", "password-bob")
		if err != nil {
			t.Fatal(err)
		}
		return loc.Query().Get("code")
	}
	base := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb}, "code_verifier": {verifier}}
	}
	code := getCode()
	if st, m := token(t, s, base(code), "", ""); st != http.StatusUnauthorized || m["error"] != "invalid_client" {
		t.Fatalf("no auth: %d %v", st, m)
	}
	if st, _ := token(t, s, base(code), "gatekeep", "bad"); st != http.StatusUnauthorized {
		t.Fatal("bad secret accepted")
	}
	f := base(code)
	f.Set("grant_type", "password")
	if _, m := token(t, s, f, "gatekeep", "s3cret"); m["error"] != "unsupported_grant_type" {
		t.Fatalf("%v", m)
	}
	f = base(code)
	f.Set("redirect_uri", "https://rp.test/other")
	if _, m := token(t, s, f, "gatekeep", "s3cret"); m["error"] != "invalid_grant" {
		t.Fatalf("redirect mismatch: %v", m)
	}
	// That attempt consumed the code (codes are burned on first use).
	if _, m := token(t, s, base(code), "gatekeep", "s3cret"); m["error"] != "invalid_grant" {
		t.Fatalf("burned code: %v", m)
	}
	code = getCode()
	st, m := token(t, s, base(code), "gatekeep", "s3cret")
	if st != http.StatusOK || m["id_token"] == nil || !mutated {
		t.Fatalf("%d %v", st, m)
	}
	p, err := jose.Parse(m["id_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(s.Keys().Active().Public()); err != nil {
		t.Fatal(err)
	}
	// Expired code.
	code = getCode()
	clk.Add(2 * time.Minute)
	if _, m := token(t, s, base(code), "gatekeep", "s3cret"); m["error"] != "invalid_grant" {
		t.Fatalf("expired code: %v", m)
	}
}

func TestDiscoveryAndJWKS(t *testing.T) {
	s := idptest.Start(t, []string{cb}, nil)
	resp, err := s.TS.Client().Get(s.Issuer + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	set, err := jose.ParseJWKSet(b)
	if err != nil || len(set.Keys) != 1 || !strings.Contains(resp.Header.Get("Cache-Control"), "max-age=300") {
		t.Fatalf("%v %v", set, err)
	}
	kid1 := s.Keys().Active().KeyID()
	kid2, _ := s.Keys().Rotate()
	kid3, _ := s.Keys().Rotate()
	jw := s.Keys().JWKS()
	if len(jw.Keys) != 2 || jw.Keys[0].Kid != kid3 || jw.Keys[1].Kid != kid2 {
		t.Fatalf("retention: %v", jw.Keys)
	}
	if _, ok := jw.Lookup(kid1); ok {
		t.Fatal("retired key still published")
	}
	if _, err := oidc.Discover(t.Context(), s.TS.Client(), s.Issuer); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := idp.New(idp.Options{}); err == nil {
		t.Fatal("empty options accepted")
	}
	kr, _ := idp.NewKeyRing(jose.ES256, 0)
	if _, err := idp.New(idp.Options{Issuer: "https://x", Keys: kr, Users: []idp.User{{Username: "a"}}}); err == nil {
		t.Fatal("user without subject accepted")
	}
	if _, err := idp.NewKeyRing("HS256", 0); err == nil {
		t.Fatal("bad alg")
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := idp.HashPassword("hunter2", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := idp.CheckPassword(h, "hunter2"); !ok || err != nil {
		t.Fatal("correct password rejected")
	}
	if ok, _ := idp.CheckPassword(h, "hunter3"); ok {
		t.Fatal("wrong password accepted")
	}
	for _, bad := range []string{"", "md5$x$y$z", "pbkdf2-sha256$10$AA$AA", "pbkdf2-sha256$5000$!!$AA", "pbkdf2-sha256$5000$AA$"} {
		if _, err := idp.CheckPassword(bad, "x"); !errors.Is(err, idp.ErrBadHash) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
