package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/idp/idptest"
	"github.com/SlateGitOrg/gatekeep/internal/jose"
	"github.com/SlateGitOrg/gatekeep/internal/oidc"
)

const redirect = "https://rp.test/.gatekeep/callback"

func newClient(t *testing.T, s *idptest.Server) *oidc.Client {
	t.Helper()
	c, err := oidc.NewClient(context.Background(), s.TS.Client(), oidc.Config{
		Issuer: s.Issuer, ClientID: "gatekeep", ClientSecret: "s3cret", RedirectURL: redirect,
		Scopes: []string{"email"}, Leeway: time.Second, JWKSMinRefresh: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// login runs the front-channel part of the flow and returns the code.
func login(t *testing.T, s *idptest.Server, c *oidc.Client, state, nonce, verifier string) string {
	t.Helper()
	loc, err := idptest.Login(idptest.NoRedirect(s.TS.Client()), c.AuthCodeURL(state, nonce, verifier), "alice", "password-alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loc.String(), redirect) || loc.Query().Get("state") != state {
		t.Fatalf("callback %s", loc)
	}
	return loc.Query().Get("code")
}

func TestFullCodeFlow(t *testing.T) {
	s := idptest.Start(t, []string{redirect}, nil)
	c := newClient(t, s)
	if c.Metadata().Issuer != s.Issuer {
		t.Fatal("metadata")
	}
	if u := c.AuthCodeURL("st", "nn", "v"); !strings.Contains(u, "scope=openid+email") || !strings.Contains(u, "code_challenge_method=S256") {
		t.Fatalf("auth url %s", u)
	}
	verifier, _ := oidc.NewCodeVerifier()
	code := login(t, s, c, "st-1", "nonce-1", verifier)
	tr, err := c.Exchange(context.Background(), code, verifier)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := c.Verifier.Verify(context.Background(), tr.IDToken, "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-alice" || claims.AZP != "gatekeep" || len(claims.Groups) != 2 {
		t.Fatalf("%+v", claims)
	}
	// Authorization codes are single use.
	_, err = c.Exchange(context.Background(), code, verifier)
	var te *oidc.TokenError
	if !errors.As(err, &te) || te.Code != "invalid_grant" {
		t.Fatalf("code replay: %v", err)
	}
}

func TestExchangeRejectsWrongVerifier(t *testing.T) {
	s := idptest.Start(t, []string{redirect}, nil)
	c := newClient(t, s)
	verifier, _ := oidc.NewCodeVerifier()
	code := login(t, s, c, "st", "nn", verifier)
	other, _ := oidc.NewCodeVerifier()
	_, err := c.Exchange(context.Background(), code, other)
	var te *oidc.TokenError
	if !errors.As(err, &te) || te.Code != "invalid_grant" || !strings.Contains(te.Error(), "PKCE") {
		t.Fatalf("got %v", err)
	}
}

func TestExchangeRejectsBadClientSecret(t *testing.T) {
	s := idptest.Start(t, []string{redirect}, nil)
	c, err := oidc.NewClient(context.Background(), s.TS.Client(), oidc.Config{
		Issuer: s.Issuer, ClientID: "gatekeep", ClientSecret: "wrong", RedirectURL: redirect,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := oidc.NewCodeVerifier()
	code := login(t, s, c, "st", "nn", verifier)
	_, err = c.Exchange(context.Background(), code, verifier)
	var te *oidc.TokenError
	if !errors.As(err, &te) || te.Status != http.StatusUnauthorized {
		t.Fatalf("got %v", err)
	}
}

func TestDiscoveryValidation(t *testing.T) {
	cases := map[string]string{
		"issuer mismatch": `{"issuer":"https://other","authorization_endpoint":"https://a/x","token_endpoint":"https://a/t","jwks_uri":"https://a/j"}`,
		"http endpoint":   `{"issuer":"ISSUER","authorization_endpoint":"http://a/x","token_endpoint":"https://a/t","jwks_uri":"https://a/j"}`,
		"no pkce":         `{"issuer":"ISSUER","authorization_endpoint":"https://a/x","token_endpoint":"https://a/t","jwks_uri":"https://a/j","code_challenge_methods_supported":["plain"]}`,
		"bad json":        `{`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			var ts *httptest.Server
			ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.ReplaceAll(doc, "ISSUER", ts.URL)))
			}))
			defer ts.Close()
			if _, err := oidc.Discover(context.Background(), ts.Client(), ts.URL); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()
	if _, err := oidc.Discover(context.Background(), ts.Client(), ts.URL); err == nil {
		t.Fatal("404 accepted")
	}
	if _, err := oidc.NewClient(context.Background(), ts.Client(), oidc.Config{Issuer: ts.URL}); err == nil {
		t.Fatal("missing client id accepted")
	}
}

func TestJWKSRotation(t *testing.T) {
	s := idptest.Start(t, []string{redirect}, nil)
	c := newClient(t, s)
	ctx := context.Background()
	flow := func() (string, error) {
		verifier, _ := oidc.NewCodeVerifier()
		code := login(t, s, c, "st", "nn", verifier)
		tr, err := c.Exchange(ctx, code, verifier)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Verifier.Verify(ctx, tr.IDToken, "nn")
		return tr.IDToken, err
	}
	oldTok, err := flow()
	if err != nil {
		t.Fatal(err)
	}
	if c.Keys.Fetches() != 1 {
		t.Fatalf("fetches %d", c.Keys.Fetches())
	}
	// Rotate: the new kid is unknown to the cache, which must refetch once.
	if _, err := s.Keys().Rotate(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := flow(); err != nil {
		t.Fatalf("token from rotated key rejected: %v", err)
	}
	if c.Keys.Fetches() != 2 {
		t.Fatalf("fetches after rotation %d", c.Keys.Fetches())
	}
	// Old key still published (keepRetired=1): old token still verifies.
	if _, err := c.Verifier.Verify(ctx, oldTok, "nn"); err != nil {
		t.Fatalf("old token during overlap: %v", err)
	}
	// Rotate again: the original key falls out of the JWKS.
	_, _ = s.Keys().Rotate()
	time.Sleep(2 * time.Millisecond)
	if _, err := flow(); err != nil {
		t.Fatal(err)
	}
	// The refetch triggered by the newest kid replaced the cached set, so the
	// retired key is gone and tokens it signed no longer verify.
	_, err = c.Verifier.Verify(ctx, oldTok, "nn")
	if oidc.Reason(err) != "unknown_key" {
		t.Fatalf("token signed by retired key: %v", err)
	}
}

func TestKeySetRateLimitAndStaleIfError(t *testing.T) {
	signer, _ := jose.GenerateKey(jose.ES256)
	sg, _ := jose.NewSigner(signer, "k1")
	var mu sync.Mutex
	fail := false
	hits := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
		if fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write([]byte(`{"keys":[` + mustJSON(t, sg.Public()) + `]}`))
	}))
	defer ts.Close()
	clock := time.Unix(1_000_000, 0)
	var cmu sync.Mutex
	ks := oidc.NewRemoteKeySet(ts.URL, ts.Client())
	ks.Now = func() time.Time { cmu.Lock(); defer cmu.Unlock(); return clock }
	ks.MinRefreshInterval = 10 * time.Second
	ctx := context.Background()
	if _, err := ks.Key(ctx, "k1", jose.ES256); err != nil {
		t.Fatal(err)
	}
	// Within MinRefreshInterval of the last fetch, unknown kids never refetch.
	if _, err := ks.Key(ctx, "random-kid", jose.ES256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("got %v", err)
	}
	if ks.Fetches() != 1 {
		t.Fatalf("fetches = %d inside the rate-limit window", ks.Fetches())
	}
	// After the window, a flood of unknown kids triggers exactly one refetch.
	cmu.Lock()
	clock = clock.Add(11 * time.Second)
	cmu.Unlock()
	for range 50 {
		if _, err := ks.Key(ctx, "random-kid", jose.ES256); !errors.Is(err, oidc.ErrUnknownKey) {
			t.Fatalf("got %v", err)
		}
	}
	if ks.Fetches() != 2 {
		t.Fatalf("fetches = %d, want 2 (initial + one rate-limited refresh)", ks.Fetches())
	}
	// Wrong alg for a known kid is not returned.
	if _, err := ks.Key(ctx, "k1", jose.RS256); err == nil {
		t.Fatal("alg mismatch accepted")
	}
	// After expiry with the IdP down, the stale key keeps working.
	mu.Lock()
	fail = true
	mu.Unlock()
	cmu.Lock()
	clock = clock.Add(2 * time.Minute)
	cmu.Unlock()
	if _, err := ks.Key(ctx, "k1", jose.ES256); err != nil {
		t.Fatalf("stale-if-error: %v", err)
	}
	if _, err := ks.Key(ctx, "", jose.ES256); err != nil {
		t.Fatalf("empty kid with single key: %v", err)
	}
	empty := oidc.NewRemoteKeySet(ts.URL, ts.Client())
	if _, err := empty.Key(ctx, "k1", jose.ES256); err == nil {
		t.Fatal("expected fetch error with no cache")
	}
}

func TestKeySetConcurrentSingleFlight(t *testing.T) {
	sg, _ := jose.NewSigner(must(jose.GenerateKey(jose.ES256)), "k1")
	release := make(chan struct{})
	var mu sync.Mutex
	hits := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		<-release
		_, _ = w.Write([]byte(`{"keys":[` + mustJSON(t, sg.Public()) + `]}`))
	}))
	defer ts.Close()
	ks := oidc.NewRemoteKeySet(ts.URL, ts.Client())
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ks.Key(context.Background(), "k1", jose.ES256)
			errs <- err
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if hits != 1 {
		t.Fatalf("hits %d", hits)
	}
}
