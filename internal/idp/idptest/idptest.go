// Package idptest starts the demo identity provider on an httptest TLS
// server and drives its login form, for use in tests.
package idptest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/archit2501/gatekeep/internal/idp"
	"github.com/archit2501/gatekeep/internal/jose"
)

// TestIterations keeps PBKDF2 cheap in tests.
const TestIterations = 1000

// Users returns two demo users with password "password-<username>".
func Users(t testing.TB) []idp.User {
	t.Helper()
	mk := func(username, sub, email string, groups ...string) idp.User {
		h, err := idp.HashPassword("password-"+username, TestIterations)
		if err != nil {
			t.Fatal(err)
		}
		return idp.User{Username: username, PasswordHash: h, Subject: sub, Email: email,
			EmailVerified: true, Name: username, Groups: groups}
	}
	return []idp.User{
		mk("alice", "user-alice", "alice@example.test", "eng", "admins"),
		mk("bob", "user-bob", "bob@example.test", "eng"),
	}
}

// Server is a running test IdP.
type Server struct {
	*idp.Server
	TS     *httptest.Server
	Issuer string
}

// Start runs an IdP. configure may adjust options (issuer and keys are
// pre-filled); clients default to one "gatekeep"/"s3cret" client allowing
// redirectURIs.
func Start(t testing.TB, redirectURIs []string, configure func(*idp.Options)) *Server {
	t.Helper()
	h := http.NotFoundHandler()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	keys, err := idp.NewKeyRing(jose.ES256, 1)
	if err != nil {
		t.Fatal(err)
	}
	opts := idp.Options{
		Issuer:  ts.URL,
		Keys:    keys,
		Users:   Users(t),
		Clients: []idp.Client{{ID: "gatekeep", Secret: "s3cret", RedirectURIs: redirectURIs}},
	}
	if configure != nil {
		configure(&opts)
	}
	srv, err := idp.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h = srv
	return &Server{Server: srv, TS: ts, Issuer: ts.URL}
}

var reqField = regexp.MustCompile(`name="req" value="([^"]+)"`)

// ErrLoginFailed is returned when the IdP re-renders the form.
var ErrLoginFailed = errors.New("idptest: login rejected")

// Login fetches authURL (the IdP authorize URL), submits credentials and
// returns the redirect target the IdP sends the browser to. hc must not
// follow redirects automatically.
func Login(hc *http.Client, authURL, username, password string) (*url.URL, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		return resp.Location()
	}
	m := reqField.FindSubmatch(body)
	if m == nil {
		return nil, fmt.Errorf("idptest: no login form (status %d): %s", resp.StatusCode, body)
	}
	au, _ := url.Parse(authURL)
	loginURL := au.ResolveReference(&url.URL{Path: "login"})
	form := url.Values{"req": {string(m[1])}, "username": {username}, "password": {password}}
	req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, loginURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = hc.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("%w: status %d", ErrLoginFailed, resp.StatusCode)
	}
	return resp.Location()
}

// NoRedirect returns a copy of hc that does not follow redirects.
func NoRedirect(hc *http.Client) *http.Client {
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}
