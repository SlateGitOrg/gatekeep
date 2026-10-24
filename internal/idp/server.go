// Package idp is a deliberately minimal OpenID Connect provider used by
// gatekeep's tests and offline demo. It supports exactly one flow —
// authorization code with mandatory PKCE S256 and client_secret_basic — and
// signs ID tokens with a rotating key ring. It is a test fixture with honest
// security properties (one-time codes, constant-time secret checks, login
// throttling), not a production identity provider.
package idp

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/oidc"
)

// Client is a registered relying party.
type Client struct {
	ID           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

// User is a local account.
type User struct {
	Username      string   `yaml:"username"`
	PasswordHash  string   `yaml:"password_hash"`
	Subject       string   `yaml:"subject"`
	Email         string   `yaml:"email"`
	EmailVerified bool     `yaml:"email_verified"`
	Name          string   `yaml:"name"`
	Groups        []string `yaml:"groups"`
}

// Options configures the provider.
type Options struct {
	Issuer      string
	Clients     []Client
	Users       []User
	Keys        *KeyRing
	TokenTTL    time.Duration
	CodeTTL     time.Duration
	Now         func() time.Time
	Logger      *slog.Logger
	MaxFailures int           // failed logins per user before lockout
	Lockout     time.Duration // lockout duration
	// MutateIDToken, when set, may rewrite ID-token claims just before
	// signing. Tests use it to simulate a misbehaving or compromised IdP
	// (expired tokens, wrong audience, reused nonce). Never set in serve mode.
	MutateIDToken func(claims *oidc.IDTokenClaims)
}

// Server is the provider's HTTP handler.
type Server struct {
	opts Options
	mux  *http.ServeMux

	mu       sync.Mutex
	dummy    string // hash compared for unknown users (timing equalisation)
	pending  map[string]*authRequest
	codes    map[string]*grant
	failures map[string]*failure
}

type authRequest struct {
	ClientID    string
	RedirectURI string
	State       string
	Nonce       string
	Challenge   string
	Expires     time.Time
}

type grant struct {
	ClientID    string
	RedirectURI string
	Nonce       string
	Challenge   string
	User        *User
	AuthTime    time.Time
	Expires     time.Time
	Used        bool
}

type failure struct {
	count       int
	lockedUntil time.Time
}

//go:embed login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// New validates options and returns a provider.
func New(opts Options) (*Server, error) {
	if opts.Issuer == "" || opts.Keys == nil {
		return nil, errors.New("idp: issuer and keys are required")
	}
	if opts.TokenTTL <= 0 {
		opts.TokenTTL = 5 * time.Minute
	}
	if opts.CodeTTL <= 0 {
		opts.CodeTTL = time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.MaxFailures <= 0 {
		opts.MaxFailures = 5
	}
	if opts.Lockout <= 0 {
		opts.Lockout = time.Minute
	}
	iterations := DefaultPBKDF2Iterations
	for _, u := range opts.Users {
		if u.Subject == "" || u.Username == "" {
			return nil, errors.New("idp: every user needs username and subject")
		}
		if n, ok := hashIterations(u.PasswordHash); ok {
			iterations = n
		}
	}
	randomPassword, err := oidc.NewState()
	if err != nil {
		return nil, err
	}
	dummy, err := HashPassword(randomPassword, iterations)
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:     opts,
		dummy:    dummy,
		mux:      http.NewServeMux(),
		pending:  map[string]*authRequest{},
		codes:    map[string]*grant{},
		failures: map[string]*failure{},
	}
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	s.mux.HandleFunc("GET /jwks", s.jwks)
	s.mux.HandleFunc("GET /authorize", s.authorize)
	s.mux.HandleFunc("POST /login", s.login)
	s.mux.HandleFunc("POST /token", s.token)
	return s, nil
}

// ServeHTTP implements http.Handler with baseline security headers.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	s.mux.ServeHTTP(w, r)
}

// Keys exposes the key ring (for rotation in tests and the demo).
func (s *Server) Keys() *KeyRing { return s.opts.Keys }

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.opts.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"jwks_uri":                              iss + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{string(s.opts.Keys.Active().Public().Algorithm())},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
		"grant_types_supported":                 []string{"authorization_code"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	b, err := json.Marshal(s.opts.Keys.JWKS())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (s *Server) client(id string) *Client {
	for i := range s.opts.Clients {
		if s.opts.Clients[i].ID == id {
			return &s.opts.Clients[i]
		}
	}
	return nil
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c := s.client(q.Get("client_id"))
	redirect := q.Get("redirect_uri")
	// Never redirect to an unregistered URI: show the error locally instead
	// (RFC 6749 §4.1.2.1), otherwise the IdP becomes an open redirector.
	if c == nil || !slices.Contains(c.RedirectURIs, redirect) {
		http.Error(w, "unknown client or unregistered redirect_uri", http.StatusBadRequest)
		return
	}
	fail := func(code, desc string) {
		v := url.Values{"error": {code}, "error_description": {desc}}
		if st := q.Get("state"); st != "" {
			v.Set("state", st)
		}
		// redirect is an exact match against the client's registered URIs.
		http.Redirect(w, r, redirect+"?"+v.Encode(), http.StatusFound) //nolint:gosec // validated above
	}
	switch {
	case q.Get("response_type") != "code":
		fail("unsupported_response_type", "only code is supported")
		return
	case !slices.Contains(strings.Fields(q.Get("scope")), "openid"):
		fail("invalid_scope", "openid scope required")
		return
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43:
		fail("invalid_request", "PKCE S256 code_challenge required")
		return
	case q.Get("nonce") == "":
		fail("invalid_request", "nonce required")
		return
	}
	id, err := oidc.NewState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.gc()
	s.pending[id] = &authRequest{
		ClientID: c.ID, RedirectURI: redirect, State: q.Get("state"), Nonce: q.Get("nonce"),
		Challenge: q.Get("code_challenge"),
		Expires:   s.opts.Now().Add(10 * time.Minute),
	}
	s.mu.Unlock()
	s.renderLogin(w, id, c.ID, "", http.StatusOK)
}

func (s *Server) renderLogin(w http.ResponseWriter, reqID, client, msg string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginTmpl.Execute(w, map[string]string{"Req": reqID, "Client": client, "Error": msg, "Issuer": s.opts.Issuer})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	reqID := r.PostForm.Get("req")
	username := r.PostForm.Get("username")
	now := s.opts.Now()

	s.mu.Lock()
	ar, ok := s.pending[reqID]
	if !ok || now.After(ar.Expires) {
		s.mu.Unlock()
		http.Error(w, "login request expired; restart sign-in", http.StatusBadRequest)
		return
	}
	if f := s.failures[username]; f != nil && now.Before(f.lockedUntil) {
		s.mu.Unlock()
		s.opts.Logger.Warn("idp login locked out", "username", username)
		s.renderLogin(w, reqID, ar.ClientID, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	s.mu.Unlock()

	user := s.authenticate(username, r.PostForm.Get("password"))

	s.mu.Lock()
	defer s.mu.Unlock()
	if user == nil {
		f := s.failures[username]
		if f == nil {
			f = &failure{}
			s.failures[username] = f
		}
		f.count++
		if f.count >= s.opts.MaxFailures {
			f.lockedUntil = now.Add(s.opts.Lockout)
			f.count = 0
		}
		s.opts.Logger.Info("idp login failed", "username", username)
		s.renderLogin(w, reqID, ar.ClientID, "Invalid username or password.", http.StatusUnauthorized)
		return
	}
	delete(s.failures, username)
	delete(s.pending, reqID)
	code, err := oidc.NewState()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.codes[hashCode(code)] = &grant{
		ClientID: ar.ClientID, RedirectURI: ar.RedirectURI, Nonce: ar.Nonce, Challenge: ar.Challenge,
		User: user, AuthTime: now, Expires: now.Add(s.opts.CodeTTL),
	}
	s.opts.Logger.Info("idp login ok", "sub", user.Subject, "client", ar.ClientID)
	v := url.Values{"code": {code}}
	if ar.State != "" {
		v.Set("state", ar.State)
	}
	http.Redirect(w, r, ar.RedirectURI+"?"+v.Encode(), http.StatusFound)
}

// authenticate checks credentials; it always runs a hash to avoid a
// username-enumeration timing oracle.
func (s *Server) authenticate(username, password string) *User {
	var match *User
	hash := s.dummy
	for i := range s.opts.Users {
		if s.opts.Users[i].Username == username {
			match = &s.opts.Users[i]
			hash = match.PasswordHash
		}
	}
	ok, err := CheckPassword(hash, password)
	if err != nil || !ok || match == nil {
		return nil
	}
	return match
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	}
	c := s.client(id)
	if !ok || c == nil || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	now := s.opts.Now()
	s.mu.Lock()
	g, found := s.codes[hashCode(r.PostForm.Get("code"))]
	var reuse bool
	if found {
		reuse = g.Used
		g.Used = true
	}
	s.mu.Unlock()
	switch {
	case !found || now.After(g.Expires):
		tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
		return
	case reuse:
		s.opts.Logger.Warn("idp authorization code replay", "client", id)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "code already used")
		return
	case g.ClientID != c.ID || g.RedirectURI != r.PostForm.Get("redirect_uri"):
		tokenError(w, http.StatusBadRequest, "invalid_grant", "client or redirect_uri mismatch")
		return
	}
	verifier := r.PostForm.Get("code_verifier")
	if !oidc.ValidVerifier(verifier) ||
		subtle.ConstantTimeCompare([]byte(oidc.CodeChallengeS256(verifier)), []byte(g.Challenge)) != 1 {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	claims := oidc.IDTokenClaims{
		RegisteredClaims: jose.RegisteredClaims{
			Issuer: s.opts.Issuer, Subject: g.User.Subject, Audience: jose.Audience{c.ID},
			IssuedAt: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(s.opts.TokenTTL)),
		},
		Nonce: g.Nonce, AuthTime: jose.NewNumericDate(g.AuthTime), AZP: c.ID,
		Email: g.User.Email, EmailVerified: g.User.EmailVerified, Name: g.User.Name, Groups: g.User.Groups,
	}
	if s.opts.MutateIDToken != nil {
		s.opts.MutateIDToken(&claims)
	}
	idt, err := s.opts.Keys.Active().Sign("JWT", claims)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	at, err := oidc.NewState()
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": at, "token_type": "Bearer",
		"expires_in": int(s.opts.TokenTTL.Seconds()), "id_token": idt,
	})
}

// gc drops expired pending requests and codes. Caller holds s.mu.
func (s *Server) gc() {
	now := s.opts.Now()
	for k, v := range s.pending {
		if now.After(v.Expires) {
			delete(s.pending, k)
		}
	}
	for k, v := range s.codes {
		if now.After(v.Expires.Add(time.Minute)) {
			delete(s.codes, k)
		}
	}
}

// Codes are stored hashed so a memory dump does not yield redeemable codes.
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return string(sum[:])
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
