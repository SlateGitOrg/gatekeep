// Package gateway is gatekeep's identity-aware reverse proxy. For every
// request it establishes who is calling (OIDC session), from what device
// (verified posture), evaluates the matched route's CEL policy, writes a
// chained audit record and, only on allow, forwards to the upstream with
// signed identity headers.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/archit2501/gatekeep/internal/audit"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/oidc"
	"github.com/archit2501/gatekeep/internal/policy"
	"github.com/archit2501/gatekeep/internal/posture"
	"github.com/archit2501/gatekeep/internal/replay"
	"github.com/archit2501/gatekeep/internal/session"
)

// reservedPrefix is gatekeep's own URL namespace; it is never proxied.
const reservedPrefix = "/.gatekeep/"

// Header names gatekeep sets on upstream requests. Any inbound header with
// the X-Gatekeep- prefix is stripped first so clients cannot spoof them.
const (
	HeaderUser      = "X-Gatekeep-User"
	HeaderEmail     = "X-Gatekeep-Email"
	HeaderGroups    = "X-Gatekeep-Groups"
	HeaderDevice    = "X-Gatekeep-Device"
	HeaderRequestID = "X-Gatekeep-Request-Id"
	HeaderAssertion = "X-Gatekeep-Assertion"
	headerPrefix    = "X-Gatekeep-"
	// AssertionType is the "typ" of upstream identity assertions.
	AssertionType = "gatekeep-identity+jwt"
)

// Authenticator is the OIDC relying-party surface the gateway needs.
type Authenticator interface {
	AuthCodeURL(state, nonce, codeVerifier string) string
	Exchange(ctx context.Context, code, codeVerifier string) (*oidc.TokenResponse, error)
	VerifyIDToken(ctx context.Context, raw, nonce string) (*oidc.IDTokenClaims, error)
	Issuer() string
}

// Options configures a Gateway. All fields without a documented default are
// required.
type Options struct {
	PublicURL     *url.URL
	Auth          Authenticator
	Cookies       *session.KeyRing
	CSRFKey       []byte // >= 32 bytes, used to derive per-session CSRF tokens
	CookieName    string // default "gatekeep"
	Lifetimes     session.Lifetimes
	LoginTTL      time.Duration // default 10m
	Router        *Router
	Posture       *posture.Verifier
	PostureStore  *posture.Store
	PostureMaxAge time.Duration // default 10m
	PairingTTL    time.Duration // default 5m
	// UpstreamSigner signs X-Gatekeep-Assertion (ES256 recommended).
	UpstreamSigner *jose.Signer
	Audit          *audit.Logger
	Headers        HeaderPolicy
	Logger         *slog.Logger
	Now            func() time.Time
	// Transport for upstream requests (default http.DefaultTransport).
	Transport http.RoundTripper
}

// Gateway is the proxy's http.Handler.
type Gateway struct {
	opts     Options
	secure   bool
	origin   string
	internal *http.ServeMux
	proxies  map[*Route]*httputil.ReverseProxy
	nonces   *replay.Cache
	revoked  *replay.Cache
}

// New validates options and builds the handler.
func New(opts Options) (*Gateway, error) {
	switch {
	case opts.PublicURL == nil || opts.PublicURL.Host == "":
		return nil, errors.New("gateway: public URL required")
	case opts.Auth == nil, opts.Cookies == nil, opts.Router == nil, opts.Audit == nil, opts.UpstreamSigner == nil:
		return nil, errors.New("gateway: auth, cookies, router, audit and upstream signer are required")
	case opts.Posture == nil || opts.PostureStore == nil:
		return nil, errors.New("gateway: posture verifier and store are required")
	case len(opts.CSRFKey) < 32:
		return nil, errors.New("gateway: CSRF key must be at least 32 bytes")
	}
	if opts.CookieName == "" {
		opts.CookieName = "gatekeep"
	}
	if opts.LoginTTL <= 0 {
		opts.LoginTTL = 10 * time.Minute
	}
	if opts.PostureMaxAge <= 0 {
		opts.PostureMaxAge = 10 * time.Minute
	}
	if opts.PairingTTL <= 0 {
		opts.PairingTTL = 5 * time.Minute
	}
	if opts.Lifetimes.Absolute <= 0 {
		opts.Lifetimes.Absolute = 8 * time.Hour
	}
	if opts.Lifetimes.TouchInterval <= 0 {
		opts.Lifetimes.TouchInterval = time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Transport == nil {
		opts.Transport = http.DefaultTransport
	}
	g := &Gateway{
		opts:    opts,
		secure:  opts.PublicURL.Scheme == "https",
		origin:  opts.PublicURL.Scheme + "://" + opts.PublicURL.Host,
		proxies: map[*Route]*httputil.ReverseProxy{},
		nonces:  replay.New(200_000, opts.Now),
		revoked: replay.New(200_000, opts.Now),
	}
	if !g.secure && !isLoopback(opts.PublicURL.Hostname()) {
		return nil, errors.New("gateway: public URL must be https (plain http is allowed only on loopback)")
	}
	for _, r := range opts.Router.Routes() {
		g.proxies[r] = g.newProxy(r)
	}
	g.internal = http.NewServeMux()
	g.internal.HandleFunc("GET /.gatekeep/login", g.handleLogin)
	g.internal.HandleFunc("GET /.gatekeep/callback", g.handleCallback)
	g.internal.HandleFunc("POST /.gatekeep/logout", g.handleLogout)
	g.internal.HandleFunc("GET /.gatekeep/me", g.handleMe)
	g.internal.HandleFunc("GET /.gatekeep/device", g.handleDevicePage)
	g.internal.HandleFunc("POST /.gatekeep/device/pair", g.handlePair)
	g.internal.HandleFunc("POST /.gatekeep/device/report", g.handleReport)
	g.internal.HandleFunc("GET /.gatekeep/jwks.json", g.handleJWKS)
	g.internal.HandleFunc("GET /.gatekeep/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	return g, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rid := newRequestID()
	sw := &statusWriter{ResponseWriter: w}
	sw.Header().Set("X-Request-Id", rid)
	r = r.WithContext(withRequestID(r.Context(), rid))
	if strings.HasPrefix(r.URL.Path, reservedPrefix) {
		g.opts.Headers.setPageHeaders(sw, g.secure)
		g.internal.ServeHTTP(sw, r)
		return
	}
	g.serveProxied(sw, r, rid)
}

// serveProxied runs the access pipeline for a non-internal request.
func (g *Gateway) serveProxied(w *statusWriter, r *http.Request, rid string) {
	start := g.opts.Now()
	ev := audit.Event{
		Kind: audit.KindAccess, RequestID: rid, Method: r.Method, Host: r.Host,
		Path: r.URL.Path, ClientIP: clientIP(r),
	}
	defer func() {
		ev.Status = w.status()
		ev.LatencyMS = float64(g.opts.Now().Sub(start).Microseconds()) / 1000
		g.audit(ev)
	}()
	deny := func(status int, reason, title, msg string) {
		ev.Decision, ev.Reason = "deny", reason
		g.opts.Headers.setPageHeaders(w, g.secure)
		g.renderError(w, r, status, title, msg, reason)
	}

	if !canonicalPath(r.URL.Path) {
		deny(http.StatusBadRequest, "non_canonical_path", "Bad request", "The request path is not canonical.")
		return
	}
	route := g.opts.Router.Match(r.Host, r.URL.Path)
	if route == nil {
		deny(http.StatusNotFound, "no_route", "Not found", "No application is configured at this address.")
		return
	}
	ev.Route = route.Name

	sess, sessReason := g.readSession(r)
	if sessReason != "" && sessReason != reasonNoSession {
		g.clearCookie(w, g.sessionCookie())
	}
	if sess != nil {
		ev.Subject, ev.Email = sess.Subject, sess.Email
	}
	if sess == nil && !route.Anonymous {
		ev.Reason = sessReason
		g.opts.Headers.setPageHeaders(w, g.secure)
		if isNavigation(r) {
			ev.Decision = "login_redirect"
			g.startLogin(w, r, r.URL.RequestURI())
			return
		}
		ev.Decision = "unauthenticated"
		w.Header().Set("WWW-Authenticate", `Cookie realm="gatekeep"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "unauthenticated", "reason": sessReason, "login": reservedPrefix + "login", "request_id": rid,
		})
		return
	}

	in := policy.Input{Request: g.requestInput(r, route)}
	var devState string
	if sess != nil {
		in.Identity = g.identityInput(sess)
		in.Device, devState, ev.DeviceID = g.deviceInput(sess)
	} else {
		devState = deviceAbsent
	}
	ev.Device = devState

	if isUnsafe(r.Method) && !route.DisableCSRF {
		if err := g.checkOrigin(r); err != nil {
			deny(http.StatusForbidden, "csrf_origin", "Request blocked", "Cross-site request rejected.")
			return
		}
	}
	if route.RequireDevice && devState != deviceFresh {
		reason := "device_required"
		if devState == deviceStale {
			reason = "posture_stale"
		}
		deny(http.StatusForbidden, reason, "Device check required",
			"This application requires a verified, up-to-date device. Pair your device at "+reservedPrefix+"device.")
		return
	}
	if route.Policy != nil {
		d := route.Policy.Evaluate(r.Context(), in)
		ev.Rule, ev.Errors, ev.PolicyCost = d.Rule, d.Errors, d.Cost
		if !d.Allowed {
			msg := "Your access request was denied by policy."
			if devState != deviceFresh {
				msg += " Your device posture is " + devState + "; pairing a compliant device at " + reservedPrefix + "device may help."
			}
			deny(http.StatusForbidden, d.Reason, "Access denied", msg)
			return
		}
		ev.Reason = d.Reason
	} else {
		ev.Reason = "anonymous_route"
	}
	ev.Decision = "allow"
	if sess != nil && sess.NeedsTouch(g.opts.Now(), g.opts.Lifetimes) {
		sess.LastSeen = g.opts.Now()
		if err := g.writeSession(w, sess); err != nil {
			g.opts.Logger.Warn("session refresh failed", "err", err)
		}
	}
	fwd := &forward{route: route, rid: rid, sess: sess, device: in.Device, devState: devState}
	g.proxies[route].ServeHTTP(w, r.WithContext(withForward(r.Context(), fwd)))
}

func (g *Gateway) audit(ev audit.Event) {
	if _, err := g.opts.Audit.Log(ev); err != nil {
		g.opts.Logger.Error("audit write failed", "err", err, "request_id", ev.RequestID)
	}
}

func (g *Gateway) identityInput(s *session.Session) policy.Identity {
	return policy.Identity{
		Authenticated: true, Subject: s.Subject, Email: s.Email, EmailVerified: s.EmailVerified,
		Name: s.Name, Groups: append([]string{}, s.Groups...), Issuer: s.Issuer,
		AuthAge: g.opts.Now().Sub(s.AuthTime),
	}
}

// requestInput exposes request attributes to policy. Cookie and
// Authorization headers are withheld: policies must not see credentials.
func (g *Gateway) requestInput(r *http.Request, route *Route) policy.Request {
	q := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			q[k] = v[0]
		}
	}
	h := map[string]string{}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if lk == "cookie" || lk == "authorization" || len(v) == 0 {
			continue
		}
		h[lk] = v[0]
	}
	return policy.Request{
		Method: r.Method, Host: strings.ToLower(r.Host), Path: r.URL.Path, Query: q, Headers: h,
		ClientIP: clientIP(r), Time: g.opts.Now().UTC(), Route: route.Name,
	}
}

// Device states recorded in the audit log.
const (
	deviceFresh  = "fresh"
	deviceStale  = "stale"
	deviceAbsent = "absent"
)

func (g *Gateway) deviceInput(s *session.Session) (policy.Device, string, string) {
	rec, ok := g.opts.PostureStore.Lookup(s.ID)
	if !ok {
		return policy.Device{}, deviceAbsent, ""
	}
	age := rec.Age(g.opts.Now())
	if age > g.opts.PostureMaxAge || age < 0 {
		return policy.Device{}, deviceStale, rec.DeviceID
	}
	f := rec.Facts
	return policy.Device{
		Present: true, ID: rec.DeviceID, OS: f.OS, OSVersion: f.OSVersion, Arch: f.Arch,
		DiskEncrypted: f.DiskEncrypted, FirewallEnabled: f.FirewallEnabled, ScreenLock: f.ScreenLock,
		PatchAgeDays: f.PatchAgeDays, Age: age,
	}, deviceFresh, rec.DeviceID
}

// canonicalPath rejects dot segments, empty segments and backslashes so a
// path can never match one route's prefix while resolving to another
// upstream resource (e.g. /public/../admin).
func canonicalPath(p string) bool {
	if p == "" || p[0] != '/' || strings.Contains(p, "\\") {
		return false
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c == p
}

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return m == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// clientIP is the TCP peer address. Forwarding headers are deliberately not
// trusted (see DECISIONS.md).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// statusWriter records the response status for the audit log.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) status() int {
	if s.code == 0 {
		return http.StatusOK
	}
	return s.code
}

// Flush supports streaming upstream responses.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
