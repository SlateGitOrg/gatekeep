package gateway

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/archit2501/gatekeep/internal/audit"
	"github.com/archit2501/gatekeep/internal/oidc"
	"github.com/archit2501/gatekeep/internal/session"
)

// Session read outcomes (audit reason codes).
const (
	reasonNoSession      = "no_session"
	reasonSessionInvalid = "session_invalid"
	reasonSessionExpired = "session_expired"
	reasonSessionIdle    = "session_idle"
	reasonSessionRevoked = "session_revoked"
	reasonWrongIssuer    = "session_wrong_issuer"
)

// AAD purposes binding each sealed cookie to its role.
const (
	aadSession = "gatekeep/session/v1"
	aadLogin   = "gatekeep/login/v1"
)

func (g *Gateway) sessionCookie() string { return g.cookiePrefix() + g.opts.CookieName }
func (g *Gateway) loginCookie() string   { return g.cookiePrefix() + g.opts.CookieName + "-login" }

// cookiePrefix uses __Host- over TLS: the browser then enforces Secure,
// Path=/ and no Domain attribute, so a sibling subdomain cannot plant or
// overwrite gatekeep's cookies.
func (g *Gateway) cookiePrefix() string {
	if g.secure {
		return "__Host-"
	}
	return ""
}

func (g *Gateway) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: g.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func (g *Gateway) clearCookie(w http.ResponseWriter, name string) { g.setCookie(w, name, "", -1) }

// readSession decodes and validates the session cookie. It returns a reason
// code when there is no usable session.
func (g *Gateway) readSession(r *http.Request) (*session.Session, string) {
	c, err := r.Cookie(g.sessionCookie())
	if err != nil || c.Value == "" {
		return nil, reasonNoSession
	}
	var s session.Session
	if err := g.opts.Cookies.Open(aadSession, c.Value, &s); err != nil {
		return nil, reasonSessionInvalid
	}
	switch err := s.Check(g.opts.Now(), g.opts.Lifetimes); {
	case errors.Is(err, session.ErrExpired):
		return nil, reasonSessionExpired
	case errors.Is(err, session.ErrIdle):
		return nil, reasonSessionIdle
	}
	if s.Issuer != g.opts.Auth.Issuer() {
		return nil, reasonWrongIssuer
	}
	if g.revoked.Seen(s.ID) {
		return nil, reasonSessionRevoked
	}
	return &s, ""
}

func (g *Gateway) writeSession(w http.ResponseWriter, s *session.Session) error {
	v, err := g.opts.Cookies.Seal(aadSession, s)
	if err != nil {
		return err
	}
	maxAge := int(s.ExpiresAt.Sub(g.opts.Now()).Seconds())
	g.setCookie(w, g.sessionCookie(), v, max(maxAge, 1))
	return nil
}

// startLogin seals a fresh login state into a short-lived cookie and
// redirects to the IdP.
func (g *Gateway) startLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	state, err1 := oidc.NewState()
	nonce, err2 := oidc.NewNonce()
	verifier, err3 := oidc.NewCodeVerifier()
	if err := errors.Join(err1, err2, err3); err != nil {
		g.renderError(w, r, http.StatusInternalServerError, "Sign-in unavailable", "Could not start sign-in.", "internal_error")
		return
	}
	ls := session.LoginState{
		State: state, Nonce: nonce, CodeVerifier: verifier,
		ReturnTo: safeReturnTo(returnTo), CreatedAt: g.opts.Now(),
	}
	v, err := g.opts.Cookies.Seal(aadLogin, ls)
	if err != nil {
		g.renderError(w, r, http.StatusInternalServerError, "Sign-in unavailable", "Could not start sign-in.", "internal_error")
		return
	}
	g.setCookie(w, g.loginCookie(), v, int(g.opts.LoginTTL.Seconds()))
	http.Redirect(w, r, g.opts.Auth.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

// safeReturnTo only allows local absolute paths, preventing open redirects
// via //evil.example, /\evil.example or absolute URLs.
func safeReturnTo(rt string) string {
	if rt == "" || rt[0] != '/' || strings.HasPrefix(rt, "//") || strings.HasPrefix(rt, "/\\") ||
		strings.HasPrefix(rt, reservedPrefix) || strings.ContainsAny(rt, "\r\n\t") {
		return "/"
	}
	u, err := url.Parse(rt)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	return u.RequestURI()
}

func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	g.startLogin(w, r, r.URL.Query().Get("rd"))
}

func (g *Gateway) handleCallback(w http.ResponseWriter, r *http.Request) {
	ev := audit.Event{
		Kind: audit.KindLogin, RequestID: requestID(r.Context()), Method: r.Method, Host: r.Host,
		Path: r.URL.Path, ClientIP: clientIP(r), Decision: "fail",
	}
	retry := reservedPrefix + "login"
	fail := func(status int, reason, msg string) {
		ev.Reason, ev.Status = reason, status
		g.audit(ev)
		g.clearCookie(w, g.loginCookie())
		g.renderErrorLink(w, r, status, "Sign-in failed", msg, reason, retry, "Try signing in again")
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail(http.StatusUnauthorized, "idp_error", "The identity provider returned an error: "+e)
		return
	}
	c, err := r.Cookie(g.loginCookie())
	if err != nil {
		fail(http.StatusBadRequest, "login_state_missing", "No sign-in is in progress in this browser.")
		return
	}
	var ls session.LoginState
	if err := g.opts.Cookies.Open(aadLogin, c.Value, &ls); err != nil {
		fail(http.StatusBadRequest, "login_state_invalid", "The sign-in state was invalid.")
		return
	}
	retry += "?rd=" + url.QueryEscape(ls.ReturnTo)
	if g.opts.Now().Sub(ls.CreatedAt) > g.opts.LoginTTL {
		fail(http.StatusBadRequest, "login_state_expired", "The sign-in took too long.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(ls.State)) != 1 {
		fail(http.StatusBadRequest, "state_mismatch", "The sign-in response did not match this browser.")
		return
	}
	// A nonce is consumed exactly once. Checking before the code exchange
	// stops a replayed callback without contacting the IdP.
	if g.nonces.Seen("nonce:" + ls.Nonce) {
		fail(http.StatusBadRequest, "nonce_replayed", "This sign-in response was already used.")
		return
	}
	code := q.Get("code")
	if code == "" {
		fail(http.StatusBadRequest, "missing_code", "The sign-in response had no authorization code.")
		return
	}
	tr, err := g.opts.Auth.Exchange(r.Context(), code, ls.CodeVerifier)
	if err != nil {
		g.opts.Logger.Warn("code exchange failed", "err", err)
		fail(http.StatusBadGateway, "token_exchange_failed", "The identity provider rejected the sign-in.")
		return
	}
	claims, err := g.opts.Auth.VerifyIDToken(r.Context(), tr.IDToken, ls.Nonce)
	if err != nil {
		g.opts.Logger.Warn("id token rejected", "err", err)
		fail(http.StatusUnauthorized, oidc.Reason(err), "The identity token was rejected.")
		return
	}
	ev.Subject, ev.Email = claims.Subject, claims.Email
	if err := g.nonces.Use("nonce:"+ls.Nonce, claims.Expiry.Time().Add(g.opts.LoginTTL)); err != nil {
		fail(http.StatusBadRequest, "nonce_replayed", "This sign-in response was already used.")
		return
	}
	sid, err := session.RandomID()
	if err != nil {
		fail(http.StatusInternalServerError, "internal_error", "Could not create a session.")
		return
	}
	now := g.opts.Now()
	authTime := now
	if claims.AuthTime != nil {
		authTime = claims.AuthTime.Time()
	}
	s := &session.Session{
		ID: sid, Subject: claims.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified,
		Name: claims.Name, Groups: claims.Groups, Issuer: claims.Issuer,
		AuthTime: authTime, IssuedAt: now, LastSeen: now, ExpiresAt: now.Add(g.opts.Lifetimes.Absolute),
	}
	if err := g.writeSession(w, s); err != nil {
		fail(http.StatusInternalServerError, "session_too_large", "The session could not be stored (too many groups?).")
		return
	}
	g.clearCookie(w, g.loginCookie())
	ev.Decision, ev.Reason, ev.Status = "ok", "login_success", http.StatusFound
	g.audit(ev)
	http.Redirect(w, r, ls.ReturnTo, http.StatusFound)
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	s, reason := g.readSession(r)
	ev := audit.Event{
		Kind: audit.KindLogout, RequestID: requestID(r.Context()), Method: r.Method, Host: r.Host,
		Path: r.URL.Path, ClientIP: clientIP(r), Decision: "fail", Reason: reason,
	}
	if s == nil {
		g.clearCookie(w, g.sessionCookie())
		ev.Status = http.StatusUnauthorized
		g.audit(ev)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	ev.Subject, ev.Email = s.Subject, s.Email
	if err := g.requireCSRF(r, s.ID); err != nil {
		ev.Reason, ev.Status = "csrf", http.StatusForbidden
		g.audit(ev)
		g.renderError(w, r, http.StatusForbidden, "Request blocked", "Missing or invalid CSRF token.", "csrf")
		return
	}
	// Cookies are stateless, so logout records the session ID as revoked
	// until the session would have expired anyway.
	if err := g.revoked.Use(s.ID, s.ExpiresAt); err != nil {
		g.opts.Logger.Warn("revocation cache", "err", err)
	}
	g.opts.PostureStore.Revoke(s.ID)
	g.clearCookie(w, g.sessionCookie())
	ev.Decision, ev.Reason, ev.Status = "ok", "logout", http.StatusOK
	g.audit(ev)
	g.renderPage(w, http.StatusOK, pageData{Title: "Signed out", Message: "You have been signed out of gatekeep."})
}

// meResponse is the JSON shape of /.gatekeep/me.
type meResponse struct {
	Subject   string     `json:"sub"`
	Email     string     `json:"email,omitempty"`
	Name      string     `json:"name,omitempty"`
	Groups    []string   `json:"groups,omitempty"`
	ExpiresAt string     `json:"expires_at"`
	CSRFToken string     `json:"csrf_token"`
	Device    deviceInfo `json:"device"`
}

type deviceInfo struct {
	State      string `json:"state"`
	ID         string `json:"id,omitempty"`
	AgeSeconds int    `json:"age_seconds,omitempty"`
}

func (g *Gateway) handleMe(w http.ResponseWriter, r *http.Request) {
	s, reason := g.readSession(r)
	if s == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated", "reason": reason})
		return
	}
	writeJSON(w, http.StatusOK, meResponse{
		Subject: s.Subject, Email: s.Email, Name: s.Name, Groups: s.Groups,
		ExpiresAt: s.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		CSRFToken: g.csrfToken(s.ID), Device: g.deviceInfo(s),
	})
}

func (g *Gateway) deviceInfo(s *session.Session) deviceInfo {
	d, state, id := g.deviceInput(s)
	return deviceInfo{State: state, ID: id, AgeSeconds: int(d.Age.Seconds())}
}
