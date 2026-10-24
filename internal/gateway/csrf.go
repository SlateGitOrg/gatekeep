package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
)

// CSRF defence is layered:
//
//  1. Cookies are SameSite=Lax, so cross-site sub-requests carry no session.
//  2. Every unsafe request (proxied or internal) must prove same-origin via
//     Sec-Fetch-Site, else Origin, else Referer. A request carrying none of
//     them is rejected: browsers send at least one on unsafe methods.
//  3. Gatekeep's own state-changing endpoints (logout, device pairing)
//     additionally require a synchronizer token bound to the session:
//     base64url(HMAC-SHA256(csrfKey, "csrf:" || sid)).
//  4. The OIDC callback is protected by the sealed, single-use login state.

var errCrossOrigin = errors.New("gateway: cross-origin request")

func (g *Gateway) checkOrigin(r *http.Request) error {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return nil
	case "":
	default: // same-site, cross-site
		return errCrossOrigin
	}
	if o := r.Header.Get("Origin"); o != "" {
		if o == g.origin {
			return nil
		}
		return errCrossOrigin
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		if err == nil && u.Scheme+"://"+u.Host == g.origin {
			return nil
		}
	}
	return errCrossOrigin
}

func (g *Gateway) csrfToken(sid string) string {
	m := hmac.New(sha256.New, g.opts.CSRFKey)
	m.Write([]byte("csrf:" + sid))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (g *Gateway) validCSRFToken(sid, tok string) bool {
	return tok != "" && hmac.Equal([]byte(tok), []byte(g.csrfToken(sid)))
}

// requireCSRF enforces origin + token for gatekeep's internal POST endpoints.
func (g *Gateway) requireCSRF(r *http.Request, sid string) error {
	if err := g.checkOrigin(r); err != nil {
		return err
	}
	tok := r.Header.Get("X-CSRF-Token")
	if tok == "" {
		tok = r.PostFormValue("csrf")
	}
	if !g.validCSRFToken(sid, tok) {
		return errors.New("gateway: missing or invalid CSRF token")
	}
	return nil
}
