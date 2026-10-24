package gateway

import (
	"context"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/policy"
	"github.com/archit2501/gatekeep/internal/session"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxForward
)

// forward carries the authorised request's identity into the proxy rewrite.
type forward struct {
	route    *Route
	rid      string
	sess     *session.Session
	device   policy.Device
	devState string
}

func withRequestID(ctx context.Context, rid string) context.Context {
	return context.WithValue(ctx, ctxRequestID, rid)
}

func requestID(ctx context.Context) string {
	s, _ := ctx.Value(ctxRequestID).(string)
	return s
}

func withForward(ctx context.Context, f *forward) context.Context {
	return context.WithValue(ctx, ctxForward, f)
}

// IdentityAssertion is the claim set of X-Gatekeep-Assertion. Upstreams
// verify it against /.gatekeep/jwks.json instead of trusting plain headers.
type IdentityAssertion struct {
	jose.RegisteredClaims
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	DeviceID    string   `json:"device_id,omitempty"`
	DeviceState string   `json:"device_state"`
	RequestID   string   `json:"request_id"`
}

// AssertionAudience is the audience upstreams should require for a route.
func AssertionAudience(route string) string { return "gatekeep:route:" + route }

func (g *Gateway) newProxy(route *Route) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: g.opts.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			if route.StripPrefix && route.PathPrefix != "/" {
				p := strings.TrimPrefix(pr.Out.URL.Path, strings.TrimSuffix(route.PathPrefix, "/"))
				if !strings.HasPrefix(p, "/") {
					p = "/" + p
				}
				pr.Out.URL.Path, pr.Out.URL.RawPath = p, ""
			}
			pr.SetURL(route.Upstream)
			pr.SetXForwarded()
			g.sanitizeOutbound(pr.Out.Header)
			if f, ok := pr.In.Context().Value(ctxForward).(*forward); ok {
				g.addIdentity(pr.Out, f)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			g.opts.Headers.applyUpstream(resp.Header, g.secure)
			g.stripUpstreamCookies(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.opts.Logger.Warn("upstream error", "route", route.Name, "err", err, "request_id", requestID(r.Context()))
			g.opts.Headers.setPageHeaders(w, g.secure)
			g.renderError(w, r, http.StatusBadGateway, "Upstream unavailable",
				"The application behind gatekeep did not respond.", "upstream_error")
		},
	}
}

// isIdentityHeader reports whether name is, or could be read by an upstream
// as, one of gatekeep's X-Gatekeep-* headers. The match is case-insensitive
// and treats "_" as "-", because WSGI/CGI/Rack upstreams map both
// X_Gatekeep_User and X-Gatekeep-User to HTTP_X_GATEKEEP_USER.
func isIdentityHeader(name string) bool {
	if len(name) < len(headerPrefix) {
		return false
	}
	return strings.EqualFold(strings.ReplaceAll(name[:len(headerPrefix)], "_", "-"), headerPrefix)
}

// sanitizeOutbound removes spoofable identity headers (in any spelling an
// upstream could conflate with X-Gatekeep-*) and gatekeep's own cookies so
// the session cookie never reaches an upstream.
func (g *Gateway) sanitizeOutbound(h http.Header) {
	for k := range h {
		if isIdentityHeader(k) {
			delete(h, k) // the raw key: h.Del would re-canonicalise it
		}
	}
	cookies := h.Values("Cookie")
	if len(cookies) == 0 {
		return
	}
	h.Del("Cookie")
	var kept []string
	for _, line := range cookies {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			if part == "" || g.isOwnCookie(name) {
				continue
			}
			kept = append(kept, part)
		}
	}
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

// stripUpstreamCookies drops Set-Cookie headers from an upstream that would
// overwrite or shadow gatekeep's cookies.
func (g *Gateway) stripUpstreamCookies(h http.Header) {
	sc := h.Values("Set-Cookie")
	if len(sc) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, c := range sc {
		name, _, _ := strings.Cut(c, "=")
		if !g.isOwnCookie(strings.TrimSpace(name)) {
			h.Add("Set-Cookie", c)
		}
	}
}

func (g *Gateway) isOwnCookie(name string) bool {
	base := g.opts.CookieName
	return name == g.sessionCookie() || name == g.loginCookie() ||
		strings.EqualFold(name, base) || strings.EqualFold(name, base+"-login") ||
		strings.EqualFold(name, "__Host-"+base) || strings.EqualFold(name, "__Host-"+base+"-login")
}

func (g *Gateway) addIdentity(out *http.Request, f *forward) {
	out.Header.Set(HeaderRequestID, f.rid)
	if f.sess == nil {
		return
	}
	out.Header.Set(HeaderUser, f.sess.Subject)
	if f.sess.Email != "" {
		out.Header.Set(HeaderEmail, f.sess.Email)
	}
	if len(f.sess.Groups) > 0 {
		out.Header.Set(HeaderGroups, strings.Join(f.sess.Groups, ","))
	}
	if f.device.Present {
		out.Header.Set(HeaderDevice, f.device.ID)
	}
	now := g.opts.Now()
	tok, err := g.opts.UpstreamSigner.Sign(AssertionType, IdentityAssertion{
		RegisteredClaims: jose.RegisteredClaims{
			Issuer: g.origin, Subject: f.sess.Subject, Audience: jose.Audience{AssertionAudience(f.route.Name)},
			IssuedAt: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(time.Minute)),
		},
		Email: f.sess.Email, Groups: f.sess.Groups, DeviceID: f.device.ID, DeviceState: f.devState, RequestID: f.rid,
	})
	if err != nil {
		g.opts.Logger.Error("sign upstream assertion", "err", err)
		return
	}
	out.Header.Set(HeaderAssertion, tok)
}

func (g *Gateway) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, jose.JWKSet{Keys: []jose.JWK{g.opts.UpstreamSigner.Public()}})
}
