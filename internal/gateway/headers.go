package gateway

import (
	"fmt"
	"net/http"
)

// HeaderPolicy configures response security headers.
type HeaderPolicy struct {
	// HSTSMaxAge > 0 adds Strict-Transport-Security (only over TLS).
	HSTSMaxAge int
	// HSTSIncludeSubdomains adds includeSubDomains.
	HSTSIncludeSubdomains bool
}

// pageCSP is the policy for gatekeep's own pages: no scripts at all, inline
// styles only, forms may only post back to gatekeep.
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// setPageHeaders applies the strict header set to gatekeep-generated
// responses (login redirects, error pages, device pages, JSON endpoints).
func (h HeaderPolicy) setPageHeaders(w http.ResponseWriter, tls bool) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", pageCSP)
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Pragma", "no-cache")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Cross-Origin-Opener-Policy", "same-origin")
	hd.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.setAlways(hd, tls)
}

// setAlways applies headers gatekeep enforces on every response.
func (h HeaderPolicy) setAlways(hd http.Header, tls bool) {
	hd.Set("X-Content-Type-Options", "nosniff")
	if tls && h.HSTSMaxAge > 0 {
		v := fmt.Sprintf("max-age=%d", h.HSTSMaxAge)
		if h.HSTSIncludeSubdomains {
			v += "; includeSubDomains"
		}
		hd.Set("Strict-Transport-Security", v)
	}
}

// applyUpstream hardens a proxied response: the always-on headers are
// enforced, safe defaults fill gaps the upstream left, upstream choices are
// otherwise respected, and fingerprinting headers are removed.
func (h HeaderPolicy) applyUpstream(hd http.Header, tls bool) {
	h.setAlways(hd, tls)
	setDefault(hd, "Referrer-Policy", "strict-origin-when-cross-origin")
	setDefault(hd, "Cross-Origin-Opener-Policy", "same-origin")
	setDefault(hd, "Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
	if hd.Get("X-Frame-Options") == "" && hd.Get("Content-Security-Policy") == "" {
		hd.Set("X-Frame-Options", "SAMEORIGIN")
	}
	hd.Del("X-Powered-By")
	hd.Del("Server")
}

func setDefault(hd http.Header, k, v string) {
	if hd.Get(k) == "" {
		hd.Set(k, v)
	}
}
