package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestRouterMatch(t *testing.T) {
	up := mustURL("http://127.0.0.1:1")
	rt, err := NewRouter([]*Route{
		{Name: "root", PathPrefix: "/", Upstream: up, Anonymous: true},
		{Name: "app", PathPrefix: "/app", Upstream: up, Anonymous: true},
		{Name: "app-admin", PathPrefix: "/app/admin/", Upstream: up, Anonymous: true},
		{Name: "host-app", Host: "intranet.test", PathPrefix: "/app", Upstream: up, Anonymous: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[[2]string]string{
		{"x.test", "/app"}:              "app",
		{"x.test", "/app/page"}:         "app",
		{"x.test", "/application"}:      "root",
		{"x.test", "/app/admin/users"}:  "app-admin",
		{"x.test", "/app/admin"}:        "app",
		{"intranet.test:443", "/app/x"}: "host-app",
		{"INTRANET.test", "/app"}:       "host-app",
		{"x.test", "/other"}:            "root",
	}
	for in, want := range cases {
		if got := rt.Match(in[0], in[1]); got == nil || got.Name != want {
			t.Errorf("Match(%q,%q) = %v, want %s", in[0], in[1], got, want)
		}
	}
	rt2, _ := NewRouter([]*Route{{Name: "a", PathPrefix: "/a/", Upstream: up, Anonymous: true}})
	if rt2.Match("x", "/b") != nil {
		t.Fatal("unexpected match")
	}
}

func TestRouterValidation(t *testing.T) {
	up := mustURL("http://127.0.0.1:1")
	bad := [][]*Route{
		{{PathPrefix: "/", Upstream: up, Anonymous: true}},
		{{Name: "a", PathPrefix: "/", Upstream: up, Anonymous: true}, {Name: "a", PathPrefix: "/b", Upstream: up, Anonymous: true}},
		{{Name: "a", PathPrefix: "x", Upstream: up, Anonymous: true}},
		{{Name: "a", PathPrefix: "/.gatekeep/x", Upstream: up, Anonymous: true}},
		{{Name: "a", PathPrefix: "/", Upstream: mustURL("ftp://x"), Anonymous: true}},
		{{Name: "a", PathPrefix: "/", Upstream: up}},
		{{Name: "a", PathPrefix: "/x", Upstream: up, Anonymous: true}, {Name: "b", PathPrefix: "/x", Upstream: up, Anonymous: true}},
	}
	for i, rs := range bad {
		if _, err := NewRouter(rs); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestCanonicalPath(t *testing.T) {
	ok := []string{"/", "/a", "/a/", "/a/b.txt", "/a/b/"}
	bad := []string{"", "a", "/a/../b", "/a/./b", "//a", "/a//b", "/a\\b", "/..", "/a/.."}
	for _, p := range ok {
		if !canonicalPath(p) {
			t.Errorf("%q rejected", p)
		}
	}
	for _, p := range bad {
		if canonicalPath(p) {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestSafeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/wiki/x?a=1":            "/wiki/x?a=1",
		"":                       "/",
		"//evil.test":            "/",
		"/\\evil.test":           "/",
		"https://evil.test/":     "/",
		"javascript:alert(1)":    "/",
		"/.gatekeep/logout":      "/",
		"/ok\r\nSet-Cookie: x=1": "/",
		"/a b":                   "/a%20b",
	}
	for in, want := range cases {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHeaders(t *testing.T) {
	hp := HeaderPolicy{HSTSMaxAge: 600, HSTSIncludeSubdomains: true}
	w := httptest.NewRecorder()
	hp.setPageHeaders(w, true)
	if w.Header().Get("Strict-Transport-Security") != "max-age=600; includeSubDomains" ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("%v", w.Header())
	}
	w = httptest.NewRecorder()
	hp.setPageHeaders(w, false)
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS over plain http")
	}
	up := http.Header{"X-Powered-By": {"php"}, "Server": {"apache"}, "Referrer-Policy": {"no-referrer"}}
	hp.applyUpstream(up, true)
	if up.Get("X-Powered-By") != "" || up.Get("Server") != "" || up.Get("X-Frame-Options") != "SAMEORIGIN" ||
		up.Get("Referrer-Policy") != "no-referrer" || up.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%v", up)
	}
	up = http.Header{"Content-Security-Policy": {"frame-ancestors 'self' https://x"}}
	hp.applyUpstream(up, true)
	if up.Get("X-Frame-Options") != "" {
		t.Fatal("XFO added despite upstream CSP")
	}
}

func testGateway(t *testing.T) *Gateway {
	t.Helper()
	return &Gateway{opts: Options{CookieName: "gatekeep", CSRFKey: make([]byte, 32)}, secure: true, origin: "https://gk.test"}
}

func TestCheckOrigin(t *testing.T) {
	g := testGateway(t)
	cases := []struct {
		hdr map[string]string
		ok  bool
	}{
		{map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
		{map[string]string{"Sec-Fetch-Site": "none"}, true},
		{map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://gk.test"}, false},
		{map[string]string{"Origin": "https://gk.test"}, true},
		{map[string]string{"Origin": "https://gk.test.evil"}, false},
		{map[string]string{"Origin": "null"}, false},
		{map[string]string{"Referer": "https://gk.test/a"}, true},
		{map[string]string{"Referer": "https://gk.test.evil/a"}, false},
		{map[string]string{"Referer": "::"}, false},
		{nil, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "https://gk.test/x", nil)
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		if got := g.checkOrigin(r) == nil; got != c.ok {
			t.Errorf("%v: ok=%v want %v", c.hdr, got, c.ok)
		}
	}
	tok := g.csrfToken("sid-1")
	if !g.validCSRFToken("sid-1", tok) || g.validCSRFToken("sid-2", tok) || g.validCSRFToken("sid-1", "") {
		t.Fatal("csrf token binding")
	}
}

func TestSanitizeOutbound(t *testing.T) {
	g := testGateway(t)
	h := http.Header{}
	h.Set("X-Gatekeep-User", "admin")
	h.Set("x-gatekeep-assertion", "forged")
	h.Add("Cookie", "__Host-gatekeep=secret; app=1")
	h.Add("Cookie", "__Host-gatekeep-login=s2; other=2; gatekeep=legacy")
	g.sanitizeOutbound(h)
	if h.Get("X-Gatekeep-User") != "" || h.Get("X-Gatekeep-Assertion") != "" {
		t.Fatalf("spoofable headers kept: %v", h)
	}
	if got := h.Get("Cookie"); got != "app=1; other=2" {
		t.Fatalf("cookie = %q", got)
	}
	h = http.Header{"Cookie": {"__Host-gatekeep=x"}}
	g.sanitizeOutbound(h)
	if _, ok := h["Cookie"]; ok {
		t.Fatal("empty cookie header kept")
	}
	resp := http.Header{"Set-Cookie": {"__Host-gatekeep=evil; Path=/", "app=1", "gatekeep-login=x"}}
	g.stripUpstreamCookies(resp)
	if v := resp.Values("Set-Cookie"); len(v) != 1 || v[0] != "app=1" {
		t.Fatalf("set-cookie %v", v)
	}
}

func TestNavigationAndUnsafe(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept", "text/html")
	if !isNavigation(r) {
		t.Fatal("html GET")
	}
	r.Header.Set("Sec-Fetch-Mode", "cors")
	if isNavigation(r) {
		t.Fatal("fetch() is not navigation")
	}
	if isNavigation(httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatal("POST")
	}
	for m, want := range map[string]bool{"GET": false, "HEAD": false, "OPTIONS": false, "POST": true, "PUT": true, "DELETE": true, "PATCH": true} {
		if isUnsafe(m) != want {
			t.Errorf("%s", m)
		}
	}
	if !isLoopback("localhost") || !isLoopback("127.0.0.2") || !isLoopback("::1") || isLoopback("10.0.0.1") || isLoopback("example.test") {
		t.Fatal("isLoopback")
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "garbage"
	if clientIP(r) != "garbage" {
		t.Fatal("clientIP fallback")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("empty options")
	}
	if _, err := New(Options{PublicURL: mustURL("https://gk.test")}); err == nil {
		t.Fatal("missing deps")
	}
}

func TestStatusWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}
	if sw.status() != 200 {
		t.Fatal("default")
	}
	_, _ = sw.Write([]byte("x"))
	sw.WriteHeader(http.StatusInternalServerError) // ignored after body
	sw.Flush()
	if sw.status() != 200 || sw.Unwrap() != rec {
		t.Fatal("status writer")
	}
}
