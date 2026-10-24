package e2e

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/archit2501/gatekeep/internal/audit"
	"github.com/archit2501/gatekeep/internal/idp/idptest"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/oidc"
	"github.com/archit2501/gatekeep/internal/posture"
)

const sessionCookie = "__Host-gatekeep"

func TestFullRedirectFlow(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	resp := e.login(b, "/wiki/page?x=1", "alice")
	if resp.Status != http.StatusOK {
		t.Fatalf("final status %d\n%s", resp.Status, hopsString(resp.Hops))
	}
	// The exact redirect choreography of the authorization-code flow.
	h := resp.Hops
	if len(h) != 5 {
		t.Fatalf("expected 5 hops, got:\n%s", hopsString(h))
	}
	authz, _ := url.Parse(h[0].Location)
	q := authz.Query()
	switch {
	case h[0].Status != http.StatusFound || !strings.HasPrefix(h[0].Location, e.st.IdPURL+"/authorize"):
		t.Fatalf("hop0 %s", h[0])
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("nonce") == "" || q.Get("state") == "":
		t.Fatalf("authorize request lacks PKCE/nonce/state: %s", authz)
	case q.Get("redirect_uri") != e.url("/.gatekeep/callback"):
		t.Fatalf("redirect_uri %s", q.Get("redirect_uri"))
	case h[1].Status != http.StatusOK: // login form
		t.Fatalf("hop1 %s", h[1])
	case h[2].Method != http.MethodPost || h[2].Status != http.StatusFound || !strings.HasPrefix(h[2].Location, e.url("/.gatekeep/callback?")):
		t.Fatalf("hop2 %s", h[2])
	case h[3].Status != http.StatusFound || h[3].Location != "/wiki/page?x=1":
		t.Fatalf("hop3 %s", h[3])
	}
	// Login cookie on hop 0; session cookie set and login cookie cleared on callback.
	if !hasCookie(h[0].SetCookies, "__Host-gatekeep-login=", "Secure", "HttpOnly", "SameSite=Lax", "Path=/") {
		t.Fatalf("login cookie attrs: %v", h[0].SetCookies)
	}
	if !hasCookie(h[3].SetCookies, sessionCookie+"=", "Secure", "HttpOnly", "SameSite=Lax", "Path=/") ||
		!hasCookie(h[3].SetCookies, "__Host-gatekeep-login=;", "Max-Age=0") {
		t.Fatalf("callback cookies: %v", h[3].SetCookies)
	}
	w := whoami(t, resp)
	if w.Subject != "user-alice" || w.Email != "alice@example.test" || w.Audience != "gatekeep:route:wiki" ||
		w.Path != "/wiki/page" || !slices.Contains(w.Groups, "admins") {
		t.Fatalf("upstream saw %+v", w)
	}
	if slices.Contains(w.CookiesSeen, sessionCookie) {
		t.Fatal("session cookie leaked to upstream")
	}
	// Security headers on the proxied response.
	hd := resp.Header
	if hd.Get("Strict-Transport-Security") == "" || hd.Get("X-Content-Type-Options") != "nosniff" ||
		hd.Get("X-Frame-Options") != "SAMEORIGIN" || hd.Get("X-Powered-By") != "" || hd.Get("X-Request-Id") == "" {
		t.Fatalf("proxied headers: %v", hd)
	}
	ev := e.expectAudit(audit.KindLogin, "login_success")
	if ev.Subject != "user-alice" {
		t.Fatalf("%+v", ev)
	}
	allow := e.expectAudit(audit.KindAccess, "allowed_by_rule")
	if allow.Rule != "employees" || allow.Route != "wiki" || allow.Status != 200 || allow.Device != "absent" {
		t.Fatalf("%+v", allow)
	}
	redirect := e.events(nil)[0]
	if redirect.Decision != "login_redirect" || redirect.Reason != "no_session" {
		t.Fatalf("first event %+v", redirect)
	}
	// A second request rides on the session: no redirects.
	r2, err := b.Navigate(e.url("/wiki/other"))
	if err != nil || r2.Status != 200 || len(r2.Hops) != 1 {
		t.Fatalf("second request: %v %d", err, r2.Status)
	}
}

func hasCookie(set []string, prefix string, attrs ...string) bool {
	for _, c := range set {
		if !strings.HasPrefix(c, prefix) {
			continue
		}
		ok := true
		for _, a := range attrs {
			ok = ok && strings.Contains(c, a)
		}
		if ok {
			return true
		}
	}
	return false
}

func TestGatekeepPageHeaders(t *testing.T) {
	e := newEnv(t, nil)
	st, _, hd := e.api(e.browser(), http.MethodGet, "/.gatekeep/me", nil, nil)
	if st != http.StatusUnauthorized {
		t.Fatalf("me without session: %d", st)
	}
	for k, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
		"Referrer-Policy": "no-referrer", "Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff",
	} {
		if !strings.Contains(hd.Get(k), want) {
			t.Errorf("%s = %q, want %q", k, hd.Get(k), want)
		}
	}
	st, _, _ = e.api(e.browser(), http.MethodGet, "/.gatekeep/healthz", nil, nil)
	if st != http.StatusOK {
		t.Fatal("healthz")
	}
}

func TestUnauthenticatedAPIGets401(t *testing.T) {
	e := newEnv(t, nil)
	st, m, hd := e.api(e.browser(), http.MethodGet, "/wiki/", nil, nil)
	if st != http.StatusUnauthorized || m["error"] != "unauthenticated" || hd.Get("WWW-Authenticate") == "" {
		t.Fatalf("%d %v", st, m)
	}
	e.expectAudit(audit.KindAccess, "no_session")
}

func TestNegativeExpiredIDToken(t *testing.T) {
	var clk *clock
	e := newEnv(t, func(c *oidc.IDTokenClaims) {
		c.Expiry = jose.NewNumericDate(clk.Now().Add(-2 * time.Minute))
	})
	clk = e.clock
	b := e.browser()
	resp := e.login(b, "/wiki/", "alice")
	if resp.Status != http.StatusUnauthorized || !strings.Contains(resp.Body, "token_expired") {
		t.Fatalf("%d %s", resp.Status, resp.Body)
	}
	if b.Cookie(e.url("/"), sessionCookie) != "" {
		t.Fatal("session issued for expired token")
	}
	ev := e.expectAudit(audit.KindLogin, "token_expired")
	if ev.Decision != "fail" {
		t.Fatalf("%+v", ev)
	}
}

func TestNegativeWrongAudience(t *testing.T) {
	e := newEnv(t, func(c *oidc.IDTokenClaims) {
		c.Audience = jose.Audience{"some-other-app"}
		c.AZP = ""
	})
	resp := e.login(e.browser(), "/wiki/", "alice")
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("%d", resp.Status)
	}
	e.expectAudit(audit.KindLogin, "wrong_audience")
}

func TestIdPKeyRotationEndToEnd(t *testing.T) {
	e := newEnv(t, nil)
	if r := e.login(e.browser(), "/wiki/", "alice"); r.Status != http.StatusOK {
		t.Fatalf("first login: %d", r.Status)
	}
	// The IdP rotates to a key gatekeep has never seen: the unknown kid
	// triggers a JWKS refetch and sign-in keeps working without a restart.
	for range 2 {
		if _, err := e.st.IdP.Keys().Rotate(); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Second)
		if r := e.login(e.browser(), "/wiki/", "bob"); r.Status != http.StatusOK {
			t.Fatalf("login after IdP key rotation: %d %s", r.Status, r.Body)
		}
	}
}

func TestNegativeReplayedNonce(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	page, err := b.Navigate(e.url("/wiki/"))
	if err != nil {
		t.Fatal(err)
	}
	loginCookie := b.Cookie(e.url("/"), "__Host-gatekeep-login")
	resp, err := b.SubmitLogin(page, "alice", "alice-pw")
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("login: %v", err)
	}
	var callback string
	for _, h := range resp.Hops {
		if strings.Contains(h.URL, "/.gatekeep/callback") {
			callback = h.URL
		}
	}
	// An attacker who captured the login cookie and the callback URL replays
	// them in a fresh browser after the victim has signed in.
	attacker := e.browser()
	attacker.SetCookie(e.url("/"), "__Host-gatekeep-login", loginCookie)
	r, err := attacker.Navigate(callback)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "nonce_replayed") {
		t.Fatalf("replay: %d %s", r.Status, r.Body)
	}
	if attacker.Cookie(e.url("/"), sessionCookie) != "" {
		t.Fatal("replay produced a session")
	}
	e.expectAudit(audit.KindLogin, "nonce_replayed")
}

func TestNegativeStateMismatchAndMissingLoginState(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	page, _ := b.Navigate(e.url("/wiki/"))
	// Login CSRF: the victim's browser receives a callback for a flow it did
	// not start (state differs from its sealed login cookie).
	r, err := b.Navigate(e.url("/.gatekeep/callback?code=attacker-code&state=attacker-state"))
	if err != nil || r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "state_mismatch") {
		t.Fatalf("%v %d", err, r.Status)
	}
	_ = page
	r, _ = e.browser().Navigate(e.url("/.gatekeep/callback?code=x&state=y"))
	if r.Status != http.StatusBadRequest || !strings.Contains(r.Body, "login_state_missing") {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	r, _ = e.browser().Navigate(e.url("/.gatekeep/callback?error=access_denied"))
	if r.Status != http.StatusUnauthorized || !strings.Contains(r.Body, "idp_error") {
		t.Fatalf("%d", r.Status)
	}
	// Expired login state.
	b2 := e.browser()
	page, _ = b2.Navigate(e.url("/wiki/"))
	cb, err := idptest.Login(b2.Client, page.Hops[0].Location, "alice", "alice-pw")
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(11 * time.Minute)
	r, err = b2.Navigate(cb.String())
	if err != nil || !strings.Contains(r.Body, "login_state_expired") {
		t.Fatalf("expired login state: %v %d %s", err, r.Status, r.Body)
	}
}

func TestNegativeTamperedCookie(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	e.login(b, "/wiki/", "alice")
	v := b.Cookie(e.url("/"), sessionCookie)
	if v == "" {
		t.Fatal("no session")
	}
	// Flip one character in the ciphertext.
	i := len(v) / 2
	c := byte('A')
	if v[i] == 'A' {
		c = 'B'
	}
	b.SetCookie(e.url("/"), sessionCookie, v[:i]+string(c)+v[i+1:])
	st, m, _ := e.api(b, http.MethodGet, "/wiki/", nil, nil)
	if st != http.StatusUnauthorized || m["reason"] != "session_invalid" {
		t.Fatalf("%d %v", st, m)
	}
	e.expectAudit(audit.KindAccess, "session_invalid")
	// The browser is sent back through login.
	r, _ := b.Navigate(e.url("/wiki/"))
	if r.Status != http.StatusOK || !strings.Contains(r.Body, "Sign in") {
		t.Fatalf("expected IdP login page, got %d", r.Status)
	}
	// A cookie sealed for another purpose (login state) is not a session.
	login := b.Cookie(e.url("/"), "__Host-gatekeep-login")
	b.SetCookie(e.url("/"), sessionCookie, login)
	if st, m, _ := e.api(b, http.MethodGet, "/wiki/", nil, nil); st != http.StatusUnauthorized || m["reason"] != "session_invalid" {
		t.Fatalf("login cookie accepted as session: %d %v", st, m)
	}
}

func TestSessionIdleAndAbsoluteTimeout(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	e.login(b, "/wiki/", "bob")
	e.clock.Advance(61 * time.Minute)
	if st, m, _ := e.api(b, http.MethodGet, "/wiki/", nil, nil); st != http.StatusUnauthorized || m["reason"] != "session_idle" {
		t.Fatalf("idle: %d %v", st, m)
	}
	b2 := e.browser()
	e.login(b2, "/wiki/", "bob")
	// Stay active every 50 minutes until past the 8h absolute limit.
	for range 9 {
		e.clock.Advance(50 * time.Minute)
		if st, _, _ := e.api(b2, http.MethodGet, "/wiki/", nil, nil); st != http.StatusOK {
			t.Fatalf("active session rejected: %d", st)
		}
	}
	e.clock.Advance(50 * time.Minute) // 8h20m after login
	if st, m, _ := e.api(b2, http.MethodGet, "/wiki/", nil, nil); st != http.StatusUnauthorized || m["reason"] != "session_expired" {
		t.Fatalf("absolute: %d %v", st, m)
	}
}

func TestDevicePostureLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	e.login(b, "/wiki/", "alice")
	// Without posture the admin route is closed.
	if st, m, _ := e.api(b, http.MethodGet, "/admin/", nil, nil); st != http.StatusForbidden || m["error"] != "device_required" {
		t.Fatalf("no device: %d %v", st, m)
	}
	binding := e.pairDevice(b, "alice-laptop")
	r, _ := b.Navigate(e.url("/admin/panel"))
	w := whoami(t, r)
	if r.Status != 200 || w.DeviceID != "alice-laptop" || w.DeviceState != "fresh" {
		t.Fatalf("with device: %d %+v", r.Status, w)
	}
	e.expectAudit(audit.KindDevice, "posture_accepted")
	// Stale posture: 11 minutes later the posture is too old.
	e.clock.Advance(11 * time.Minute)
	st, m, _ := e.api(b, http.MethodGet, "/admin/", nil, nil)
	if st != http.StatusForbidden || m["error"] != "posture_stale" {
		t.Fatalf("stale: %d %v", st, m)
	}
	ev := e.expectAudit(audit.KindAccess, "posture_stale")
	if ev.Device != "stale" || ev.DeviceID != "alice-laptop" {
		t.Fatalf("%+v", ev)
	}
	// The agent refreshes over its binding and access returns.
	if _, err := e.st.Agent("alice-laptop", e.clock.Now).Report(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.api(b, http.MethodGet, "/admin/", nil, nil); st != http.StatusOK {
		t.Fatalf("after refresh: %d", st)
	}
	// Policy deny rule: DELETE requires screen lock (alice has it) - allowed.
	if st, _, _ := e.api(b, http.MethodDelete, "/admin/item", nil, map[string]string{"Origin": e.st.GatewayURL}); st != http.StatusOK {
		t.Fatalf("delete: %d", st)
	}
	// A signed-out visit to the device page returns there after login.
	fresh := e.browser()
	r, _ = fresh.Login(e.url("/.gatekeep/device"), "bob", "bob-pw")
	if r.Status != 200 || !strings.Contains(r.Body, "Pair a device") {
		t.Fatalf("device page after login: %d", r.Status)
	}
	// Device page renders for the signed-in user.
	r, _ = b.Navigate(e.url("/.gatekeep/device"))
	if r.Status != 200 || !strings.Contains(r.Body, "fresh (alice-laptop)") {
		t.Fatalf("device page: %d %s", r.Status, r.Body)
	}
}

func TestPostureNegatives(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.browser()
	e.login(alice, "/wiki/", "alice")
	code := e.pairingCode(alice)
	// Bob's (enrolled) laptop cannot claim Alice's pairing code.
	if _, err := e.st.Agent("bob-laptop", e.clock.Now).Report(context.Background(), code); err == nil {
		t.Fatal("foreign device paired")
	}
	e.expectAudit(audit.KindDevice, "device_owner_mismatch")
	// A guessed code fails.
	if _, err := e.st.Agent("alice-laptop", e.clock.Now).Report(context.Background(), "AAAAAAAAAA"); err == nil {
		t.Fatal("guessed code accepted")
	}
	e.expectAudit(audit.KindDevice, "unknown_nonce")
	// Replaying a captured assertion is rejected even with a valid nonce.
	code = e.pairingCode(alice)
	tok := signAssertion(t, e, "alice-laptop", code)
	if st := postReport(t, e, tok); st != http.StatusOK {
		t.Fatalf("first report %d", st)
	}
	if st := postReport(t, e, tok); st != http.StatusForbidden {
		t.Fatalf("replayed report %d", st)
	}
	e.expectAudit(audit.KindDevice, "posture_replay")
	// An assertion signed by an unenrolled key is rejected.
	k, _ := jose.GenerateKey(jose.EdDSA)
	rogue, _ := jose.NewSigner(k, "alice-laptop")
	e.st.Devices["rogue"] = rogue
	if st := postReport(t, e, signWith(t, e, rogue, "alice-laptop", e.pairingCode(alice))); st != http.StatusForbidden {
		t.Fatalf("rogue key %d", st)
	}
	e.expectAudit(audit.KindDevice, "bad_signature")
	// Pairing requires CSRF token.
	if st, _, _ := e.api(alice, http.MethodPost, "/.gatekeep/device/pair", nil, map[string]string{"Origin": e.st.GatewayURL}); st != http.StatusForbidden {
		t.Fatalf("pair without token: %d", st)
	}
	// Non-compliant device: bob pairs a fresh device but policy denies admin.
	bob := e.browser()
	e.login(bob, "/wiki/", "bob")
	e.pairDevice(bob, "bob-laptop")
	if st, m, _ := e.api(bob, http.MethodGet, "/admin/", nil, nil); st != http.StatusForbidden || m["error"] != "no_matching_allow" {
		t.Fatalf("bob admin: %d %v", st, m)
	}
}

func signAssertion(t *testing.T, e *env, deviceID, nonce string) string {
	t.Helper()
	return signWith(t, e, e.st.Devices[deviceID], deviceID, nonce)
}

func signWith(t *testing.T, e *env, s *jose.Signer, deviceID, nonce string) string {
	t.Helper()
	tok, err := posture.Sign(s, deviceID, e.st.Config.Posture.Audience, nonce, posture.Facts{OS: "linux"}, e.clock.Now(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func postReport(t *testing.T, e *env, tok string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.url("/.gatekeep/device/report"), strings.NewReader(tok))
	resp, err := (&http.Client{Transport: e.st.Transport}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestPolicyDecisionsAcrossUsers(t *testing.T) {
	e := newEnv(t, nil)
	carol := e.browser()
	r := e.login(carol, "/wiki/doc", "carol")
	if r.Status != 200 {
		t.Fatalf("contractor read: %d", r.Status)
	}
	st, m, _ := e.api(carol, http.MethodPost, "/wiki/doc", strings.NewReader("x"), map[string]string{"Origin": e.st.GatewayURL})
	if st != http.StatusForbidden || m["error"] != "no_matching_allow" {
		t.Fatalf("contractor write: %d %v", st, m)
	}
	if st, _, _ := e.api(carol, http.MethodGet, "/api/v1/items", nil, nil); st != http.StatusForbidden {
		t.Fatalf("contractor api: %d", st)
	}
	bob := e.browser()
	r = e.login(bob, "/api/v1/items", "bob")
	if w := whoami(t, r); w.Path != "/v1/items" || w.Audience != "gatekeep:route:api" {
		t.Fatalf("strip_prefix: %+v", w)
	}
	// Time-based deny: writes are blocked off-hours (23:00 UTC).
	e.clock.Advance(9 * time.Minute)
	if st, _, _ := e.api(bob, http.MethodPost, "/api/v1/items", nil, map[string]string{"Origin": e.st.GatewayURL}); st != http.StatusOK {
		t.Fatalf("daytime write: %d", st)
	}
	e.clock.Set(time.Date(2026, 10, 24, 23, 0, 0, 0, time.UTC))
	b3 := e.browser()
	e.login(b3, "/api/", "bob")
	st, m, _ = e.api(b3, http.MethodPost, "/api/v1/items", nil, map[string]string{"Origin": e.st.GatewayURL})
	if st != http.StatusForbidden || m["error"] != "denied_by_rule" {
		t.Fatalf("night write: %d %v", st, m)
	}
	ev := e.expectAudit(audit.KindAccess, "denied_by_rule")
	if ev.Rule != "no-writes-off-hours" || ev.PolicyCost == 0 {
		t.Fatalf("%+v", ev)
	}
}

func TestAnonymousRouteAndHeaderSpoofing(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	st, m, _ := e.api(b, http.MethodGet, "/public/info", nil, map[string]string{
		"X-Gatekeep-User": "user-alice", "X-Gatekeep-Assertion": "forged",
	})
	if st != http.StatusOK || m["user_header"] != nil || m["anonymous"] != true {
		t.Fatalf("spoofed headers reached upstream: %d %v", st, m)
	}
	// Signed-in users keep their identity on anonymous routes, and a spoofed
	// header is replaced by the real one.
	e.login(b, "/wiki/", "bob")
	_, m, _ = e.api(b, http.MethodGet, "/public/info", nil, map[string]string{"X-Gatekeep-User": "user-alice"})
	if m["sub"] != "user-bob" || m["user_header"] != "user-bob" {
		t.Fatalf("%v", m)
	}
}

func TestPathAndRoutingEdgeCases(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	for _, p := range []string{"/public/../admin/", "/public//x", "/public/./x"} {
		if st, m, _ := e.api(b, http.MethodGet, p, nil, nil); st != http.StatusBadRequest || m["error"] != "non_canonical_path" {
			t.Errorf("%s: %d %v", p, st, m)
		}
	}
	if st, m, _ := e.api(b, http.MethodGet, "/nowhere", nil, nil); st != http.StatusNotFound || m["error"] != "no_route" {
		t.Fatalf("%d %v", st, m)
	}
	// "/wikifoo" must not match the "/wiki/" route.
	if st, _, _ := e.api(b, http.MethodGet, "/wikifoo", nil, nil); st != http.StatusNotFound {
		t.Fatalf("prefix boundary: %d", st)
	}
}

func TestOpenRedirectBlocked(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	for _, rd := range []string{"//evil.test/x", "https://evil.test/", "/\\evil.test"} {
		page, err := b.Navigate(e.url("/.gatekeep/login?rd=" + url.QueryEscape(rd)))
		if err != nil {
			t.Fatal(err)
		}
		r, err := b.SubmitLogin(page, "bob", "bob-pw")
		if err != nil {
			t.Fatal(err)
		}
		last := r.Hops[len(r.Hops)-1]
		if !strings.HasPrefix(last.URL, e.st.GatewayURL+"/") || r.URL.Path != "/" {
			t.Fatalf("rd=%s ended at %s", rd, last.URL)
		}
	}
}

func TestCSRFAndLogout(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	e.login(b, "/wiki/", "alice")
	// Cross-site POST to a proxied app.
	for _, hdr := range []map[string]string{
		{"Origin": "https://evil.test"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Referer": "https://evil.test/page"},
		{}, // no provenance at all
	} {
		st, m, _ := e.api(b, http.MethodPost, "/wiki/edit", strings.NewReader("x"), hdr)
		if st != http.StatusForbidden || m["error"] != "csrf_origin" {
			t.Fatalf("%v: %d %v", hdr, st, m)
		}
	}
	for _, hdr := range []map[string]string{
		{"Origin": e.st.GatewayURL}, {"Sec-Fetch-Site": "same-origin"}, {"Referer": e.st.GatewayURL + "/wiki/"},
	} {
		if st, _, _ := e.api(b, http.MethodPost, "/wiki/edit", strings.NewReader("x"), hdr); st != http.StatusOK {
			t.Fatalf("%v: same-origin POST %d", hdr, st)
		}
	}
	saved := b.Cookie(e.url("/"), sessionCookie)
	// Logout without a token is refused.
	if st, _, _ := e.api(b, http.MethodPost, "/.gatekeep/logout", nil, map[string]string{"Origin": e.st.GatewayURL}); st != http.StatusForbidden {
		t.Fatalf("logout without token: %d", st)
	}
	_, me, _ := e.api(b, http.MethodGet, "/.gatekeep/me", nil, nil)
	tok := me["csrf_token"].(string)
	if st, _, _ := e.api(b, http.MethodPost, "/.gatekeep/logout", nil, map[string]string{"Origin": "https://evil.test", "X-CSRF-Token": tok}); st != http.StatusForbidden {
		t.Fatalf("cross-origin logout: %d", st)
	}
	form := url.Values{"csrf": {tok}}
	r, err := b.Do(http.MethodPost, e.url("/.gatekeep/logout"), "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil || r.Status != http.StatusOK || !strings.Contains(r.Body, "Signed out") {
		t.Fatalf("logout: %v %d", err, r.Status)
	}
	e.expectAudit(audit.KindLogout, "logout")
	// The captured cookie is revoked server-side.
	b.SetCookie(e.url("/"), sessionCookie, saved)
	if st, m, _ := e.api(b, http.MethodGet, "/wiki/", nil, nil); st != http.StatusUnauthorized || m["reason"] != "session_revoked" {
		t.Fatalf("revoked cookie: %d %v", st, m)
	}
	if st, _, _ := e.api(e.browser(), http.MethodPost, "/.gatekeep/logout", nil, nil); st != http.StatusUnauthorized {
		t.Fatalf("anonymous logout: %d", st)
	}
}

func TestUpstreamAssertionVerifiable(t *testing.T) {
	e := newEnv(t, nil)
	st, m, hd := e.api(e.browser(), http.MethodGet, "/.gatekeep/jwks.json", nil, nil)
	if st != 200 || !strings.Contains(hd.Get("Cache-Control"), "max-age") {
		t.Fatalf("%d", st)
	}
	keys, _ := m["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("jwks %v", m)
	}
	// The whoami upstream answers 401 unless the assertion verifies against
	// this JWKS, so a populated response proves the end-to-end check.
	b := e.browser()
	r := e.login(b, "/wiki/", "alice")
	if whoami(t, r).Subject != "user-alice" {
		t.Fatal("assertion not accepted")
	}
}

func TestUpstreamDown(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	e.login(b, "/wiki/", "alice")
	e.st.StopUpstream()
	st, m, _ := e.api(b, http.MethodGet, "/wiki/", nil, nil)
	if st != http.StatusBadGateway || m["error"] != "upstream_error" {
		t.Fatalf("%d %v", st, m)
	}
}

func TestAuditDecisionCoverage(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser()
	e.login(b, "/wiki/", "alice")
	_, _, _ = e.api(b, http.MethodGet, "/admin/", nil, nil)
	evs := e.events(func(ev audit.Event) bool { return ev.Reason == "device_required" })
	kinds := map[string]bool{}
	for _, ev := range evs {
		kinds[ev.Decision] = true
		if ev.Kind == audit.KindAccess && (ev.RequestID == "" || ev.ClientIP == "" || ev.LatencyMS < 0) {
			t.Fatalf("incomplete event %+v", ev)
		}
	}
	for _, d := range []string{"login_redirect", "ok", "allow", "deny"} {
		if !kinds[d] {
			t.Errorf("no %s decision in audit log", d)
		}
	}
}
