// Command gatekeep-demo runs an offline, end-to-end walkthrough: it starts
// the demo IdP, gatekeep and a verifying upstream on loopback TLS, then
// scripts users, devices and attackers through the system and prints what
// happened, finishing with the verified audit log.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/audit"
	"github.com/SlateGitOrg/gatekeep/internal/demo"
	"github.com/SlateGitOrg/gatekeep/internal/gateway"
	"github.com/SlateGitOrg/gatekeep/internal/idp/idptest"
	"github.com/SlateGitOrg/gatekeep/internal/jose"
	"github.com/SlateGitOrg/gatekeep/internal/oidc"
)

func main() {
	auditOut := flag.String("audit-out", "", "also write the audit log to this file")
	upstream := flag.String("upstream", "", "instead of the demo, serve the whoami upstream on this address")
	gk := flag.String("gatekeep", "https://127.0.0.1:8443", "gatekeep public URL (upstream mode)")
	ca := flag.String("ca", "", "CA certificate trusted for gatekeep's JWKS (upstream mode)")
	flag.Parse()
	var err error
	if *upstream != "" {
		err = serveUpstream(*upstream, *gk, *ca)
	} else {
		err = run(os.Stdout, *auditOut)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gatekeep-demo:", err)
		os.Exit(1)
	}
}

// serveUpstream runs the whoami app standalone for the quickstart.
func serveUpstream(addr, gatekeepURL, caFile string) error {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return err
		}
		pool.AppendCertsFromPEM(b)
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	auds := []string{}
	for _, n := range []string{"public", "wiki", "admin", "api"} {
		auds = append(auds, gateway.AssertionAudience(n))
	}
	app := &demo.WhoAmI{Name: "whoami", Issuer: gatekeepURL, Audiences: auds,
		Keys: oidc.NewRemoteKeySet(gatekeepURL+"/.gatekeep/jwks.json", hc)}
	fmt.Printf("whoami upstream on http://%s (trusting assertions from %s)\n", addr, gatekeepURL)
	srv := &http.Server{Addr: addr, Handler: app, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// demoClock starts at a fixed instant and advances with real time plus any
// simulated jumps, so timestamps are stable but latencies are real.
type demoClock struct {
	mu     sync.Mutex
	base   time.Time
	start  time.Time
	offset time.Duration
}

func (c *demoClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base.Add(c.offset + time.Since(c.start))
}

func (c *demoClock) Jump(d time.Duration) {
	c.mu.Lock()
	c.offset += d
	c.mu.Unlock()
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Clone(l.b.Bytes())
}

// fault lets the demo make the IdP misbehave for one sign-in.
type fault struct {
	mu   sync.Mutex
	kind string
	now  func() time.Time
}

func (f *fault) set(k string) { f.mu.Lock(); f.kind = k; f.mu.Unlock() }

func (f *fault) mutate(c *oidc.IDTokenClaims) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch f.kind {
	case "expired":
		c.Expiry = jose.NewNumericDate(f.now().Add(-time.Minute))
	case "wrong-aud":
		c.Audience, c.AZP = jose.Audience{"another-app"}, ""
	}
}

type runner struct {
	w   io.Writer
	st  *demo.Stack
	clk *demoClock
	n   int
	err error
}

func (r *runner) section(title string) {
	r.n++
	fmt.Fprintf(r.w, "\n== %d. %s\n", r.n, title)
}

func (r *runner) line(format string, a ...any) { fmt.Fprintf(r.w, "   "+format+"\n", a...) }

func (r *runner) url(p string) string { return r.st.GatewayURL + p }

func (r *runner) check(cond bool, what string) {
	if !cond && r.err == nil {
		r.err = fmt.Errorf("demo expectation failed: %s", what)
	}
}

// api makes a JSON request with the browser's cookies.
func (r *runner) api(b *demo.Browser, method, p string, hdr map[string]string) (int, map[string]any) {
	req, _ := http.NewRequestWithContext(context.Background(), method, r.url(p), nil)
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		r.check(false, err.Error())
		return 0, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (r *runner) result(label string, status int, m map[string]any) {
	reason := m["error"]
	if r, ok := m["reason"].(string); ok && r != "" {
		reason = r
	}
	if status == http.StatusOK {
		r.line("%-46s -> %d  sub=%v device=%v", label, status, m["sub"], m["device_state"])
		return
	}
	r.line("%-46s -> %d  reason=%v", label, status, reason)
}

func shortURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	p := u.Path
	if p == "/authorize" {
		return u.Host + "/authorize?...(PKCE S256, state, nonce)"
	}
	if strings.HasSuffix(p, "/callback") {
		return u.Host + p + "?code=...&state=..."
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return u.Host + p
}

func run(w io.Writer, auditOut string) error {
	clk := &demoClock{base: time.Date(2026, 10, 24, 14, 0, 0, 0, time.UTC), start: time.Now()}
	buf := &lockedBuffer{}
	flt := &fault{now: clk.Now}
	st, err := demo.StartStack(context.Background(), demo.StackOptions{
		Now: clk.Now, AuditWriter: buf, MutateIDToken: flt.mutate,
	})
	if err != nil {
		return err
	}
	defer st.Close()
	r := &runner{w: w, st: st, clk: clk}
	fmt.Fprintf(w, "gatekeep offline demo (all traffic on loopback TLS; simulated clock starts %s)\n", clk.base.Format(time.RFC3339))
	fmt.Fprintf(w, "   demo IdP : %s\n   gatekeep : %s\n   upstream : %s (verifies X-Gatekeep-Assertion)\n", st.IdPURL, st.GatewayURL, st.UpstreamURL)

	alice := demo.NewBrowser(st.Transport)
	r.section("Alice opens /wiki/ — full OIDC authorization-code + PKCE redirect flow")
	resp, err := alice.Login(r.url("/wiki/handbook"), "alice", "alice-pw")
	if err != nil {
		return err
	}
	for _, h := range resp.Hops {
		loc := ""
		if h.Location != "" {
			loc = "  -> " + shortURL(h.Location)
		}
		r.line("%-4s %-52s %d%s", h.Method, shortURL(h.URL), h.Status, loc)
	}
	var who demo.WhoAmIResponse
	_ = json.Unmarshal([]byte(resp.Body), &who)
	r.line("upstream verified assertion: sub=%s email=%s groups=%v aud=%s", who.Subject, who.Email, who.Groups, who.Audience)
	r.line("cookies the upstream received: %v (gatekeep's session cookie is stripped)", who.CookiesSeen)
	r.check(resp.Status == 200 && who.Subject == "user-alice", "alice wiki login")

	r.section("Device posture gates /admin/")
	st1, m := r.api(alice, http.MethodGet, "/admin/console", nil)
	r.result("alice GET /admin/console (no device)", st1, m)
	r.check(st1 == 403, "admin without device")
	code := pairingCode(r, alice)
	r.line("alice requests a pairing code on /.gatekeep/device: %s", code)
	agent := st.Agent("alice-laptop", clk.Now)
	rr, err := agent.Report(context.Background(), code)
	if err != nil {
		return err
	}
	r.line("posture-agent on alice-laptop signs posture (EdDSA) -> accepted, fresh for %ds", rr.MaxAgeSecs)
	st1, m = r.api(alice, http.MethodGet, "/admin/console", nil)
	r.result("alice GET /admin/console (compliant laptop)", st1, m)
	r.check(st1 == 200, "admin with device")

	r.section("Posture goes stale after 10 minutes without a refresh")
	clk.Jump(11 * time.Minute)
	st1, m = r.api(alice, http.MethodGet, "/admin/console", nil)
	r.result("alice GET /admin/console (+11m)", st1, m)
	r.check(st1 == 403, "stale posture")
	if _, err := agent.Report(context.Background(), rr.Binding); err != nil {
		return err
	}
	st1, m = r.api(alice, http.MethodGet, "/admin/console", nil)
	r.result("agent refreshes over its binding; retry", st1, m)
	r.check(st1 == 200, "refreshed posture")

	r.section("Policy decisions for other users")
	bob := demo.NewBrowser(st.Transport)
	if _, err := bob.Login(r.url("/wiki/"), "bob", "bob-pw"); err != nil {
		return err
	}
	if _, err := st.Agent("bob-laptop", clk.Now).Report(context.Background(), pairingCode(r, bob)); err != nil {
		return err
	}
	st1, m = r.api(bob, http.MethodGet, "/admin/console", nil)
	r.result("bob GET /admin/console (unencrypted disk)", st1, m)
	r.check(st1 == 403, "bob admin")
	st1, m = r.api(bob, http.MethodGet, "/api/v1/builds", nil)
	r.result("bob GET /api/v1/builds", st1, m)
	carol := demo.NewBrowser(st.Transport)
	if _, err := carol.Login(r.url("/wiki/"), "carol", "carol-pw"); err != nil {
		return err
	}
	st1, m = r.api(carol, http.MethodGet, "/wiki/handbook", nil)
	r.result("carol (contractor) GET /wiki/handbook", st1, m)
	st1, m = r.api(carol, http.MethodPost, "/wiki/handbook", map[string]string{"Origin": st.GatewayURL})
	r.result("carol (contractor) POST /wiki/handbook", st1, m)
	r.check(st1 == 403, "contractor write")

	r.section("Attacks that must fail")
	saved := alice.Cookie(r.url("/"), "__Host-gatekeep")
	alice.SetCookie(r.url("/"), "__Host-gatekeep", flip(saved))
	st1, m = r.api(alice, http.MethodGet, "/wiki/", nil)
	r.result("tampered session cookie (1 byte flipped)", st1, m)
	r.check(st1 == 401, "tampered cookie")
	alice.SetCookie(r.url("/"), "__Host-gatekeep", saved)
	st1, m = r.api(alice, http.MethodPost, "/wiki/edit", map[string]string{"Origin": "https://evil.test"})
	r.result("cross-site POST from https://evil.test", st1, m)
	st1, m = r.api(demo.NewBrowser(st.Transport), http.MethodGet, "/public/status", map[string]string{"X-Gatekeep-User": "user-alice"})
	seen, _ := m["user_header"].(string)
	if seen == "" {
		seen = "(stripped)"
	}
	r.line("%-46s -> %d  upstream saw X-Gatekeep-User: %s", "spoofed X-Gatekeep-User on /public/", st1, seen)
	r.check(seen == "(stripped)", "spoofed header")
	st1, m = r.api(alice, http.MethodGet, "/public/../admin/console", nil)
	r.result("path traversal /public/../admin/console", st1, m)
	replayCallback(r)
	for _, f := range []string{"expired", "wrong-aud"} {
		flt.set(f)
		resp, err := demo.NewBrowser(st.Transport).Login(r.url("/wiki/"), "bob", "bob-pw")
		if err != nil {
			return err
		}
		r.line("%-46s -> %d  reason=%s", "IdP issues "+f+" ID token", resp.Status, reasonFromBody(resp.Body))
		r.check(resp.Status == 401, f)
	}
	flt.set("")

	r.section("IdP signing-key rotation (JWKS refetch on unknown kid)")
	kid, _ := st.IdP.Keys().Rotate()
	resp, err = demo.NewBrowser(st.Transport).Login(r.url("/wiki/"), "bob", "bob-pw")
	if err != nil {
		return err
	}
	r.line("IdP rotated to %s; new sign-in -> %d", kid, resp.Status)
	r.check(resp.Status == 200, "rotation")

	r.section("Logout revokes the session server-side")
	_, me := r.api(alice, http.MethodGet, "/.gatekeep/me", nil)
	st1, _ = r.api(alice, http.MethodPost, "/.gatekeep/logout", map[string]string{"Origin": st.GatewayURL, "X-CSRF-Token": fmt.Sprint(me["csrf_token"])})
	r.line("%-46s -> %d", "alice POST /.gatekeep/logout (CSRF token)", st1)
	alice.SetCookie(r.url("/"), "__Host-gatekeep", saved)
	st1, m = r.api(alice, http.MethodGet, "/wiki/", nil)
	r.result("replay of alice's pre-logout cookie", st1, m)
	r.check(st1 == 401, "revoked cookie")

	time.Sleep(50 * time.Millisecond) // let the last audit records land
	logBytes := buf.Bytes()
	r.section("Decision audit log (hash-chained JSON lines)")
	printAudit(w, logBytes)
	res, err := audit.Verify(bytes.NewReader(logBytes))
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "\n   audit chain verified: %d records, head %s\n", res.Records, res.Head[:16])
	if auditOut != "" {
		if err := os.WriteFile(auditOut, logBytes, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(w, "   audit log written to %s\n", auditOut)
	}
	if r.err != nil {
		return r.err
	}
	fmt.Fprintln(w, "\ndemo OK")
	return nil
}

func pairingCode(r *runner, b *demo.Browser) string {
	_, me := r.api(b, http.MethodGet, "/.gatekeep/me", nil)
	_, m := r.api(b, http.MethodPost, "/.gatekeep/device/pair", map[string]string{
		"Origin": r.st.GatewayURL, "X-CSRF-Token": fmt.Sprint(me["csrf_token"]),
	})
	return fmt.Sprint(m["code"])
}

// replayCallback captures a login cookie and callback URL, lets the victim
// finish, then replays both from an attacker's browser.
func replayCallback(r *runner) {
	victim := demo.NewBrowser(r.st.Transport)
	page, err := victim.Navigate(r.url("/wiki/"))
	if err != nil {
		r.check(false, err.Error())
		return
	}
	loginCookie := victim.Cookie(r.url("/"), "__Host-gatekeep-login")
	cb, err := idptest.Login(victim.Client, page.Hops[0].Location, "bob", "bob-pw")
	if err != nil {
		r.check(false, err.Error())
		return
	}
	if _, err := victim.Navigate(cb.String()); err != nil {
		r.check(false, err.Error())
		return
	}
	attacker := demo.NewBrowser(r.st.Transport)
	attacker.SetCookie(r.url("/"), "__Host-gatekeep-login", loginCookie)
	resp, err := attacker.Navigate(cb.String())
	if err != nil {
		r.check(false, err.Error())
		return
	}
	r.line("%-46s -> %d  reason=%s", "replayed OIDC callback (captured cookie+code)", resp.Status, reasonFromBody(resp.Body))
	r.check(resp.Status == 400, "replayed callback")
}

func reasonFromBody(body string) string {
	_, after, ok := strings.Cut(body, "Reason: <code>")
	if !ok {
		return "?"
	}
	reason, _, _ := strings.Cut(after, "<")
	return reason
}

func flip(v string) string {
	if v == "" {
		return v
	}
	i := len(v) / 2
	c := byte('A')
	if v[i] == 'A' {
		c = 'B'
	}
	return v[:i] + string(c) + v[i+1:]
}

func printAudit(w io.Writer, b []byte) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "   seq\tkind\troute\tsub\tdevice\tdecision\treason\trule\tstatus")
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev audit.Event
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		fmt.Fprintf(tw, "   %d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", ev.Seq, ev.Kind, dash(ev.Route), dash(ev.Subject),
			dash(ev.Device), ev.Decision, dash(ev.Reason), dash(ev.Rule), ev.Status)
	}
	_ = tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
