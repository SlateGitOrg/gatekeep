// Package e2e drives the complete system — demo IdP, gatekeep and a
// verifying upstream — over real loopback TLS connections with a cookie-jar
// browser, exactly as a user's browser and device agent would.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/audit"
	"github.com/SlateGitOrg/gatekeep/internal/demo"
	"github.com/SlateGitOrg/gatekeep/internal/oidc"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.b.Bytes())
}

type env struct {
	t     *testing.T
	st    *demo.Stack
	clock *clock
	audit *syncBuffer
}

func newEnv(t *testing.T, mutate func(*oidc.IDTokenClaims)) *env {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 24, 14, 0, 0, 0, time.UTC)}
	buf := &syncBuffer{}
	st, err := demo.StartStack(context.Background(), demo.StackOptions{
		Now: clk.Now, MutateIDToken: mutate, AuditWriter: buf, PasswordIterations: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, clock: clk, audit: buf}
	t.Cleanup(func() {
		st.Close()
		// Every scenario must leave a verifiable audit chain behind.
		if _, err := audit.Verify(bytes.NewReader(buf.Bytes())); err != nil {
			t.Errorf("audit chain: %v", err)
		}
	})
	return e
}

func (e *env) browser() *demo.Browser { return demo.NewBrowser(e.st.Transport) }

func (e *env) url(p string) string { return e.st.GatewayURL + p }

// login signs user in via target and returns the final response.
func (e *env) login(b *demo.Browser, target, user string) *demo.Response {
	e.t.Helper()
	resp, err := b.Login(e.url(target), user, user+"-pw")
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// events returns audit events, waiting briefly for pred to match one.
// (The audit record is written after the response is flushed.)
func (e *env) events(pred func(audit.Event) bool) []audit.Event {
	e.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var evs []audit.Event
		sc := bufio.NewScanner(bytes.NewReader(e.audit.Bytes()))
		found := false
		for sc.Scan() {
			var ev audit.Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				e.t.Fatal(err)
			}
			evs = append(evs, ev)
			if pred == nil || pred(ev) {
				found = true
			}
		}
		if found || time.Now().After(deadline) {
			return evs
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// expectAudit waits for an event of kind with reason and returns it.
func (e *env) expectAudit(kind, reason string) audit.Event {
	e.t.Helper()
	match := func(ev audit.Event) bool { return ev.Kind == kind && ev.Reason == reason }
	for _, ev := range e.events(match) {
		if match(ev) {
			return ev
		}
	}
	e.t.Fatalf("no audit event kind=%s reason=%s in:\n%s", kind, reason, e.audit.Bytes())
	return audit.Event{}
}

// api performs a non-navigation request (JSON client) with the browser's cookies.
func (e *env) api(b *demo.Browser, method, path string, body io.Reader, hdr map[string]string) (int, map[string]any, http.Header) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.url(path), body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m, resp.Header
}

func whoami(t *testing.T, r *demo.Response) demo.WhoAmIResponse {
	t.Helper()
	var w demo.WhoAmIResponse
	if err := json.Unmarshal([]byte(r.Body), &w); err != nil {
		t.Fatalf("not a whoami response (status %d): %s", r.Status, r.Body)
	}
	return w
}

func hopsString(hs []demo.Hop) string {
	var sb strings.Builder
	for _, h := range hs {
		sb.WriteString(h.String())
		sb.WriteByte('\n')
	}
	return sb.String()
}

// pairDevice runs the pairing ceremony for a signed-in browser and returns
// the agent's binding.
func (e *env) pairDevice(b *demo.Browser, deviceID string) string {
	e.t.Helper()
	code := e.pairingCode(b)
	rr, err := e.st.Agent(deviceID, e.clock.Now).Report(context.Background(), code)
	if err != nil {
		e.t.Fatalf("pair %s: %v", deviceID, err)
	}
	return rr.Binding
}

func (e *env) pairingCode(b *demo.Browser) string {
	e.t.Helper()
	st, me, _ := e.api(b, http.MethodGet, "/.gatekeep/me", nil, nil)
	if st != http.StatusOK {
		e.t.Fatalf("me: %d %v", st, me)
	}
	tok, _ := me["csrf_token"].(string)
	st, m, _ := e.api(b, http.MethodPost, "/.gatekeep/device/pair", nil, map[string]string{
		"X-CSRF-Token": tok, "Origin": e.st.GatewayURL,
	})
	if st != http.StatusOK {
		e.t.Fatalf("pair: %d %v", st, m)
	}
	return m["code"].(string)
}
