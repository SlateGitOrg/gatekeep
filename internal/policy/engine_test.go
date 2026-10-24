package policy

import (
	"context"
	"strings"
	"testing"
	"time"
)

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(0)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func adminInput() Input {
	return Input{
		Identity: Identity{Authenticated: true, Subject: "u1", Email: "alice@example.test", EmailVerified: true,
			Groups: []string{"eng", "admins"}, AuthAge: 5 * time.Minute},
		Device: Device{Present: true, ID: "laptop-1", OS: "darwin", DiskEncrypted: true, FirewallEnabled: true,
			ScreenLock: true, PatchAgeDays: 3, Age: 30 * time.Second},
		Request: Request{Method: "GET", Host: "app.test", Path: "/admin/users", ClientIP: "10.1.2.3",
			Headers: map[string]string{"user-agent": "x"}, Query: map[string]string{"q": "1"},
			Time: time.Date(2026, 10, 24, 14, 0, 0, 0, time.UTC), Route: "admin"},
	}
}

func TestEvaluateBasics(t *testing.T) {
	e := mustEngine(t)
	p, err := e.Compile([]RuleSpec{
		{Name: "admins", Effect: Allow, Expr: `"admins" in identity.groups && device.present && device.disk_encrypted && device.patch_age_days <= 14`},
		{Name: "block-writes-off-net", Effect: Deny, Expr: `request.method != "GET" && !request.ip.in_cidr("10.0.0.0/8")`},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := adminInput()
	d := p.Evaluate(context.Background(), in)
	if !d.Allowed || d.Rule != "admins" || d.Reason != ReasonAllowed || d.Cost == 0 {
		t.Fatalf("%+v", d)
	}
	in.Request.Method, in.Request.ClientIP = "POST", "203.0.113.9"
	d = p.Evaluate(context.Background(), in)
	if d.Allowed || d.Rule != "block-writes-off-net" || d.Reason != ReasonDenied {
		t.Fatalf("%+v", d)
	}
	in = adminInput()
	in.Device = Device{}
	d = p.Evaluate(context.Background(), in)
	if d.Allowed || d.Reason != ReasonNoAllow {
		t.Fatalf("%+v", d)
	}
}

func TestTypeCheckingCatchesTypos(t *testing.T) {
	e := mustEngine(t)
	for _, expr := range []string{
		`identity.grups.exists(g, g == "x")`,
		`device.patch_age_days == "3"`,
		`identity.email`,
		`unknown_var`,
		`request.ip.in_cidr(5)`,
	} {
		if _, err := e.Compile([]RuleSpec{{Name: "r", Effect: Allow, Expr: expr}}); err == nil {
			t.Errorf("compiled %q", expr)
		}
	}
	if _, err := e.Compile([]RuleSpec{{Name: "r", Effect: "maybe", Expr: "true"}}); err == nil {
		t.Error("bad effect accepted")
	}
	if _, err := e.Compile([]RuleSpec{{Name: "r", Effect: Allow, Expr: " "}}); err == nil {
		t.Error("empty expr accepted")
	}
	_, err := e.Compile([]RuleSpec{{Name: "r", Effect: Allow, Expr: "true"}, {Name: "r", Effect: Deny, Expr: "true"}})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate names: %v", err)
	}
}

func TestFailClosedOnDenyError(t *testing.T) {
	e := mustEngine(t)
	p, err := e.Compile([]RuleSpec{
		{Name: "allow-all", Effect: Allow, Expr: `true`},
		{Name: "needs-header", Effect: Deny, Expr: `request.headers["x-tenant"] == "evil"`},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate(context.Background(), adminInput())
	if d.Allowed || d.Reason != ReasonDenyError || len(d.Errors) != 1 {
		t.Fatalf("deny rule error must fail closed: %+v", d)
	}
}

func TestAllowErrorIsFalse(t *testing.T) {
	e := mustEngine(t)
	p, _ := e.Compile([]RuleSpec{
		{Name: "bad", Effect: Allow, Expr: `request.ip.in_cidr("not-a-cidr")`},
		{Name: "good", Effect: Allow, Expr: `identity.authenticated`},
	})
	d := p.Evaluate(context.Background(), adminInput())
	if !d.Allowed || d.Rule != "good" || len(d.Errors) != 1 {
		t.Fatalf("%+v", d)
	}
	in := adminInput()
	in.Request.ClientIP = "garbage"
	p2, _ := e.Compile([]RuleSpec{{Name: "ip", Effect: Allow, Expr: `request.ip.in_cidr("10.0.0.0/8")`}})
	if d := p2.Evaluate(context.Background(), in); d.Allowed {
		t.Fatalf("%+v", d)
	}
}

func TestCostLimit(t *testing.T) {
	e, err := NewEngine(50)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.Compile([]RuleSpec{
		{Name: "expensive", Effect: Deny, Expr: `identity.groups.all(a, identity.groups.all(b, identity.groups.all(c, a != "zz")))`},
	})
	if err != nil {
		t.Fatal(err)
	}
	in := adminInput()
	for i := range 40 {
		in.Identity.Groups = append(in.Identity.Groups, strings.Repeat("g", i%5+1))
	}
	d := p.Evaluate(context.Background(), in)
	if d.Allowed || d.Reason != ReasonCostExhausted {
		t.Fatalf("%+v", d)
	}
}

func TestStdlibExtensions(t *testing.T) {
	e := mustEngine(t)
	cases := map[string]bool{
		`sets.intersects(identity.groups, ["admins", "sre"])`:             true,
		`identity.email.endsWith("@example.test")`:                        true,
		`identity.email.lowerAscii().split("@")[1] == "example.test"`:     true,
		`request.time.getHours() >= 9 && request.time.getHours() < 18`:    true,
		`identity.auth_age < duration("1h")`:                              true,
		`device.age > duration("10m")`:                                    false,
		`request.path.startsWith("/admin/") && request.query["q"] == "1"`: true,
		`"::ffff:10.1.2.3".in_cidr("10.0.0.0/8")`:                         true,
		`"2001:db8::1".in_cidr("2001:db8::/32")`:                          true,
	}
	for expr, want := range cases {
		p, err := e.Compile([]RuleSpec{{Name: "r", Effect: Allow, Expr: expr}})
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if got := p.Evaluate(context.Background(), adminInput()).Allowed; got != want {
			t.Errorf("%s = %v, want %v", expr, got, want)
		}
	}
}

func TestNoRulesDenies(t *testing.T) {
	p, _ := mustEngine(t).Compile(nil)
	if d := p.Evaluate(context.Background(), adminInput()); d.Allowed || d.Reason != ReasonNoRules {
		t.Fatalf("%+v", d)
	}
	if len(p.Rules()) != 0 {
		t.Fatal("rules")
	}
}
