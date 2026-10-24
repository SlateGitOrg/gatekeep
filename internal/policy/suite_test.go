package policy

import (
	"context"
	"strings"
	"testing"
)

const casesYAML = `
cases:
  - name: admin on healthy laptop
    route: admin
    expect: allow
    rule: admins
    input:
      identity: {authenticated: true, sub: u1, groups: [admins]}
      device: {present: true, disk_encrypted: true, patch_age_days: 2, age: 30s}
      request: {method: GET, path: /admin/, time: 2026-10-24T10:00:00Z}
  - name: admin without device
    route: admin
    expect: deny
    input:
      identity: {authenticated: true, sub: u1, groups: [admins]}
  - name: wrong expectation
    route: admin
    expect: allow
    input:
      identity: {authenticated: true, groups: [eng]}
  - name: wrong rule pinned
    route: admin
    expect: allow
    rule: other
    input:
      identity: {authenticated: true, groups: [admins]}
      device: {present: true, disk_encrypted: true}
  - name: missing route
    route: nope
    expect: deny
`

func TestRunCases(t *testing.T) {
	e := mustEngine(t)
	p, err := e.Compile([]RuleSpec{{Name: "admins", Effect: Allow,
		Expr: `"admins" in identity.groups && device.present && device.disk_encrypted && device.age < duration("5m")`}})
	if err != nil {
		t.Fatal(err)
	}
	cases, err := LoadCases(strings.NewReader(casesYAML))
	if err != nil {
		t.Fatal(err)
	}
	res := RunCases(context.Background(), map[string]*Policy{"admin": p}, cases)
	want := []bool{true, true, false, false, false}
	for i, r := range res {
		if r.Pass != want[i] {
			t.Errorf("case %q pass=%v problem=%q", r.Case.Name, r.Pass, r.Problem)
		}
	}
}

func TestLoadCasesErrors(t *testing.T) {
	for _, doc := range []string{
		"cases: [{name: x, route: r, expect: maybe}]",
		"cases: [{name: x, route: r, expect: allow, bogus: 1}]",
		"cases: [{name: x, route: r, expect: allow, input: {identity: {grups: [a]}}}]",
	} {
		if _, err := LoadCases(strings.NewReader(doc)); err == nil {
			t.Errorf("accepted %s", doc)
		}
	}
}
