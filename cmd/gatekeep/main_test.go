package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archit2501/gatekeep/internal/audit"
)

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(context.Background(), args, &out, &errOut)
	return out.String() + errOut.String(), err
}

func TestPolicyTestOnExamples(t *testing.T) {
	out, err := runCmd(t, "policy-test", "--config", "../../examples/gatekeep.yaml", "--cases", "../../examples/policy-cases.yaml")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "11 cases, 0 failed") {
		t.Fatal(out)
	}
	bad := filepath.Join(t.TempDir(), "cases.yaml")
	_ = os.WriteFile(bad, []byte("cases: [{name: x, route: wiki, expect: allow, input: {}}]"), 0o600)
	out, err = runCmd(t, "policy-test", "--config", "../../examples/gatekeep.yaml", "--cases", bad)
	if err == nil || !strings.Contains(out, "FAIL") {
		t.Fatalf("failing case passed: %s", out)
	}
}

func TestCheckAndKeygen(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := os.ReadFile("../../examples/gatekeep.yaml")
	if err := os.WriteFile(filepath.Join(dir, "gk.yaml"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(t, "check", "--config", filepath.Join(dir, "gk.yaml")); err == nil {
		t.Fatal("check passed without device key")
	}
	_ = os.Mkdir(filepath.Join(dir, "devices"), 0o700)
	pub, err := runCmd(t, "keygen", "--alg", "EdDSA", "--out", filepath.Join(dir, "dev.key"))
	if err != nil || !strings.Contains(pub, "PUBLIC KEY") {
		t.Fatalf("%v %s", err, pub)
	}
	_ = os.WriteFile(filepath.Join(dir, "devices", "alice-laptop.pub.pem"), []byte(pub), 0o600)
	out, err := runCmd(t, "check", "--config", filepath.Join(dir, "gk.yaml"))
	if err != nil || !strings.Contains(out, "config OK: 4 routes, 6 rules, 1 devices") {
		t.Fatalf("%v %s", err, out)
	}
	if _, err := runCmd(t, "keygen"); err == nil {
		t.Fatal("keygen without --out")
	}
	if _, err := runCmd(t, "keygen", "--alg", "HS256", "--out", filepath.Join(dir, "x")); err == nil {
		t.Fatal("bad alg")
	}
}

func TestAuditVerify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	f, _ := os.Create(p)
	l := audit.NewLogger(f, nil)
	for range 3 {
		_, _ = l.Log(audit.Event{Kind: audit.KindAccess, Decision: "allow"})
	}
	_ = f.Close()
	out, err := runCmd(t, "audit-verify", "--file", p)
	if err != nil || !strings.Contains(out, "3 records") {
		t.Fatalf("%v %s", err, out)
	}
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, bytes.Replace(b, []byte("allow"), []byte("deny!"), 1), 0o600)
	if _, err := runCmd(t, "audit-verify", "--file", p); err == nil {
		t.Fatal("tampered log verified")
	}
	if _, err := runCmd(t, "audit-verify", "--file", p+".missing"); err == nil {
		t.Fatal("missing log")
	}
}

func TestMiscCommands(t *testing.T) {
	out, err := runCmd(t, "secret")
	if err != nil || len(strings.TrimSpace(out)) != 43 {
		t.Fatalf("secret %q", out)
	}
	dir := t.TempDir()
	out, err = runCmd(t, "dev-cert", "--cert", filepath.Join(dir, "c"), "--key", filepath.Join(dir, "k"), "--days", "1")
	if err != nil || !strings.Contains(out, "self-signed") {
		t.Fatalf("%v %s", err, out)
	}
	if out, _ := runCmd(t, "help"); !strings.Contains(out, "policy-test") {
		t.Fatal("help")
	}
	for _, args := range [][]string{nil, {"nope"}, {"check", "--config", "/nonexistent"}, {"serve", "--config", "/nonexistent"}, {"check", "--bogus"}} {
		if _, err := runCmd(t, args...); err == nil {
			t.Errorf("%v succeeded", args)
		}
	}
}
