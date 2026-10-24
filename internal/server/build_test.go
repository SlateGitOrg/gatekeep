package server

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archit2501/gatekeep/internal/config"
	"github.com/archit2501/gatekeep/internal/idp/idptest"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/policy"
)

func TestParseSecrets(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding} {
		s, err := ParseSecrets(enc.EncodeToString(raw) + " , " + enc.EncodeToString(raw))
		if err != nil || len(s) != 2 || string(s[0]) != string(raw) {
			t.Fatalf("%v", err)
		}
	}
	for _, bad := range []string{"", "  ", "!!!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseSecrets(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func writeConfig(t *testing.T, issuer, extra string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	k, _ := jose.GenerateKey(jose.EdDSA)
	pub, _ := jose.MarshalPublicKeyPEM(k.Public())
	_ = os.WriteFile(filepath.Join(dir, "dev.pub.pem"), pub, 0o600)
	uk, _ := jose.GenerateKey(jose.ES256)
	priv, _ := jose.MarshalPrivateKeyPEM(uk)
	_ = os.WriteFile(filepath.Join(dir, "up.key"), priv, 0o600)
	doc := `
public_url: https://127.0.0.1:8443
oidc: {issuer: "` + issuer + `", client_id: gatekeep}
posture: {devices: [{id: d1, owner: u1, public_key_file: dev.pub.pem}]}
upstream_assertion: {key_file: up.key}
audit: {file: audit.jsonl}
routes:
  - {name: pub, path_prefix: /pub/, upstream: "http://127.0.0.1:9", anonymous: true}
  - {name: app, path_prefix: /app/, upstream: "http://127.0.0.1:9", rules: [{name: r, effect: allow, expr: "identity.authenticated"}]}
` + extra
	p := filepath.Join(dir, "gk.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestBuild(t *testing.T) {
	s := idptest.Start(t, []string{"https://127.0.0.1:8443/.gatekeep/callback"}, nil)
	cfg := writeConfig(t, s.Issuer, "")
	env := map[string]string{
		"GATEKEEP_CLIENT_SECRET":   "s3cret",
		"GATEKEEP_SESSION_SECRETS": base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	b, err := Build(context.Background(), cfg, Deps{Getenv: func(k string) string { return env[k] }, HTTPClient: s.TS.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if b.Gateway == nil || b.Policies["pub"] != nil || b.Policies["app"] == nil {
		t.Fatal("built")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.Resolve("audit.jsonl")); err != nil {
		t.Fatal("audit file not created")
	}
	// Missing secrets.
	for _, k := range []string{"GATEKEEP_CLIENT_SECRET", "GATEKEEP_SESSION_SECRETS"} {
		saved := env[k]
		env[k] = ""
		if _, err := Build(context.Background(), cfg, Deps{Getenv: func(k string) string { return env[k] }, HTTPClient: s.TS.Client()}); err == nil {
			t.Errorf("built without %s", k)
		}
		env[k] = saved
	}
	// Unreachable IdP (discovery fails) with the default client.
	cfg2 := writeConfig(t, "https://127.0.0.1:1", "")
	if _, err := Build(context.Background(), cfg2, Deps{Getenv: func(k string) string { return env[k] }}); err == nil {
		t.Fatal("built against unreachable IdP")
	}
	// Ephemeral upstream key + stdout audit.
	cfg3 := writeConfig(t, s.Issuer, "")
	cfg3.Upstream.KeyFile, cfg3.Audit.File = "", "-"
	if _, err := Build(context.Background(), cfg3, Deps{Getenv: func(k string) string { return env[k] }, HTTPClient: s.TS.Client()}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildFileErrors(t *testing.T) {
	cfg := writeConfig(t, "https://idp.test", "")
	cfg.Posture.Devices[0].PublicKeyFile = "missing.pem"
	if _, err := LoadDevices(cfg); err == nil {
		t.Fatal("missing device key")
	}
	cfg = writeConfig(t, "https://idp.test", "")
	_ = os.WriteFile(cfg.Resolve("dev.pub.pem"), []byte("junk"), 0o600)
	if _, err := LoadDevices(cfg); err == nil {
		t.Fatal("junk device key")
	}
	rk, _ := jose.GenerateKey(jose.RS256)
	pub, _ := jose.MarshalPublicKeyPEM(rk.Public())
	_ = os.WriteFile(cfg.Resolve("dev.pub.pem"), pub, 0o600)
	if _, err := LoadDevices(cfg); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("RSA device key: %v", err)
	}
	if _, err := idpClient(cfg.Resolve("missing.pem")); err == nil {
		t.Fatal("missing CA")
	}
	_ = os.WriteFile(cfg.Resolve("ca.pem"), []byte("x"), 0o600)
	if _, err := idpClient(cfg.Resolve("ca.pem")); err == nil {
		t.Fatal("empty CA")
	}
	cfg.Upstream.KeyFile = "missing.key"
	if _, err := upstreamSigner(cfg, nil); err == nil {
		t.Fatal("missing upstream key")
	}
}

func TestCompilePoliciesErrors(t *testing.T) {
	cfg := writeConfig(t, "https://idp.test", "")
	cfg.Routes[1].Rules = []policy.RuleSpec{{Name: "r", Effect: policy.Allow, Expr: "identity.nope"}}
	if _, err := CompilePolicies(cfg); err == nil {
		t.Fatal("bad rule compiled")
	}
}
