package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const minimal = `
public_url: https://gk.test
oidc: {issuer: "https://idp.test", client_id: gk}
routes:
  - {name: app, path_prefix: /, upstream: "http://127.0.0.1:9000", rules: [{name: r, effect: allow, expr: "true"}]}
`

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.Session.CookieName != "gatekeep" || c.Session.Absolute != 8*time.Hour ||
		c.Posture.Audience != "https://gk.test" || c.Posture.MaxAge != 10*time.Minute || c.Headers.HSTSMaxAge != 31536000 ||
		c.OIDC.ClientSecretEnv != "GATEKEEP_CLIENT_SECRET" || len(c.OIDC.Scopes) != 4 {
		t.Fatalf("%+v", c)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":      minimal + "bogus: 1\n",
		"http issuer":      strings.Replace(minimal, "https://idp.test", "http://idp.test", 1),
		"bad public url":   strings.Replace(minimal, "https://gk.test", "https://gk.test/path", 1),
		"no client":        strings.Replace(minimal, "client_id: gk", "client_id: \"\"", 1),
		"no rules":         strings.Replace(minimal, `, rules: [{name: r, effect: allow, expr: "true"}]`, "", 1),
		"bad prefix":       strings.Replace(minimal, "path_prefix: /", "path_prefix: x", 1),
		"bad upstream":     strings.Replace(minimal, "http://127.0.0.1:9000", "127.0.0.1:9000", 1),
		"tls half":         minimal + "tls: {cert_file: a}\n",
		"idle > absolute":  minimal + "session: {absolute_timeout: 1h, idle_timeout: 2h}\n",
		"assertion age":    minimal + "posture: {assertion_max_age: 10m}\n",
		"device fields":    minimal + "posture: {devices: [{id: d}]}\n",
		"duplicate device": minimal + "posture: {devices: [{id: d, owner: o, public_key_file: f}, {id: d, owner: o, public_key_file: f}]}\n",
		"no routes":        "public_url: https://gk.test\noidc: {issuer: \"https://idp.test\", client_id: gk}\n",
		"route name":       strings.Replace(minimal, "name: app, ", "", 1),
		"yaml syntax":      "routes: [",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gk.yaml")
	if err := os.WriteFile(p, []byte(minimal), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Resolve("tls.crt") != filepath.Join(dir, "tls.crt") || c.Resolve("/abs") != "/abs" || c.Resolve("") != "" {
		t.Fatal("resolve")
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file")
	}
	if err := os.WriteFile(p, []byte("bogus: 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("invalid file")
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "examples", "gatekeep.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) != 4 || c.Resolve(c.TLS.CertFile) != filepath.Join("..", "..", "examples", "tls.crt") {
		t.Fatalf("%+v", c.Routes)
	}
}
