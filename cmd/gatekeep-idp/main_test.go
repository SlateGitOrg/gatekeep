package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SlateGitOrg/gatekeep/internal/idp"
)

func TestHashPassword(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"hash-password", "--iterations", "1000"}, strings.NewReader("pw\n"), &out, &out); err != nil {
		t.Fatal(err)
	}
	if ok, err := idp.CheckPassword(strings.TrimSpace(out.String()), "pw"); !ok || err != nil {
		t.Fatalf("hash %q", out.String())
	}
	if err := run(context.Background(), []string{"hash-password"}, strings.NewReader(""), &out, &out); err == nil {
		t.Fatal("empty password hashed")
	}
	if err := run(context.Background(), nil, nil, &out, &out); err == nil {
		t.Fatal("no command")
	}
	if err := run(context.Background(), []string{"x"}, nil, &out, &out); err == nil {
		t.Fatal("bad command")
	}
}

func TestLoadExampleConfig(t *testing.T) {
	env := map[string]string{"GATEKEEP_CLIENT_SECRET": "s"}
	opts, fc, err := loadConfig("../../examples/idp.yaml", func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if opts.Issuer != "https://127.0.0.1:9443" || len(opts.Users) != 3 || len(opts.Clients) != 1 ||
		fc.CertFile != filepath.Join("..", "..", "examples", "tls.crt") {
		t.Fatalf("%+v", opts)
	}
	if _, _, err := loadConfig("../../examples/idp.yaml", func(string) string { return "" }); err == nil {
		t.Fatal("missing client secret accepted")
	}
	p := filepath.Join(t.TempDir(), "idp.yaml")
	_ = os.WriteFile(p, []byte("bogus: 1"), 0o600)
	if _, _, err := loadConfig(p, os.Getenv); err == nil {
		t.Fatal("unknown key accepted")
	}
	if err := run(context.Background(), []string{"serve", "--config", p}, nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("serve with bad config")
	}
}
