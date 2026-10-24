// Command gatekeep is the identity-aware reverse proxy.
//
//	gatekeep serve        --config gatekeep.yaml
//	gatekeep check        --config gatekeep.yaml
//	gatekeep policy-test  --config gatekeep.yaml --cases cases.yaml
//	gatekeep audit-verify --file audit.jsonl
//	gatekeep keygen       --alg ES256 --out upstream.key
//	gatekeep secret
//	gatekeep dev-cert     --hosts 127.0.0.1,localhost --cert tls.crt --key tls.key
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/archit2501/gatekeep/internal/audit"
	"github.com/archit2501/gatekeep/internal/config"
	"github.com/archit2501/gatekeep/internal/devcert"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/policy"
	"github.com/archit2501/gatekeep/internal/server"
)

const usage = `usage: gatekeep <command> [flags]

commands:
  serve         run the proxy
  check         validate a config and compile its policies (offline)
  policy-test   run policy unit tests against a config's routes
  audit-verify  verify a hash-chained audit log
  keygen        generate a private key (PKCS#8 PEM) and print its public key
  secret        print a random 32-byte session secret (base64url)
  dev-cert      write a self-signed TLS certificate for local development
`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gatekeep:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errors.New("missing command")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return cmdServe(ctx, rest, stderr)
	case "check":
		return cmdCheck(rest, stdout)
	case "policy-test":
		return cmdPolicyTest(ctx, rest, stdout)
	case "audit-verify":
		return cmdAuditVerify(rest, stdout)
	case "keygen":
		return cmdKeygen(rest, stdout)
	case "secret":
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return err
		}
		fmt.Fprintln(stdout, base64.RawURLEncoding.EncodeToString(b[:]))
		return nil
	case "dev-cert":
		return cmdDevCert(rest, stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	}
	fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

func cmdServe(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "gatekeep.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	built, err := server.Build(ctx, cfg, server.Deps{Logger: logger})
	if err != nil {
		return err
	}
	defer func() { _ = built.Close() }()
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           built.Gateway,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		logger.Info("gatekeep listening", "addr", cfg.Listen, "public_url", cfg.PublicURL, "routes", len(cfg.Routes))
		if cfg.TLS.CertFile != "" {
			errc <- srv.ListenAndServeTLS(cfg.Resolve(cfg.TLS.CertFile), cfg.Resolve(cfg.TLS.KeyFile))
			return
		}
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func cmdCheck(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	cfgPath := fs.String("config", "gatekeep.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if _, err := server.LoadDevices(cfg); err != nil {
		return err
	}
	pols, err := server.CompilePolicies(cfg)
	if err != nil {
		return err
	}
	rules := 0
	for _, p := range pols {
		if p != nil {
			rules += len(p.Rules())
		}
	}
	fmt.Fprintf(stdout, "config OK: %d routes, %d rules, %d devices\n", len(cfg.Routes), rules, len(cfg.Posture.Devices))
	return nil
}

func cmdPolicyTest(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("policy-test", flag.ContinueOnError)
	cfgPath := fs.String("config", "gatekeep.yaml", "config file")
	casesPath := fs.String("cases", "", "policy test cases (YAML)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	pols, err := server.CompilePolicies(cfg)
	if err != nil {
		return err
	}
	f, err := os.Open(*casesPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	cases, err := policy.LoadCases(f)
	if err != nil {
		return err
	}
	compiled := map[string]*policy.Policy{}
	for name, p := range pols {
		if p != nil {
			compiled[name] = p
		}
	}
	failed := 0
	for _, r := range policy.RunCases(ctx, compiled, cases) {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
			failed++
		}
		fmt.Fprintf(stdout, "%s  %-45s route=%-8s decision=%-5s rule=%q", status, r.Case.Name, r.Case.Route,
			effect(r.Decision.Allowed), r.Decision.Rule)
		if r.Problem != "" {
			fmt.Fprintf(stdout, "  -- %s", r.Problem)
		}
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "%d cases, %d failed\n", len(cases), failed)
	if failed > 0 {
		return fmt.Errorf("%d policy test(s) failed", failed)
	}
	return nil
}

func effect(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

func cmdAuditVerify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("audit-verify", flag.ContinueOnError)
	file := fs.String("file", "audit.jsonl", "audit log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	res, err := audit.Verify(f)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "audit log OK: %d records, head %s\n", res.Records, res.Head)
	return nil
}

func cmdKeygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	alg := fs.String("alg", "ES256", "ES256, EdDSA or RS256")
	out := fs.String("out", "", "private key output file (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("keygen: --out is required")
	}
	k, err := jose.GenerateKey(jose.Algorithm(*alg))
	if err != nil {
		return err
	}
	priv, err := jose.MarshalPrivateKeyPEM(k)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, priv, 0o600); err != nil {
		return err
	}
	pub, err := jose.MarshalPublicKeyPEM(k.Public())
	if err != nil {
		return err
	}
	_, err = stdout.Write(pub)
	return err
}

func cmdDevCert(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("dev-cert", flag.ContinueOnError)
	hosts := fs.String("hosts", "127.0.0.1,localhost", "comma-separated DNS names / IPs")
	certOut := fs.String("cert", "tls.crt", "certificate output")
	keyOut := fs.String("key", "tls.key", "key output")
	days := fs.Int("days", 30, "validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, k, err := devcert.Generate(strings.Split(*hosts, ","), time.Now(), time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*certOut, c, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*keyOut, k, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote %s and %s (self-signed, %d days, hosts %s)\n", *certOut, *keyOut, *days, *hosts)
	return nil
}
