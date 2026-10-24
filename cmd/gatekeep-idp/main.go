// Command gatekeep-idp runs the minimal demo OpenID Connect provider.
//
//	gatekeep-idp serve --config idp.yaml
//	gatekeep-idp hash-password [--iterations N] < password
//
// It exists so gatekeep can be exercised end to end without an external
// identity provider. Do not use it to protect anything real.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/archit2501/gatekeep/internal/idp"
	"github.com/archit2501/gatekeep/internal/jose"
)

type fileConfig struct {
	Issuer      string        `yaml:"issuer"`
	Listen      string        `yaml:"listen"`
	CertFile    string        `yaml:"cert_file"`
	KeyFile     string        `yaml:"key_file"`
	TokenTTL    time.Duration `yaml:"token_ttl"`
	RotateEvery time.Duration `yaml:"rotate_every"`
	Clients     []struct {
		ID           string   `yaml:"id"`
		SecretEnv    string   `yaml:"secret_env"`
		RedirectURIs []string `yaml:"redirect_uris"`
	} `yaml:"clients"`
	Users []idp.User `yaml:"users"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "gatekeep-idp:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: gatekeep-idp serve --config idp.yaml | hash-password")
	}
	switch args[0] {
	case "serve":
		return serve(ctx, args[1:], stderr)
	case "hash-password":
		fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
		iter := fs.Int("iterations", idp.DefaultPBKDF2Iterations, "PBKDF2 iterations")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return errors.New("empty password on stdin")
		}
		h, err := idp.HashPassword(pw, *iter)
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, h)
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func loadConfig(path string, getenv func(string) string) (idp.Options, fileConfig, error) {
	var fc fileConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return idp.Options{}, fc, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&fc); err != nil {
		return idp.Options{}, fc, fmt.Errorf("%s: %w", path, err)
	}
	if fc.Listen == "" {
		fc.Listen = "127.0.0.1:9443"
	}
	dir := filepath.Dir(path)
	for _, p := range []*string{&fc.CertFile, &fc.KeyFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	keys, err := idp.NewKeyRing(jose.ES256, 1)
	if err != nil {
		return idp.Options{}, fc, err
	}
	opts := idp.Options{Issuer: fc.Issuer, Keys: keys, Users: fc.Users, TokenTTL: fc.TokenTTL}
	for _, c := range fc.Clients {
		secret := getenv(c.SecretEnv)
		if secret == "" {
			return idp.Options{}, fc, fmt.Errorf("client %q: env %s is empty", c.ID, c.SecretEnv)
		}
		opts.Clients = append(opts.Clients, idp.Client{ID: c.ID, Secret: secret, RedirectURIs: c.RedirectURIs})
	}
	return opts, fc, nil
}

func serve(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "idp.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	opts, fc, err := loadConfig(*cfgPath, os.Getenv)
	if err != nil {
		return err
	}
	opts.Logger = logger
	srv, err := idp.New(opts)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if fc.RotateEvery > 0 {
		go func() {
			t := time.NewTicker(fc.RotateEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					kid, err := srv.Keys().Rotate()
					logger.Info("rotated signing key", "kid", kid, "err", err)
				}
			}
		}()
	}
	hs := &http.Server{Addr: fc.Listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		logger.Info("demo idp listening", "addr", fc.Listen, "issuer", fc.Issuer)
		errc <- hs.ListenAndServeTLS(fc.CertFile, fc.KeyFile)
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}
