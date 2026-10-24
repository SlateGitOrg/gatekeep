// Package server wires a validated configuration into a running gateway:
// secrets from the environment, OIDC discovery, device registry, policies,
// audit log and upstream assertion key.
package server

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/archit2501/gatekeep/internal/audit"
	"github.com/archit2501/gatekeep/internal/config"
	"github.com/archit2501/gatekeep/internal/gateway"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/oidc"
	"github.com/archit2501/gatekeep/internal/policy"
	"github.com/archit2501/gatekeep/internal/posture"
	"github.com/archit2501/gatekeep/internal/replay"
	"github.com/archit2501/gatekeep/internal/session"
)

// Deps are injectable dependencies; zero values use production defaults.
type Deps struct {
	Getenv func(string) string
	Now    func() time.Time
	Logger *slog.Logger
	// HTTPClient talks to the IdP. Default: system roots plus oidc.ca_file.
	HTTPClient *http.Client
	// AuditWriter overrides audit.file (tests and the demo).
	AuditWriter io.Writer
	// Transport is used for upstream requests.
	Transport http.RoundTripper
	// JWKSMinRefresh overrides the JWKS refetch rate limit (tests).
	JWKSMinRefresh time.Duration
}

// Built is a ready gateway plus resources to release on shutdown.
type Built struct {
	Gateway  *gateway.Gateway
	Policies map[string]*policy.Policy
	Audit    *audit.Logger
	closers  []io.Closer
}

// Close releases resources (the audit file).
func (b *Built) Close() error {
	var errs []error
	for _, c := range b.closers {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}

// CompilePolicies compiles every route's rules. Anonymous routes without
// rules get a nil policy (allow).
func CompilePolicies(cfg *config.Config) (map[string]*policy.Policy, error) {
	eng, err := policy.NewEngine(cfg.Policy.CostLimit)
	if err != nil {
		return nil, err
	}
	out := map[string]*policy.Policy{}
	var errs []error
	for _, r := range cfg.Routes {
		if len(r.Rules) == 0 {
			out[r.Name] = nil
			continue
		}
		p, err := eng.Compile(r.Rules)
		if err != nil {
			errs = append(errs, fmt.Errorf("route %q: %w", r.Name, err))
			continue
		}
		out[r.Name] = p
	}
	return out, errors.Join(errs...)
}

// Build constructs the gateway. It performs OIDC discovery, so the IdP must
// be reachable.
func Build(ctx context.Context, cfg *config.Config, d Deps) (*Built, error) {
	if d.Getenv == nil {
		d.Getenv = os.Getenv
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	secrets, err := ParseSecrets(d.Getenv(cfg.Session.SecretsEnv))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.Session.SecretsEnv, err)
	}
	ring, err := session.NewKeyRing(secrets...)
	if err != nil {
		return nil, err
	}
	csrfKey, err := hkdf.Key(sha256.New, secrets[0], nil, "gatekeep csrf v1", 32)
	if err != nil {
		return nil, fmt.Errorf("derive csrf key: %w", err)
	}
	clientSecret := d.Getenv(cfg.OIDC.ClientSecretEnv)
	if clientSecret == "" {
		return nil, fmt.Errorf("client secret env %s is empty", cfg.OIDC.ClientSecretEnv)
	}
	hc := d.HTTPClient
	if hc == nil {
		hc, err = idpClient(cfg.Resolve(cfg.OIDC.CAFile))
		if err != nil {
			return nil, err
		}
	}
	pub, _ := url.Parse(cfg.PublicURL)
	rp, err := oidc.NewClient(ctx, hc, oidc.Config{
		Issuer: cfg.OIDC.Issuer, ClientID: cfg.OIDC.ClientID, ClientSecret: clientSecret,
		RedirectURL: strings.TrimSuffix(cfg.PublicURL, "/") + "/.gatekeep/callback",
		Scopes:      cfg.OIDC.Scopes, Leeway: cfg.OIDC.Leeway, MaxTokenAge: cfg.OIDC.MaxTokenAge,
		MaxAuthAge: cfg.OIDC.MaxAuthAge, JWKSMinRefresh: d.JWKSMinRefresh, Now: d.Now,
	})
	if err != nil {
		return nil, err
	}
	rp.Keys.Logger = d.Logger
	devices, err := LoadDevices(cfg)
	if err != nil {
		return nil, err
	}
	signer, err := upstreamSigner(cfg, d.Logger)
	if err != nil {
		return nil, err
	}
	policies, err := CompilePolicies(cfg)
	if err != nil {
		return nil, err
	}
	routes := make([]*gateway.Route, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		u, err := url.Parse(r.Upstream)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", r.Name, err)
		}
		routes = append(routes, &gateway.Route{
			Name: r.Name, Host: r.Host, PathPrefix: r.PathPrefix, Upstream: u, StripPrefix: r.StripPrefix,
			Anonymous: r.Anonymous, RequireDevice: r.RequireDevice, DisableCSRF: r.DisableCSRF, Policy: policies[r.Name],
		})
	}
	router, err := gateway.NewRouter(routes)
	if err != nil {
		return nil, err
	}
	b := &Built{Policies: policies}
	switch {
	case d.AuditWriter != nil:
		b.Audit = audit.NewLogger(d.AuditWriter, d.Now)
	case cfg.Audit.File == "" || cfg.Audit.File == "-":
		b.Audit = audit.NewLogger(os.Stdout, d.Now)
	default:
		l, c, err := audit.OpenFile(cfg.Resolve(cfg.Audit.File), d.Now)
		if err != nil {
			return nil, err
		}
		b.Audit = l
		b.closers = append(b.closers, c)
	}
	g, err := gateway.New(gateway.Options{
		PublicURL: pub, Auth: rp, Cookies: ring, CSRFKey: csrfKey, CookieName: cfg.Session.CookieName,
		Lifetimes: session.Lifetimes{Absolute: cfg.Session.Absolute, Idle: cfg.Session.Idle, TouchInterval: time.Minute},
		LoginTTL:  cfg.Session.LoginTTL, Router: router,
		Posture: &posture.Verifier{
			Devices: devices, Audience: cfg.Posture.Audience, Leeway: cfg.OIDC.Leeway,
			MaxAge: cfg.Posture.AssertionAge, Replay: replay.New(100_000, d.Now), Now: d.Now,
		},
		PostureStore: posture.NewStore(d.Now), PostureMaxAge: cfg.Posture.MaxAge, PairingTTL: cfg.Posture.PairingTTL,
		UpstreamSigner: signer, Audit: b.Audit,
		Headers: gateway.HeaderPolicy{HSTSMaxAge: cfg.Headers.HSTSMaxAge, HSTSIncludeSubdomains: cfg.Headers.HSTSIncludeSubdomains},
		Logger:  d.Logger, Now: d.Now, Transport: d.Transport,
	})
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	b.Gateway = g
	return b, nil
}

// ParseSecrets decodes a comma-separated list of base64 (standard or URL,
// padded or not) secrets of at least 32 bytes. The first is primary.
func ParseSecrets(v string) ([][]byte, error) {
	if strings.TrimSpace(v) == "" {
		return nil, errors.New("no session secrets configured")
	}
	var out [][]byte
	for i, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		var b []byte
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err = enc.DecodeString(part); err == nil {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("secret %d is not base64", i)
		}
		if len(b) < 32 {
			return nil, fmt.Errorf("secret %d is %d bytes; need >= 32", i, len(b))
		}
		out = append(out, b)
	}
	return out, nil
}

func idpClient(caFile string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("oidc.ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("oidc.ca_file: no certificates found")
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, nil
}

// LoadDevices reads every enrolled device's public key.
func LoadDevices(cfg *config.Config) (map[string]posture.Device, error) {
	out := map[string]posture.Device{}
	for _, d := range cfg.Posture.Devices {
		b, err := os.ReadFile(cfg.Resolve(d.PublicKeyFile))
		if err != nil {
			return nil, fmt.Errorf("device %q: %w", d.ID, err)
		}
		k, err := jose.ParsePublicKeyPEM(b, d.ID)
		if err != nil {
			return nil, fmt.Errorf("device %q: %w", d.ID, err)
		}
		if a := k.Algorithm(); a != jose.EdDSA && a != jose.ES256 {
			return nil, fmt.Errorf("device %q: key must be Ed25519 or P-256", d.ID)
		}
		out[d.ID] = posture.Device{ID: d.ID, Owner: d.Owner, Key: k}
	}
	return out, nil
}

func upstreamSigner(cfg *config.Config, logger *slog.Logger) (*jose.Signer, error) {
	if cfg.Upstream.KeyFile == "" {
		logger.Warn("upstream_assertion.key_file not set; using an ephemeral key (assertions change on restart)")
		k, err := jose.GenerateKey(jose.ES256)
		if err != nil {
			return nil, err
		}
		pub, err := jose.NewJWK(k.Public(), "")
		if err != nil {
			return nil, err
		}
		return jose.NewSigner(k, "gk-"+pub.Thumbprint()[:12])
	}
	b, err := os.ReadFile(cfg.Resolve(cfg.Upstream.KeyFile))
	if err != nil {
		return nil, fmt.Errorf("upstream_assertion.key_file: %w", err)
	}
	k, err := jose.ParsePrivateKeyPEM(b)
	if err != nil {
		return nil, err
	}
	pub, err := jose.NewJWK(k.Public(), "")
	if err != nil {
		return nil, err
	}
	return jose.NewSigner(k, "gk-"+pub.Thumbprint()[:12])
}
