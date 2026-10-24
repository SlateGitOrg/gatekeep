// Package config loads and validates gatekeep's YAML configuration. Secrets
// are never read from the file itself: the file names environment variables
// that hold them.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/archit2501/gatekeep/internal/policy"
)

// Config is the root configuration document.
type Config struct {
	Listen    string    `yaml:"listen"`
	PublicURL string    `yaml:"public_url"`
	TLS       TLS       `yaml:"tls"`
	OIDC      OIDC      `yaml:"oidc"`
	Session   Session   `yaml:"session"`
	Posture   Posture   `yaml:"posture"`
	Upstream  Upstream  `yaml:"upstream_assertion"`
	Audit     Audit     `yaml:"audit"`
	Headers   Headers   `yaml:"security_headers"`
	Policy    PolicyCfg `yaml:"policy"`
	Routes    []Route   `yaml:"routes"`

	// dir is the config file's directory; relative paths resolve against it.
	dir string
}

// TLS configures the listener.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// OIDC configures the relying party.
type OIDC struct {
	Issuer          string        `yaml:"issuer"`
	ClientID        string        `yaml:"client_id"`
	ClientSecretEnv string        `yaml:"client_secret_env"`
	Scopes          []string      `yaml:"scopes"`
	CAFile          string        `yaml:"ca_file"`
	Leeway          time.Duration `yaml:"leeway"`
	MaxTokenAge     time.Duration `yaml:"max_token_age"`
	MaxAuthAge      time.Duration `yaml:"max_auth_age"`
}

// Session configures cookies.
type Session struct {
	CookieName string        `yaml:"cookie_name"`
	SecretsEnv string        `yaml:"secrets_env"`
	Absolute   time.Duration `yaml:"absolute_timeout"`
	Idle       time.Duration `yaml:"idle_timeout"`
	LoginTTL   time.Duration `yaml:"login_ttl"`
}

// Posture configures device posture.
type Posture struct {
	Audience     string        `yaml:"audience"`
	MaxAge       time.Duration `yaml:"max_age"`
	AssertionAge time.Duration `yaml:"assertion_max_age"`
	PairingTTL   time.Duration `yaml:"pairing_ttl"`
	Devices      []Device      `yaml:"devices"`
}

// Device is an enrolled device.
type Device struct {
	ID            string `yaml:"id"`
	Owner         string `yaml:"owner"`
	PublicKeyFile string `yaml:"public_key_file"`
}

// Upstream configures the signed identity assertion sent to upstreams.
type Upstream struct {
	KeyFile string `yaml:"key_file"`
}

// Audit configures the decision log.
type Audit struct {
	File string `yaml:"file"`
}

// Headers configures security headers.
type Headers struct {
	HSTSMaxAge            int  `yaml:"hsts_max_age"`
	HSTSIncludeSubdomains bool `yaml:"hsts_include_subdomains"`
}

// PolicyCfg configures the CEL engine.
type PolicyCfg struct {
	CostLimit uint64 `yaml:"cost_limit"`
}

// Route is a proxied application.
type Route struct {
	Name          string            `yaml:"name"`
	Host          string            `yaml:"host"`
	PathPrefix    string            `yaml:"path_prefix"`
	Upstream      string            `yaml:"upstream"`
	StripPrefix   bool              `yaml:"strip_prefix"`
	Anonymous     bool              `yaml:"anonymous"`
	RequireDevice bool              `yaml:"require_device"`
	DisableCSRF   bool              `yaml:"disable_csrf"`
	Rules         []policy.RuleSpec `yaml:"rules"`
}

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.dir = filepath.Dir(path)
	return c, nil
}

// Parse decodes YAML strictly (unknown keys are errors), applies defaults
// and validates.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.OIDC.ClientSecretEnv == "" {
		c.OIDC.ClientSecretEnv = "GATEKEEP_CLIENT_SECRET"
	}
	if len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid", "email", "profile", "groups"}
	}
	def(&c.OIDC.Leeway, 30*time.Second)
	def(&c.OIDC.MaxTokenAge, 10*time.Minute)
	if c.Session.CookieName == "" {
		c.Session.CookieName = "gatekeep"
	}
	if c.Session.SecretsEnv == "" {
		c.Session.SecretsEnv = "GATEKEEP_SESSION_SECRETS"
	}
	def(&c.Session.Absolute, 8*time.Hour)
	def(&c.Session.Idle, time.Hour)
	def(&c.Session.LoginTTL, 10*time.Minute)
	if c.Posture.Audience == "" {
		c.Posture.Audience = c.PublicURL
	}
	def(&c.Posture.MaxAge, 10*time.Minute)
	def(&c.Posture.AssertionAge, 2*time.Minute)
	def(&c.Posture.PairingTTL, 5*time.Minute)
	if c.Headers.HSTSMaxAge == 0 {
		c.Headers.HSTSMaxAge = 31536000
	}
}

// Validate checks semantic constraints. All problems are reported together.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	pu, err := url.Parse(c.PublicURL)
	if err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" || (pu.Path != "" && pu.Path != "/") {
		add("public_url must be an origin like https://gatekeep.example (got %q)", c.PublicURL)
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		add("tls.cert_file and tls.key_file must be set together")
	}
	iu, err := url.Parse(c.OIDC.Issuer)
	if err != nil || iu.Scheme != "https" || iu.Host == "" {
		add("oidc.issuer must be an https URL (got %q)", c.OIDC.Issuer)
	}
	if c.OIDC.ClientID == "" {
		add("oidc.client_id is required")
	}
	if c.Session.Idle > c.Session.Absolute {
		add("session.idle_timeout must not exceed absolute_timeout")
	}
	if c.Posture.AssertionAge > 5*time.Minute {
		add("posture.assertion_max_age must be <= 5m")
	}
	seenDev := map[string]bool{}
	for i, d := range c.Posture.Devices {
		if d.ID == "" || d.Owner == "" || d.PublicKeyFile == "" {
			add("posture.devices[%d]: id, owner and public_key_file are required", i)
		}
		if seenDev[d.ID] {
			add("posture.devices[%d]: duplicate id %q", i, d.ID)
		}
		seenDev[d.ID] = true
	}
	if len(c.Routes) == 0 {
		add("at least one route is required")
	}
	for i, r := range c.Routes {
		if r.Name == "" {
			add("routes[%d]: name is required", i)
		}
		if !strings.HasPrefix(r.PathPrefix, "/") {
			add("routes[%d] (%s): path_prefix must start with /", i, r.Name)
		}
		if !r.Anonymous && len(r.Rules) == 0 {
			add("routes[%d] (%s): protected routes need at least one rule (default is deny)", i, r.Name)
		}
		if u, err := url.Parse(r.Upstream); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("routes[%d] (%s): upstream must be an absolute http(s) URL", i, r.Name)
		}
	}
	return errors.Join(errs...)
}

// Resolve returns p relative to the config file's directory.
func (c *Config) Resolve(p string) string {
	if p == "" || filepath.IsAbs(p) || c.dir == "" {
		return p
	}
	return filepath.Join(c.dir, p)
}
