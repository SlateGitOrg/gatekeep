package demo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/archit2501/gatekeep/internal/config"
	"github.com/archit2501/gatekeep/internal/gateway"
	"github.com/archit2501/gatekeep/internal/idp"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/oidc"
	"github.com/archit2501/gatekeep/internal/posture"
	"github.com/archit2501/gatekeep/internal/server"
)

// StackOptions tunes the demo stack.
type StackOptions struct {
	Now           func() time.Time
	MutateIDToken func(*oidc.IDTokenClaims)
	AuditWriter   io.Writer
	Logger        *slog.Logger
	// PasswordIterations for demo users (default 10,000).
	PasswordIterations int
	// ExtraConfig is appended to the generated YAML config (top-level keys).
	ExtraConfig string
}

// Stack is a running IdP + gatekeep + upstream on loopback TLS listeners.
type Stack struct {
	IdP         *idp.Server
	IdPURL      string
	GatewayURL  string
	UpstreamURL string
	Built       *server.Built
	Config      *config.Config
	// Transport trusts the stack's TLS certificate.
	Transport http.RoundTripper
	// Devices are the enrolled demo devices' signers, by device ID.
	Devices map[string]*jose.Signer

	dir      string
	servers  []*httptest.Server
	upstream *httptest.Server
}

// DemoUsers are the IdP accounts: username -> (subject, groups). Every
// password is "<username>-pw".
var DemoUsers = []struct {
	Username, Subject, Email string
	Groups                   []string
}{
	{"alice", "user-alice", "alice@example.test", []string{"eng", "admins"}},
	{"bob", "user-bob", "bob@example.test", []string{"eng"}},
	{"carol", "user-carol", "carol@contractor.test", []string{"contractors"}},
}

// DemoDevices are enrolled devices and the posture each agent reports.
var DemoDevices = []struct {
	ID, Owner string
	Facts     posture.Facts
}{
	{"alice-laptop", "user-alice", posture.Facts{OS: "darwin", OSVersion: "15.1", DiskEncrypted: true, FirewallEnabled: true, ScreenLock: true, PatchAgeDays: 3}},
	{"bob-laptop", "user-bob", posture.Facts{OS: "linux", OSVersion: "6.8", DiskEncrypted: false, FirewallEnabled: true, ScreenLock: true, PatchAgeDays: 45}},
}

// RoutesYAML is the demo routing and policy configuration.
const RoutesYAML = `
routes:
  - name: public
    path_prefix: /public/
    upstream: UPSTREAM
    anonymous: true
  - name: wiki
    path_prefix: /wiki/
    upstream: UPSTREAM
    rules:
      - name: employees
        effect: allow
        expr: identity.email_verified && identity.email.endsWith("@example.test")
      - name: contractors-read-only
        effect: allow
        expr: '"contractors" in identity.groups && request.method in ["GET", "HEAD"]'
  - name: admin
    path_prefix: /admin/
    upstream: UPSTREAM
    require_device: true
    rules:
      - name: admins-on-compliant-devices
        effect: allow
        expr: >-
          "admins" in identity.groups && device.disk_encrypted && device.firewall_enabled
          && device.patch_age_days <= 14 && identity.auth_age < duration("12h")
      - name: no-deletes-without-screen-lock
        effect: deny
        expr: request.method == "DELETE" && !device.screen_lock
  - name: api
    path_prefix: /api/
    upstream: UPSTREAM
    strip_prefix: true
    rules:
      - name: engineers
        effect: allow
        expr: sets.intersects(identity.groups, ["eng", "admins"])
      - name: no-writes-off-hours
        effect: deny
        expr: request.method != "GET" && (request.time.getHours() < 6 || request.time.getHours() >= 22)
`

// StartStack launches the whole system on loopback.
func StartStack(ctx context.Context, o StackOptions) (st *Stack, err error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.PasswordIterations == 0 {
		o.PasswordIterations = 10_000
	}
	st = &Stack{Devices: map[string]*jose.Signer{}}
	defer func() {
		if err != nil {
			st.Close()
		}
	}()
	st.dir, err = os.MkdirTemp("", "gatekeep-demo-")
	if err != nil {
		return nil, err
	}

	var gwHandler, idpHandler http.Handler = http.NotFoundHandler(), http.NotFoundHandler()
	gwTS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gwHandler.ServeHTTP(w, r) }))
	idpTS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { idpHandler.ServeHTTP(w, r) }))
	st.servers = append(st.servers, gwTS, idpTS)
	st.GatewayURL, st.IdPURL, st.Transport = gwTS.URL, idpTS.URL, gwTS.Client().Transport

	users := make([]idp.User, 0, len(DemoUsers))
	for _, u := range DemoUsers {
		h, herr := idp.HashPassword(u.Username+"-pw", o.PasswordIterations)
		if herr != nil {
			return nil, herr
		}
		users = append(users, idp.User{Username: u.Username, PasswordHash: h, Subject: u.Subject,
			Email: u.Email, EmailVerified: true, Name: u.Username, Groups: u.Groups})
	}
	keys, err := idp.NewKeyRing(jose.ES256, 1)
	if err != nil {
		return nil, err
	}
	clientSecret, err := oidc.NewState()
	if err != nil {
		return nil, err
	}
	st.IdP, err = idp.New(idp.Options{
		Issuer: st.IdPURL, Keys: keys, Users: users, Now: o.Now, Logger: o.Logger, MutateIDToken: o.MutateIDToken,
		Clients: []idp.Client{{ID: "gatekeep", Secret: clientSecret, RedirectURIs: []string{st.GatewayURL + "/.gatekeep/callback"}}},
	})
	if err != nil {
		return nil, err
	}
	idpHandler = st.IdP

	var devYAML strings.Builder
	for _, d := range DemoDevices {
		k, kerr := jose.GenerateKey(jose.EdDSA)
		if kerr != nil {
			return nil, kerr
		}
		s, kerr := jose.NewSigner(k, d.ID)
		if kerr != nil {
			return nil, kerr
		}
		st.Devices[d.ID] = s
		pemBytes, kerr := jose.MarshalPublicKeyPEM(k.Public())
		if kerr != nil {
			return nil, kerr
		}
		p := filepath.Join(st.dir, d.ID+".pub.pem")
		if kerr := os.WriteFile(p, pemBytes, 0o600); kerr != nil {
			return nil, kerr
		}
		fmt.Fprintf(&devYAML, "    - {id: %s, owner: %s, public_key_file: %q}\n", d.ID, d.Owner, p)
	}

	ks := oidc.NewRemoteKeySet(st.GatewayURL+"/.gatekeep/jwks.json", gwTS.Client())
	ks.Now = o.Now
	auds := []string{}
	for _, n := range []string{"public", "wiki", "admin", "api"} {
		auds = append(auds, gateway.AssertionAudience(n))
	}
	upTS := httptest.NewServer(&WhoAmI{Name: "whoami", Issuer: st.GatewayURL, Audiences: auds, Keys: ks, Now: o.Now})
	st.servers = append(st.servers, upTS)
	st.upstream = upTS
	st.UpstreamURL = upTS.URL

	yml := fmt.Sprintf(`
public_url: %s
oidc:
  issuer: %s
  client_id: gatekeep
session:
  absolute_timeout: 8h
  idle_timeout: 1h
posture:
  max_age: 10m
  devices:
%s%s
%s`, st.GatewayURL, st.IdPURL, devYAML.String(), strings.ReplaceAll(RoutesYAML, "UPSTREAM", st.UpstreamURL), o.ExtraConfig)
	st.Config, err = config.Parse([]byte(yml))
	if err != nil {
		return nil, err
	}
	secret, err := sessionSecret()
	if err != nil {
		return nil, err
	}
	env := map[string]string{"GATEKEEP_CLIENT_SECRET": clientSecret, "GATEKEEP_SESSION_SECRETS": secret}
	st.Built, err = server.Build(ctx, st.Config, server.Deps{
		Getenv: func(k string) string { return env[k] }, Now: o.Now, Logger: o.Logger,
		HTTPClient: idpTS.Client(), AuditWriter: o.AuditWriter, JWKSMinRefresh: time.Millisecond,
	})
	if err != nil {
		return nil, err
	}
	gwHandler = st.Built.Gateway
	return st, nil
}

func sessionSecret() (string, error) {
	s, err := oidc.NewCodeVerifier() // 32 random bytes, base64url
	if err != nil {
		return "", err
	}
	return s, nil
}

// Agent returns a posture agent for an enrolled demo device.
func (s *Stack) Agent(deviceID string, now func() time.Time) *posture.Agent {
	var facts posture.Facts
	for _, d := range DemoDevices {
		if d.ID == deviceID {
			facts = d.Facts
		}
	}
	return &posture.Agent{
		DeviceID: deviceID, Signer: s.Devices[deviceID], Collector: StaticCollector(facts),
		ProxyURL: s.GatewayURL, Audience: s.Config.Posture.Audience,
		Client: &http.Client{Transport: s.Transport}, Now: now,
	}
}

// StaticCollector reports fixed facts (the demo has no real MDM).
type StaticCollector posture.Facts

// Collect implements posture.Collector.
func (c StaticCollector) Collect(context.Context) (posture.Facts, error) {
	f := posture.Facts(c)
	f.AgentVersion = posture.AgentVersion
	return f, nil
}

// StopUpstream shuts down the demo upstream (to exercise upstream failure).
func (s *Stack) StopUpstream() { s.upstream.Close() }

// Close stops all servers and removes temporary files.
func (s *Stack) Close() {
	for _, ts := range s.servers {
		ts.Close()
	}
	if s.Built != nil {
		_ = s.Built.Close()
	}
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
}
