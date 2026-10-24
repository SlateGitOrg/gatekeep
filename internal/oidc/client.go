package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const maxBodySize = 1 << 20

// Metadata is the subset of OpenID Provider metadata gatekeep uses.
type Metadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	EndSessionEndpoint            string   `json:"end_session_endpoint,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	IDTokenSigningAlgs            []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

// Config configures a relying party.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Leeway       time.Duration
	MaxTokenAge  time.Duration
	MaxAuthAge   time.Duration
	// JWKSMinRefresh rate-limits JWKS refetches on unknown kids.
	JWKSMinRefresh time.Duration
	Now            func() time.Time
}

// Client is a configured OIDC relying party.
type Client struct {
	cfg      Config
	meta     Metadata
	http     *http.Client
	Keys     *RemoteKeySet
	Verifier *Verifier
}

// Discover fetches and validates provider metadata. The returned issuer must
// equal the configured issuer exactly (OIDC Discovery §4.3) and every
// endpoint must use https, which blocks mix-up and downgrade attacks.
func Discover(ctx context.Context, hc *http.Client, issuer string) (Metadata, error) {
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	var m Metadata
	if err := getJSON(ctx, hc, u, &m); err != nil {
		return Metadata{}, err
	}
	if m.Issuer != issuer {
		return Metadata{}, fmt.Errorf("oidc: discovery issuer %q != configured %q", m.Issuer, issuer)
	}
	for name, ep := range map[string]string{
		"authorization_endpoint": m.AuthorizationEndpoint,
		"token_endpoint":         m.TokenEndpoint,
		"jwks_uri":               m.JWKSURI,
	} {
		pu, err := url.Parse(ep)
		if err != nil || pu.Scheme != "https" || pu.Host == "" {
			return Metadata{}, fmt.Errorf("oidc: %s must be an absolute https URL, got %q", name, ep)
		}
	}
	if len(m.CodeChallengeMethodsSupported) > 0 && !slices.Contains(m.CodeChallengeMethodsSupported, "S256") {
		return Metadata{}, errors.New("oidc: provider does not support PKCE S256")
	}
	return m, nil
}

// NewClient performs discovery and wires a verifier backed by a remote JWKS.
func NewClient(ctx context.Context, hc *http.Client, cfg Config) (*Client, error) {
	if cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: client_id and redirect_url are required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	if !slices.Contains(cfg.Scopes, "openid") {
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}
	meta, err := Discover(ctx, hc, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	ks := NewRemoteKeySet(meta.JWKSURI, hc)
	ks.Now = cfg.Now
	if cfg.JWKSMinRefresh > 0 {
		ks.MinRefreshInterval = cfg.JWKSMinRefresh
	}
	return &Client{
		cfg:  cfg,
		meta: meta,
		http: hc,
		Keys: ks,
		Verifier: &Verifier{
			Issuer: meta.Issuer, ClientID: cfg.ClientID, Keys: ks,
			Leeway: cfg.Leeway, MaxTokenAge: cfg.MaxTokenAge, MaxAuthAge: cfg.MaxAuthAge, Now: cfg.Now,
		},
	}, nil
}

// Metadata returns the discovered provider metadata.
func (c *Client) Metadata() Metadata { return c.meta }

// AuthCodeURL builds the authorization request URL with PKCE S256.
func (c *Client) AuthCodeURL(state, nonce, codeVerifier string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", CodeChallengeS256(codeVerifier))
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(c.meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return c.meta.AuthorizationEndpoint + sep + q.Encode()
}

// TokenResponse is the token endpoint's successful response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

// TokenError is an RFC 6749 §5.2 error response.
type TokenError struct {
	Status      int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("oidc: token endpoint %d: %s %s", e.Status, e.Code, e.Description)
}

// Exchange redeems an authorization code using client_secret_basic and the
// PKCE code verifier.
func (c *Client) Exchange(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.RedirectURL)
	form.Set("code_verifier", codeVerifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1: credentials are form-urlencoded before Basic encoding.
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("oidc: read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		te := &TokenError{Status: resp.StatusCode}
		_ = json.Unmarshal(body, te)
		return nil, te
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tr.IDToken == "" {
		return nil, errors.New("oidc: token response has no id_token")
	}
	return &tr, nil
}

func getJSON(ctx context.Context, hc *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("oidc: request %s: %w", u, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: get %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: get %s: status %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodySize)).Decode(v); err != nil {
		return fmt.Errorf("oidc: decode %s: %w", u, err)
	}
	return nil
}
