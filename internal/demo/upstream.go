package demo

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/archit2501/gatekeep/internal/gateway"
	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/oidc"
)

// WhoAmI is a demo upstream application. It trusts nothing gatekeep sends
// in plain headers: every request must carry a valid X-Gatekeep-Assertion
// signed by a key in gatekeep's JWKS, issued by the expected origin, for one
// of this app's audiences, and not expired.
type WhoAmI struct {
	Name      string
	Issuer    string // gatekeep public origin
	Audiences []string
	Keys      oidc.KeySource
	Now       func() time.Time
}

// WhoAmIResponse is what the app returns.
type WhoAmIResponse struct {
	App         string   `json:"app"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Subject     string   `json:"sub"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	DeviceID    string   `json:"device_id,omitempty"`
	DeviceState string   `json:"device_state,omitempty"`
	Audience    string   `json:"audience,omitempty"`
	RequestID   string   `json:"request_id,omitempty"`
	CookiesSeen []string `json:"cookies_seen"`
	// UserHeader echoes X-Gatekeep-User as received, to show that client
	// supplied values never reach the upstream.
	UserHeader string `json:"user_header,omitempty"`
	Anonymous   bool     `json:"anonymous,omitempty"`
}

func (a *WhoAmI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := WhoAmIResponse{App: a.Name, Method: r.Method, Path: r.URL.Path, CookiesSeen: []string{},
		UserHeader: r.Header.Get(gateway.HeaderUser)}
	for _, c := range r.Cookies() {
		resp.CookiesSeen = append(resp.CookiesSeen, c.Name)
	}
	sort.Strings(resp.CookiesSeen)
	raw := r.Header.Get(gateway.HeaderAssertion)
	if raw == "" {
		resp.Anonymous = true
		resp.RequestID = r.Header.Get(gateway.HeaderRequestID)
		writeJSON(w, http.StatusOK, resp)
		return
	}
	claims, err := a.verify(r.Context(), raw)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid gatekeep assertion: " + err.Error()})
		return
	}
	resp.Subject, resp.Email, resp.Groups = claims.Subject, claims.Email, claims.Groups
	resp.DeviceID, resp.DeviceState, resp.RequestID = claims.DeviceID, claims.DeviceState, claims.RequestID
	for _, aud := range claims.Audience {
		if slices.Contains(a.Audiences, aud) {
			resp.Audience = aud
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *WhoAmI) verify(ctx context.Context, raw string) (*gateway.IdentityAssertion, error) {
	p, err := jose.Parse(raw)
	if err != nil {
		return nil, err
	}
	if p.Header.Typ != gateway.AssertionType {
		return nil, jose.ErrMalformed
	}
	k, err := a.Keys.Key(ctx, p.Header.Kid, p.Header.Alg)
	if err != nil {
		return nil, err
	}
	if err := p.Verify(k); err != nil {
		return nil, err
	}
	var c gateway.IdentityAssertion
	if err := p.DecodeClaims(&c); err != nil {
		return nil, err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if err := c.Validate(jose.Expectations{Issuer: a.Issuer, Now: now, Leeway: 5 * time.Second}); err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(a.Audiences, c.Audience.Contains) {
		return nil, jose.ErrAudience
	}
	return &c, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Powered-By", "whoami-demo") // gatekeep strips this
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
