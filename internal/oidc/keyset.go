package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/jose"
)

// Bounds applied to the JWKS cache lifetime advertised by the IdP.
const (
	DefaultKeyTTL   = time.Hour
	MinKeyTTL       = time.Minute
	MaxKeyTTL       = 24 * time.Hour
	maxJWKSBodySize = 256 << 10
)

// ErrUnknownKey is returned when no key with the token's kid exists even
// after a permitted refresh.
var ErrUnknownKey = errors.New("oidc: signing key not found in JWKS")

// RemoteKeySet caches an IdP's JWKS and handles key rotation:
//
//   - keys are served from cache until their TTL (Cache-Control max-age,
//     clamped to [MinKeyTTL, MaxKeyTTL]) expires;
//   - an unknown kid triggers a refetch, so newly rotated-in keys are picked
//     up immediately;
//   - refetches are rate-limited to one per MinRefreshInterval, so a flood of
//     tokens with random kids cannot turn the proxy into a JWKS DoS amplifier;
//   - concurrent callers share one in-flight fetch;
//   - if a refresh fails the previous keys stay usable until expiry
//     (stale-if-error), but a kid absent from them still fails.
type RemoteKeySet struct {
	URL                string
	Client             *http.Client
	MinRefreshInterval time.Duration
	Now                func() time.Time
	Logger             *slog.Logger

	mu        sync.Mutex
	keys      *jose.JWKSet
	expires   time.Time
	lastFetch time.Time
	inflight  chan struct{}
	fetches   int
}

// NewRemoteKeySet returns a key set for url.
func NewRemoteKeySet(url string, client *http.Client) *RemoteKeySet {
	return &RemoteKeySet{URL: url, Client: client, MinRefreshInterval: 10 * time.Second}
}

func (r *RemoteKeySet) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Fetches reports how many network fetches have been made (for tests and
// metrics).
func (r *RemoteKeySet) Fetches() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetches
}

// Key returns the verification key for kid. When kid is empty the set must
// contain exactly one key usable with alg.
func (r *RemoteKeySet) Key(ctx context.Context, kid string, alg jose.Algorithm) (jose.JWK, error) {
	if k, ok := r.lookup(kid, alg, false); ok {
		return k, nil
	}
	if err := r.refresh(ctx); err != nil {
		if k, ok := r.lookup(kid, alg, true); ok {
			return k, nil
		}
		return jose.JWK{}, err
	}
	if k, ok := r.lookup(kid, alg, true); ok {
		return k, nil
	}
	return jose.JWK{}, fmt.Errorf("%w: kid %q", ErrUnknownKey, kid)
}

func (r *RemoteKeySet) lookup(kid string, alg jose.Algorithm, allowStale bool) (jose.JWK, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil || (!allowStale && !r.now().Before(r.expires)) {
		return jose.JWK{}, false
	}
	if kid != "" {
		k, ok := r.keys.Lookup(kid)
		return k, ok && k.Algorithm() == alg
	}
	var found jose.JWK
	n := 0
	for _, k := range r.keys.Keys {
		if k.Algorithm() == alg {
			found = k
			n++
		}
	}
	return found, n == 1
}

// refresh fetches the JWKS unless rate-limited; concurrent callers wait for
// the single in-flight request.
func (r *RemoteKeySet) refresh(ctx context.Context) error {
	r.mu.Lock()
	if ch := r.inflight; ch != nil {
		r.mu.Unlock()
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("oidc: waiting for jwks: %w", ctx.Err())
		}
	}
	now := r.now()
	if !r.lastFetch.IsZero() && now.Sub(r.lastFetch) < r.MinRefreshInterval {
		r.mu.Unlock()
		return nil // rate-limited; caller re-checks the existing set
	}
	ch := make(chan struct{})
	r.inflight = ch
	r.lastFetch = now
	r.fetches++
	r.mu.Unlock()

	set, ttl, err := r.fetch(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.inflight = nil
	close(ch)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("jwks refresh failed", "url", r.URL, "err", err)
		}
		return err
	}
	r.keys = set
	r.expires = r.now().Add(ttl)
	return nil
}

func (r *RemoteKeySet) fetch(ctx context.Context) (*jose.JWKSet, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("oidc: jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("oidc: fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("oidc: fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodySize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("oidc: read jwks: %w", err)
	}
	if len(body) > maxJWKSBodySize {
		return nil, 0, errors.New("oidc: jwks too large")
	}
	set, err := jose.ParseJWKSet(body)
	if err != nil {
		return nil, 0, err
	}
	return set, cacheTTL(resp.Header.Get("Cache-Control")), nil
}

// cacheTTL extracts max-age from a Cache-Control header, clamped.
func cacheTTL(h string) time.Duration {
	ttl := DefaultKeyTTL
	for _, d := range strings.Split(h, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if v, ok := strings.CutPrefix(d, "max-age="); ok {
			if secs, err := strconv.Atoi(v); err == nil {
				ttl = time.Duration(secs) * time.Second
			}
		}
		if d == "no-store" || d == "no-cache" {
			ttl = MinKeyTTL
		}
	}
	return min(max(ttl, MinKeyTTL), MaxKeyTTL)
}
