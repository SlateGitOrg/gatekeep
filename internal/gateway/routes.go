package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/SlateGitOrg/gatekeep/internal/policy"
)

// Route is a protected (or anonymous) upstream mapping.
type Route struct {
	Name string
	// Host restricts the route to one Host header value ("" matches any).
	Host string
	// PathPrefix must start with "/". "/" matches everything.
	PathPrefix string
	Upstream   *url.URL
	// StripPrefix removes PathPrefix before forwarding.
	StripPrefix bool
	// Anonymous routes do not require login; identity may still be present.
	Anonymous bool
	// RequireDevice demands fresh, verified posture before policy runs.
	RequireDevice bool
	// DisableCSRF turns off the origin check for unsafe methods.
	DisableCSRF bool
	Policy      *policy.Policy
}

// Router selects the most specific route: an exact host match beats a
// wildcard, then the longest path prefix wins. Matching is O(r) in the number
// of routes, which is small and fixed at startup.
type Router struct {
	routes []*Route
}

// NewRouter validates and orders routes.
func NewRouter(routes []*Route) (*Router, error) {
	seen := map[string]bool{}
	keys := map[string]bool{}
	for _, r := range routes {
		if r.Name == "" {
			return nil, errors.New("gateway: route without name")
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("gateway: duplicate route name %q", r.Name)
		}
		seen[r.Name] = true
		if !strings.HasPrefix(r.PathPrefix, "/") {
			return nil, fmt.Errorf("gateway: route %q: path_prefix must start with /", r.Name)
		}
		if strings.HasPrefix(r.PathPrefix, reservedPrefix) {
			return nil, fmt.Errorf("gateway: route %q: %s is reserved", r.Name, reservedPrefix)
		}
		if r.Upstream == nil || (r.Upstream.Scheme != "http" && r.Upstream.Scheme != "https") || r.Upstream.Host == "" {
			return nil, fmt.Errorf("gateway: route %q: upstream must be an absolute http(s) URL", r.Name)
		}
		if r.Policy == nil && !r.Anonymous {
			return nil, fmt.Errorf("gateway: route %q: protected routes need rules", r.Name)
		}
		k := strings.ToLower(r.Host) + "\x00" + r.PathPrefix
		if keys[k] {
			return nil, fmt.Errorf("gateway: route %q: duplicate host+path_prefix", r.Name)
		}
		keys[k] = true
	}
	sorted := append([]*Route(nil), routes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		hi, hj := sorted[i].Host != "", sorted[j].Host != ""
		if hi != hj {
			return hi
		}
		return len(sorted[i].PathPrefix) > len(sorted[j].PathPrefix)
	})
	return &Router{routes: sorted}, nil
}

// Match returns the route for host and path, or nil.
func (rt *Router) Match(host, path string) *Route {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, r := range rt.routes {
		if r.Host != "" && !strings.EqualFold(r.Host, host) {
			continue
		}
		if prefixMatch(r.PathPrefix, path) {
			return r
		}
	}
	return nil
}

// prefixMatch matches on path-segment boundaries: "/app" matches "/app" and
// "/app/x" but not "/application".
func prefixMatch(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

// Routes returns routes in match order.
func (rt *Router) Routes() []*Route { return rt.routes }
