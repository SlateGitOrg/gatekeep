// Package demo contains the pieces of gatekeep's offline end-to-end demo
// that are also reused by the end-to-end tests: a scripted browser that
// follows the OIDC redirect dance with a real cookie jar, and a "whoami"
// upstream application that verifies gatekeep's signed identity assertion.
package demo

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

// Hop is one HTTP exchange observed by the Browser.
type Hop struct {
	Method   string
	URL      string
	Status   int
	Location string
	// SetCookies are the raw Set-Cookie header values of the response.
	SetCookies []string
}

func (h Hop) String() string {
	s := fmt.Sprintf("%-4s %s -> %d", h.Method, h.URL, h.Status)
	if h.Location != "" {
		s += " (Location: " + h.Location + ")"
	}
	return s
}

// Response is the final response of a navigation.
type Response struct {
	Status int
	Header http.Header
	Body   string
	URL    *url.URL
	Hops   []Hop
}

// Browser is a minimal scripted user agent: it keeps cookies, sends
// browser-like navigation headers and records every redirect hop.
type Browser struct {
	Client *http.Client
	// MaxHops bounds redirect chains (default 10).
	MaxHops int
}

// NewBrowser returns a browser using transport (which must trust the test
// or demo certificates).
func NewBrowser(transport http.RoundTripper) *Browser {
	jar, _ := cookiejar.New(nil)
	return &Browser{
		Client: &http.Client{
			Transport: transport,
			Jar:       jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		MaxHops: 10,
	}
}

// Navigate performs a top-level GET and follows redirects.
func (b *Browser) Navigate(rawURL string) (*Response, error) {
	return b.Do(http.MethodGet, rawURL, "", nil)
}

// Do sends a request with navigation headers and follows redirects
// (POST becomes GET after 302/303, as browsers do).
func (b *Browser) Do(method, rawURL, contentType string, body io.Reader) (*Response, error) {
	var hops []Hop
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	for range b.MaxHops {
		req, err := http.NewRequest(method, u.String(), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		if method == http.MethodPost {
			req.Header.Set("Origin", u.Scheme+"://"+u.Host)
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
		}
		resp, err := b.Client.Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		hop := Hop{Method: method, URL: u.String(), Status: resp.StatusCode, Location: resp.Header.Get("Location"),
			SetCookies: resp.Header.Values("Set-Cookie")}
		hops = append(hops, hop)
		if resp.StatusCode < 300 || resp.StatusCode > 399 || hop.Location == "" {
			return &Response{Status: resp.StatusCode, Header: resp.Header, Body: string(data), URL: u, Hops: hops}, nil
		}
		next, err := u.Parse(hop.Location)
		if err != nil {
			return nil, err
		}
		u, method, body, contentType = next, http.MethodGet, nil, ""
	}
	return nil, errors.New("demo: too many redirects")
}

var (
	formAction = regexp.MustCompile(`<form method="post" action="([^"]+)"`)
	hiddenReq  = regexp.MustCompile(`name="req" value="([^"]+)"`)
)

// SubmitLogin fills the IdP login form found in page and follows the
// resulting redirects back through gatekeep.
func (b *Browser) SubmitLogin(page *Response, username, password string) (*Response, error) {
	am := formAction.FindStringSubmatch(page.Body)
	rm := hiddenReq.FindStringSubmatch(page.Body)
	if am == nil || rm == nil {
		return nil, fmt.Errorf("demo: no login form on %s (status %d)", page.URL, page.Status)
	}
	action, err := page.URL.Parse(am[1])
	if err != nil {
		return nil, err
	}
	form := url.Values{"req": {rm[1]}, "username": {username}, "password": {password}}
	resp, err := b.Do(http.MethodPost, action.String(), "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	resp.Hops = append(append([]Hop{}, page.Hops...), resp.Hops...)
	return resp, nil
}

// Login navigates to target, signs in at the IdP and returns the final page.
func (b *Browser) Login(target, username, password string) (*Response, error) {
	page, err := b.Navigate(target)
	if err != nil {
		return nil, err
	}
	return b.SubmitLogin(page, username, password)
}

// Cookie returns the value of the named cookie for u, or "".
func (b *Browser) Cookie(u, name string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return ""
	}
	for _, c := range b.Client.Jar.Cookies(pu) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// SetCookie overwrites a cookie in the jar (used to simulate tampering).
func (b *Browser) SetCookie(u, name, value string) {
	pu, err := url.Parse(u)
	if err != nil {
		return
	}
	b.Client.Jar.SetCookies(pu, []*http.Cookie{{Name: name, Value: value, Path: "/", Secure: pu.Scheme == "https"}})
}
