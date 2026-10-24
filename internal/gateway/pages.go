package gateway

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

//go:embed page.html
var pageHTML string

var pageTmpl = template.Must(template.New("page").Parse(pageHTML))

type formData struct {
	Action string
	CSRF   string
	Button string
}

type pageData struct {
	Title     string
	Message   string
	Reason    string
	RequestID string
	Code      string
	Link      string
	LinkText  string
	Form      *formData
}

func (g *Gateway) renderPage(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTmpl.Execute(w, d); err != nil {
		g.opts.Logger.Error("render page", "err", err)
	}
}

// renderError answers with JSON for API clients and HTML for browsers. Only
// the reason code and request ID are disclosed; the audit log holds detail.
func (g *Gateway) renderError(w http.ResponseWriter, r *http.Request, status int, title, msg, reason string) {
	g.renderErrorLink(w, r, status, title, msg, reason, "", "")
}

func (g *Gateway) renderErrorLink(w http.ResponseWriter, r *http.Request, status int, title, msg, reason, link, linkText string) {
	rid := requestID(r.Context())
	if wantsJSON(r) {
		writeJSON(w, status, map[string]string{"error": reason, "message": msg, "request_id": rid})
		return
	}
	g.renderPage(w, status, pageData{Title: title, Message: msg, Reason: reason, RequestID: rid, Link: link, LinkText: linkText})
}

func wantsJSON(r *http.Request) bool {
	a := r.Header.Get("Accept")
	return strings.Contains(a, "application/json") && !strings.Contains(a, "text/html")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
