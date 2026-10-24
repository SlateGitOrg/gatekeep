package gateway

import (
	"io"
	"net/http"
	"strings"

	"github.com/archit2501/gatekeep/internal/audit"
	"github.com/archit2501/gatekeep/internal/posture"
)

// Device pairing flow:
//
//  1. A signed-in user opens /.gatekeep/device and presses "Pair" (POST with
//     CSRF token) to get a single-use pairing code bound to their session.
//  2. They run `posture-agent pair --code CODE` on the device. The agent
//     signs posture with the device key using the code as nonce and POSTs it
//     to /.gatekeep/device/report.
//  3. The proxy verifies signature, freshness, jti and that the device is
//     registered to the same subject, then returns a binding ID which the
//     agent uses as nonce for periodic refreshes.

const maxReportSize = 16 << 10

func (g *Gateway) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	s, _ := g.readSession(r)
	if s == nil {
		g.startLogin(w, r, reservedPrefix+"device")
		return
	}
	info := g.deviceInfo(s)
	g.renderPage(w, http.StatusOK, pageData{
		Title:   "Device posture",
		Message: "Signed in as " + displayName(s.Email, s.Subject) + ". Device state: " + info.State + deviceSuffix(info) + ".",
		Form:    &formData{Action: reservedPrefix + "device/pair", CSRF: g.csrfToken(s.ID), Button: "Pair a device"},
	})
}

func deviceSuffix(d deviceInfo) string {
	if d.ID == "" {
		return ""
	}
	return " (" + d.ID + ")"
}

func displayName(email, sub string) string {
	if email != "" {
		return email
	}
	return sub
}

func (g *Gateway) handlePair(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	s, _ := g.readSession(r)
	ev := audit.Event{
		Kind: audit.KindDevice, RequestID: requestID(r.Context()), Method: r.Method, Host: r.Host,
		Path: r.URL.Path, ClientIP: clientIP(r), Decision: "fail",
	}
	if s == nil {
		ev.Reason, ev.Status = reasonNoSession, http.StatusUnauthorized
		g.audit(ev)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	ev.Subject, ev.Email = s.Subject, s.Email
	if err := g.requireCSRF(r, s.ID); err != nil {
		ev.Reason, ev.Status = "csrf", http.StatusForbidden
		g.audit(ev)
		g.renderError(w, r, http.StatusForbidden, "Request blocked", "Missing or invalid CSRF token.", "csrf")
		return
	}
	code, err := g.opts.PostureStore.NewPairing(s.ID, s.Subject, g.opts.PairingTTL)
	if err != nil {
		ev.Reason, ev.Status = "internal_error", http.StatusInternalServerError
		g.audit(ev)
		g.renderError(w, r, http.StatusInternalServerError, "Pairing failed", "Could not create a pairing code.", "internal_error")
		return
	}
	ev.Decision, ev.Reason, ev.Status = "ok", "pairing_issued", http.StatusOK
	g.audit(ev)
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"code": code, "expires_in": int(g.opts.PairingTTL.Seconds())})
		return
	}
	g.renderPage(w, http.StatusOK, pageData{
		Title:   "Pairing code",
		Message: "Run the posture agent on your device within " + g.opts.PairingTTL.String() + ":",
		Code:    "posture-agent pair --proxy " + g.origin + " --code " + code,
	})
}

func (g *Gateway) handleReport(w http.ResponseWriter, r *http.Request) {
	ev := audit.Event{
		Kind: audit.KindDevice, RequestID: requestID(r.Context()), Method: r.Method, Host: r.Host,
		Path: r.URL.Path, ClientIP: clientIP(r), Decision: "fail",
	}
	reject := func(status int, reason string) {
		ev.Reason, ev.Status = reason, status
		g.audit(ev)
		writeJSON(w, status, posture.ReportResponse{Accepted: false, Reason: reason})
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReportSize+1))
	if err != nil || len(body) > maxReportSize {
		reject(http.StatusRequestEntityTooLarge, "report_too_large")
		return
	}
	claims, dev, err := g.opts.Posture.Verify(strings.TrimSpace(string(body)))
	if err != nil {
		g.opts.Logger.Info("posture assertion rejected", "err", err)
		reject(http.StatusForbidden, posture.Reason(err))
		return
	}
	ev.DeviceID, ev.Subject = dev.ID, dev.Owner
	binding, _, err := g.opts.PostureStore.Accept(claims, dev, g.opts.Lifetimes.Absolute)
	if err != nil {
		reject(http.StatusForbidden, posture.Reason(err))
		return
	}
	ev.Decision, ev.Reason, ev.Status, ev.Device = "ok", "posture_accepted", http.StatusOK, deviceFresh
	g.audit(ev)
	writeJSON(w, http.StatusOK, posture.ReportResponse{
		Accepted: true, Binding: binding, MaxAgeSecs: int(g.opts.PostureMaxAge.Seconds()),
	})
}
