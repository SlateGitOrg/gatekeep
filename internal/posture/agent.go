package posture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/jose"
)

// AgentVersion is reported in every assertion.
const AgentVersion = "gatekeep-agent/0.1"

// Collector gathers device facts.
type Collector interface {
	Collect(ctx context.Context) (Facts, error)
}

// SystemCollector reports what the agent can observe portably (OS, arch,
// hostname, kernel release) and overlays managed attributes — disk
// encryption, firewall, screen lock, patch age — from an MDM-style facts
// file. Probing those attributes natively is platform-specific and out of
// scope (see README Limitations); the file keeps the trust boundary explicit.
type SystemCollector struct {
	// FactsFile is a JSON document with Facts fields; values present there
	// override observed ones.
	FactsFile string
	// ReadFile and Hostname are injectable for tests.
	ReadFile func(string) ([]byte, error)
	Hostname func() (string, error)
}

// Collect implements Collector.
func (c SystemCollector) Collect(_ context.Context) (Facts, error) {
	readFile := c.ReadFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	hostname := c.Hostname
	if hostname == nil {
		hostname = os.Hostname
	}
	f := Facts{OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVersion: AgentVersion}
	if h, err := hostname(); err == nil {
		f.Hostname = h
	}
	f.OSVersion = kernelRelease(readFile)
	if c.FactsFile == "" {
		return f, nil
	}
	b, err := readFile(c.FactsFile)
	if err != nil {
		return Facts{}, fmt.Errorf("posture: read facts: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Facts{}, fmt.Errorf("posture: parse facts %s: %w", c.FactsFile, err)
	}
	f.AgentVersion = AgentVersion
	return f, nil
}

// kernelRelease reads the running kernel version where a portable file
// exists (Linux procfs); elsewhere it is left for the facts file.
func kernelRelease(readFile func(string) ([]byte, error)) string {
	b, err := readFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Agent signs posture and submits it to a gatekeep proxy.
type Agent struct {
	DeviceID  string
	Signer    *jose.Signer
	Collector Collector
	ProxyURL  string // e.g. https://gatekeep.example
	Audience  string
	Client    *http.Client
	Logger    *slog.Logger
	Now       func() time.Time
}

// ReportResponse is the proxy's answer to a posture report.
type ReportResponse struct {
	Binding    string `json:"binding"`
	Accepted   bool   `json:"accepted"`
	Reason     string `json:"reason,omitempty"`
	MaxAgeSecs int    `json:"max_age_seconds,omitempty"`
}

// Report collects facts, signs them with nonce (a pairing code or binding
// ID) and submits them. It returns the binding to use for refreshes.
func (a *Agent) Report(ctx context.Context, nonce string) (*ReportResponse, error) {
	facts, err := a.Collector.Collect(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	tok, err := Sign(a.Signer, a.DeviceID, a.Audience, nonce, facts, now, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	u := strings.TrimSuffix(a.ProxyURL, "/") + "/.gatekeep/device/report"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(tok))
	if err != nil {
		return nil, fmt.Errorf("posture: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/jwt")
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posture: submit: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var rr ReportResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&rr); err != nil {
		return nil, fmt.Errorf("posture: decode response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || !rr.Accepted {
		return &rr, fmt.Errorf("posture: report rejected (status %d): %s", resp.StatusCode, rr.Reason)
	}
	return &rr, nil
}

// Run pairs with code and then refreshes posture every interval until ctx
// is cancelled. Transient submit errors are logged and retried; a rejected
// binding ends the loop because only a new pairing can recover it.
func (a *Agent) Run(ctx context.Context, code string, interval time.Duration) error {
	logger := a.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	rr, err := a.Report(ctx, code)
	if err != nil {
		return err
	}
	binding := rr.Binding
	logger.Info("paired with proxy", "device", a.DeviceID)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		rr, err := a.Report(ctx, binding)
		switch {
		case err == nil:
			logger.Info("posture refreshed", "device", a.DeviceID)
		case rr != nil && rr.Reason == "unknown_nonce":
			return errors.New("posture: binding expired or revoked; pair again")
		default:
			logger.Warn("posture refresh failed", "err", err)
		}
	}
}
