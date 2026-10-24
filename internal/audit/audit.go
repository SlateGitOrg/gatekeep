// Package audit writes gatekeep's structured decision log: one JSON object
// per line, each record carrying the SHA-256 of its predecessor so that
// editing, deleting or reordering any record breaks the chain. (Truncating
// the tail is only detectable against an externally anchored head hash,
// which Verify returns for exactly that purpose.)
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Genesis is the "prev" value of the first record in a chain.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Event kinds.
const (
	KindAccess = "access"
	KindLogin  = "login"
	KindLogout = "logout"
	KindDevice = "device"
)

// Event is one audit record.
type Event struct {
	Seq        uint64    `json:"seq"`
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"`
	RequestID  string    `json:"request_id,omitempty"`
	Route      string    `json:"route,omitempty"`
	Method     string    `json:"method,omitempty"`
	Host       string    `json:"host,omitempty"`
	Path       string    `json:"path,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	Subject    string    `json:"sub,omitempty"`
	Email      string    `json:"email,omitempty"`
	DeviceID   string    `json:"device_id,omitempty"`
	Device     string    `json:"device_state,omitempty"` // fresh | stale | absent
	Decision   string    `json:"decision"`
	Rule       string    `json:"rule,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Errors     []string  `json:"errors,omitempty"`
	PolicyCost uint64    `json:"policy_cost,omitempty"`
	Status     int       `json:"status,omitempty"`
	LatencyMS  float64   `json:"latency_ms,omitempty"`
	Prev       string    `json:"prev"`
	Hash       string    `json:"hash"`
}

// Logger appends chained events to a writer. It is safe for concurrent use;
// records are serialised so the chain is total.
type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	prev string
	seq  uint64
	now  func() time.Time
}

// NewLogger starts a new chain on w.
func NewLogger(w io.Writer, now func() time.Time) *Logger {
	if now == nil {
		now = time.Now
	}
	return &Logger{w: w, prev: Genesis, now: now}
}

// OpenFile opens (or creates) an append-only audit file and continues its
// chain. The existing file is verified first; a broken chain is an error so
// that gatekeep never silently extends a tampered log.
func OpenFile(path string, now func() time.Time) (*Logger, io.Closer, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	res, err := Verify(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("audit: existing log %s: %w", path, err)
	}
	l := NewLogger(f, now)
	l.prev, l.seq = res.Head, res.Records
	return l, f, nil
}

// Log fills Seq, Time (if zero), Prev and Hash, then writes the record.
func (l *Logger) Log(e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq = l.seq
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	e.Time = e.Time.UTC()
	e.Prev = l.prev
	h, err := hashEvent(e)
	if err != nil {
		l.seq--
		return Event{}, err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		l.seq--
		return Event{}, fmt.Errorf("audit: encode: %w", err)
	}
	if _, err := l.w.Write(append(line, '\n')); err != nil {
		l.seq--
		return Event{}, fmt.Errorf("audit: write: %w", err)
	}
	l.prev = h
	return e, nil
}

// Head returns the latest hash (for external anchoring).
func (l *Logger) Head() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prev
}

func hashEvent(e Event) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("audit: encode: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyResult summarises a verified log.
type VerifyResult struct {
	Records uint64
	Head    string
}

// ErrChain is returned when a log fails verification.
var ErrChain = errors.New("audit: chain broken")

// Verify checks every record's hash, its link to the previous record and the
// sequence numbering.
func Verify(r io.Reader) (VerifyResult, error) {
	res := VerifyResult{Head: Genesis}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var e Event
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return res, fmt.Errorf("%w: line %d: %w", ErrChain, line, err)
		}
		if e.Prev != res.Head {
			return res, fmt.Errorf("%w: line %d: prev does not match preceding record", ErrChain, line)
		}
		if e.Seq != res.Records+1 {
			return res, fmt.Errorf("%w: line %d: seq %d, expected %d", ErrChain, line, e.Seq, res.Records+1)
		}
		want, err := hashEvent(e)
		if err != nil {
			return res, err
		}
		if want != e.Hash {
			return res, fmt.Errorf("%w: line %d: record hash mismatch (modified)", ErrChain, line)
		}
		res.Records++
		res.Head = e.Hash
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("audit: read: %w", err)
	}
	return res, nil
}
