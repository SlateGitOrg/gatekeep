package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) }

func writeN(t *testing.T, l *Logger, n int) {
	t.Helper()
	for i := range n {
		if _, err := l.Log(Event{Kind: KindAccess, Decision: "allow", Path: "/p", Status: 200 + i}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifies(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, fixedNow)
	writeN(t, l, 5)
	res, err := Verify(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 5 || res.Head != l.Head() {
		t.Fatalf("%+v head=%s", res, l.Head())
	}
}

func TestTamperDetected(t *testing.T) {
	var buf bytes.Buffer
	writeN(t, NewLogger(&buf, fixedNow), 4)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	cases := map[string][]string{
		"modified": {lines[0], strings.Replace(lines[1], `"decision":"allow"`, `"decision":"deny"`, 1), lines[2], lines[3]},
		"deleted":  {lines[0], lines[2], lines[3]},
		"swapped":  {lines[0], lines[2], lines[1], lines[3]},
		"garbage":  {lines[0], "{not json"},
		"unknown":  {strings.Replace(lines[0], `"seq":1`, `"seq":1,"x":1`, 1)},
	}
	for name, ls := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(strings.NewReader(strings.Join(ls, "\n")))
			if !errors.Is(err, ErrChain) {
				t.Fatalf("want ErrChain, got %v", err)
			}
		})
	}
}

func TestConcurrentLoggingKeepsChain(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	l := NewLogger(lockedWriter{&buf, &mu}, nil)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				_, _ = l.Log(Event{Kind: KindAccess, Decision: "allow"})
			}
		}()
	}
	wg.Wait()
	res, err := Verify(&buf)
	if err != nil || res.Records != 200 {
		t.Fatalf("%+v %v", res, err)
	}
}

type lockedWriter struct {
	b  *bytes.Buffer
	mu *sync.Mutex
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func TestOpenFileContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, c, err := OpenFile(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, l, 3)
	_ = c.Close()
	l2, c2, err := OpenFile(path, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	writeN(t, l2, 2)
	_ = c2.Close()
	f, _ := os.Open(path)
	defer func() { _ = f.Close() }()
	res, err := Verify(f)
	if err != nil || res.Records != 5 {
		t.Fatalf("%+v %v", res, err)
	}
	// A tampered file refuses to open.
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(b, []byte(`"status":201`), []byte(`"status":500`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenFile(path, fixedNow); !errors.Is(err, ErrChain) {
		t.Fatalf("tampered log opened: %v", err)
	}
	if _, _, err := OpenFile(filepath.Join(t.TempDir(), "missing", "x"), nil); err == nil {
		t.Fatal("bad path opened")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriteErrorDoesNotAdvanceChain(t *testing.T) {
	l := NewLogger(failWriter{}, fixedNow)
	if _, err := l.Log(Event{Kind: KindAccess}); err == nil {
		t.Fatal("expected error")
	}
	if l.Head() != Genesis || l.seq != 0 {
		t.Fatal("failed write advanced the chain")
	}
}
