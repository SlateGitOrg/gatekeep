package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestDemoRuns keeps the offline demo honest: every expectation it prints
// is checked, so a regression fails here.
func TestDemoRuns(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out, filepath.Join(t.TempDir(), "audit.jsonl")); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"demo OK", "audit chain verified", "nonce_replayed", "posture_stale", "token_expired", "wrong_audience"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("demo output lacks %q", want)
		}
	}
}
