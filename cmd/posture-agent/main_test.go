package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCmd(args ...string) (string, error) {
	var out, errOut bytes.Buffer
	err := run(context.Background(), args, &out, &errOut)
	return out.String() + errOut.String(), err
}

func TestKeygenAndCollect(t *testing.T) {
	dir := t.TempDir()
	out, err := runCmd("keygen", "--out", filepath.Join(dir, "d.key"))
	if err != nil || !strings.Contains(out, "PUBLIC KEY") {
		t.Fatalf("%v %s", err, out)
	}
	out, err = runCmd("collect", "--facts", "../../examples/facts/compliant.json")
	if err != nil || !strings.Contains(out, `"disk_encrypted": true`) {
		t.Fatalf("%v %s", err, out)
	}
	if _, err := runCmd("collect", "--facts", "missing.json"); err == nil {
		t.Fatal("missing facts")
	}
	// pair validates its inputs before touching the network.
	for _, args := range [][]string{
		{"pair"},
		{"pair", "--proxy", "https://x", "--code", "C", "--device-id", "d", "--key", filepath.Join(dir, "none")},
		{"pair", "--proxy", "https://x", "--code", "C", "--device-id", "d", "--key", filepath.Join(dir, "d.key"), "--ca", filepath.Join(dir, "none")},
	} {
		if _, err := runCmd(args...); err == nil {
			t.Errorf("%v succeeded", args)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "bad.key"), []byte("junk"), 0o600)
	if _, err := runCmd("pair", "--proxy", "https://x", "--code", "C", "--device-id", "d", "--key", filepath.Join(dir, "bad.key")); err == nil {
		t.Fatal("junk key accepted")
	}
	if _, err := runCmd(); err == nil {
		t.Fatal("no command")
	}
	if _, err := runCmd("bogus"); err == nil {
		t.Fatal("bogus command")
	}
}
