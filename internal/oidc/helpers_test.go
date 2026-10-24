package oidc_test

import (
	"crypto"
	"encoding/json"
	"testing"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func must(k crypto.Signer, err error) crypto.Signer {
	if err != nil {
		panic(err)
	}
	return k
}
