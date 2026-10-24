package devcert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	now := time.Now()
	c, k, err := Generate([]string{"127.0.0.1", "localhost"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(c, k); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(c)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("localhost"); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost", CurrentTime: now}); err != nil {
		t.Fatalf("self-trust: %v", err)
	}
	if _, _, err := Generate(nil, now, time.Hour); err == nil {
		t.Fatal("no hosts accepted")
	}
}
