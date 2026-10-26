// Command posture-agent is gatekeep's device posture agent.
//
//	posture-agent keygen  --out device.key
//	posture-agent collect [--facts facts.json]
//	posture-agent pair    --proxy URL --code CODE --device-id ID --key device.key
//	                      [--facts facts.json] [--ca ca.pem] [--interval 60s] [--once]
//
// The agent holds the device's private key, collects posture facts, signs
// them as a short-lived assertion and submits them to gatekeep.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SlateGitOrg/gatekeep/internal/jose"
	"github.com/SlateGitOrg/gatekeep/internal/posture"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "posture-agent:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: posture-agent keygen|collect|pair [flags]")
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout)
	case "collect":
		fs := flag.NewFlagSet("collect", flag.ContinueOnError)
		facts := fs.String("facts", "", "MDM-style facts file (JSON)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		f, err := posture.SystemCollector{FactsFile: *facts}.Collect(ctx)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(f)
	case "pair":
		return pair(ctx, args[1:], stdout, stderr)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func keygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "device.key", "private key output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	k, err := jose.GenerateKey(jose.EdDSA)
	if err != nil {
		return err
	}
	priv, err := jose.MarshalPrivateKeyPEM(k)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, priv, 0o600); err != nil {
		return err
	}
	pub, err := jose.MarshalPublicKeyPEM(k.Public())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "# enroll this public key in gatekeep's posture.devices\n%s", pub)
	return nil
}

func pair(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	proxy := fs.String("proxy", "", "gatekeep public URL")
	code := fs.String("code", "", "pairing code from /.gatekeep/device")
	deviceID := fs.String("device-id", "", "enrolled device ID")
	keyFile := fs.String("key", "device.key", "device private key")
	facts := fs.String("facts", "", "MDM-style facts file (JSON)")
	caFile := fs.String("ca", "", "extra CA certificate (PEM) for the proxy")
	audience := fs.String("audience", "", "assertion audience (default: --proxy)")
	interval := fs.Duration("interval", time.Minute, "refresh interval")
	once := fs.Bool("once", false, "pair and exit without refreshing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *proxy == "" || *code == "" || *deviceID == "" {
		return errors.New("pair: --proxy, --code and --device-id are required")
	}
	kb, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key, err := jose.ParsePrivateKeyPEM(kb)
	if err != nil {
		return err
	}
	signer, err := jose.NewSigner(key, *deviceID)
	if err != nil {
		return err
	}
	client, err := httpClient(*caFile)
	if err != nil {
		return err
	}
	aud := *audience
	if aud == "" {
		aud = *proxy
	}
	agent := &posture.Agent{
		DeviceID: *deviceID, Signer: signer, Collector: posture.SystemCollector{FactsFile: *facts},
		ProxyURL: *proxy, Audience: aud, Client: client,
		Logger: slog.New(slog.NewTextHandler(stderr, nil)),
	}
	if *once {
		rr, err := agent.Report(ctx, *code)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "paired: posture accepted (fresh for %ds)\n", rr.MaxAgeSecs)
		return nil
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx, *code, *interval)
}

func httpClient(caFile string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("no certificates in --ca file")
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}, nil
}
