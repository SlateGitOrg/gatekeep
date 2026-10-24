package posture

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/archit2501/gatekeep/internal/jose"
	"github.com/archit2501/gatekeep/internal/replay"
)

// Device is an enrolled device.
type Device struct {
	ID    string
	Owner string // OIDC subject the device is registered to
	Key   jose.JWK
}

// Verifier checks posture assertion signatures and claims.
type Verifier struct {
	Devices  map[string]Device
	Audience string
	Leeway   time.Duration
	// MaxAge bounds now-iat for an assertion at submission time.
	MaxAge time.Duration
	Replay *replay.Cache
	Now    func() time.Time
}

// Verify returns the assertion's claims and the device that signed it.
func (v *Verifier) Verify(token string) (*Claims, Device, error) {
	p, err := jose.Parse(token)
	if err != nil {
		return nil, Device{}, err
	}
	if p.Header.Typ != TokenType {
		return nil, Device{}, ErrType
	}
	var c Claims
	if err := p.DecodeClaims(&c); err != nil {
		return nil, Device{}, err
	}
	// The claims are read before the signature is checked only to find the
	// device key; nothing else is trusted until Verify succeeds.
	dev, ok := v.Devices[c.Issuer]
	if !ok {
		return nil, Device{}, fmt.Errorf("%w: %q", ErrUnknownDevice, c.Issuer)
	}
	if err := p.Verify(dev.Key); err != nil {
		return nil, Device{}, err
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	maxAge := v.MaxAge
	if maxAge <= 0 {
		maxAge = 2 * time.Minute
	}
	if c.IssuedAt == nil {
		return nil, Device{}, fmt.Errorf("%w: iat", jose.ErrMissingClaim)
	}
	if err := c.Validate(jose.Expectations{Audience: v.Audience, Now: now, Leeway: v.Leeway, MaxAge: maxAge}); err != nil {
		return nil, Device{}, err
	}
	if c.Expiry.Time().Sub(c.IssuedAt.Time()) > MaxLifetime {
		return nil, Device{}, ErrLifetime
	}
	if c.ID == "" {
		return nil, Device{}, ErrNoJTI
	}
	if v.Replay != nil {
		if err := v.Replay.Use("posture:"+dev.ID+":"+c.ID, c.Expiry.Time().Add(v.Leeway)); err != nil {
			return nil, Device{}, fmt.Errorf("%w: %w", ErrReplay, err)
		}
	}
	return &c, dev, nil
}

const (
	// alphabetHuman avoids 0/O and 1/I/L so codes can be read aloud.
	alphabetHuman = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	alphabetURL   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// randomCode draws n symbols uniformly from alphabet (rejection sampling, so
// there is no modulo bias).
func randomCode(n int, alphabet string) (string, error) {
	out := make([]byte, 0, n)
	limit := 256 - 256%len(alphabet)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("posture: random: %w", err)
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}
