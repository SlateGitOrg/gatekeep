// Package posture implements signed device-posture assertions.
//
// A device is enrolled by registering its public key (and owning subject)
// with the proxy. The in-repo agent collects posture facts and signs them as a
// short-lived JWS. The proxy only accepts an assertion when:
//
//   - it is signed by a registered device key (EdDSA or ES256);
//   - aud names this proxy, iat/exp are fresh and the lifetime is short;
//   - its jti has not been seen before (replay cache);
//   - its nonce is either a live single-use pairing code issued to a browser
//     session of the device's owner, or a binding ID previously issued to the
//     same device for that session.
//
// Accepted posture is stored server-side against the session ID; policy sees
// it only while it is younger than the configured maximum age.
package posture

import (
	"errors"
	"fmt"
	"time"

	"github.com/archit2501/gatekeep/internal/jose"
)

// TokenType is the JOSE "typ" for posture assertions, preventing an ID
// token or any other JWS from being substituted.
const TokenType = "gatekeep-posture+jwt"

// MaxLifetime caps exp-iat of an accepted assertion.
const MaxLifetime = 5 * time.Minute

// Facts are the device attributes the agent reports.
type Facts struct {
	OS              string `json:"os"`
	OSVersion       string `json:"os_version,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	DiskEncrypted   bool   `json:"disk_encrypted"`
	FirewallEnabled bool   `json:"firewall_enabled"`
	ScreenLock      bool   `json:"screen_lock"`
	PatchAgeDays    int    `json:"patch_age_days"`
	AgentVersion    string `json:"agent_version,omitempty"`
}

// Claims is the posture assertion claim set. iss is the device ID.
type Claims struct {
	jose.RegisteredClaims
	Nonce string `json:"nonce"`
	Facts Facts  `json:"posture"`
}

// Sign creates a posture assertion for deviceID.
func Sign(s *jose.Signer, deviceID, audience, nonce string, facts Facts, now time.Time, ttl time.Duration) (string, error) {
	if ttl <= 0 || ttl > MaxLifetime {
		ttl = 2 * time.Minute
	}
	jti, err := randomCode(16, alphabetURL)
	if err != nil {
		return "", err
	}
	c := Claims{
		RegisteredClaims: jose.RegisteredClaims{
			Issuer: deviceID, Subject: deviceID, Audience: jose.Audience{audience},
			IssuedAt: jose.NewNumericDate(now), Expiry: jose.NewNumericDate(now.Add(ttl)), ID: jti,
		},
		Nonce: nonce,
		Facts: facts,
	}
	tok, err := s.Sign(TokenType, c)
	if err != nil {
		return "", fmt.Errorf("posture: sign: %w", err)
	}
	return tok, nil
}

// Errors returned by verification and the store.
var (
	ErrUnknownDevice = errors.New("posture: unknown device")
	ErrType          = errors.New("posture: wrong token type")
	ErrLifetime      = errors.New("posture: assertion lifetime too long")
	ErrNoJTI         = errors.New("posture: missing jti")
	ErrReplay        = errors.New("posture: assertion replayed")
	ErrUnknownNonce  = errors.New("posture: unknown or expired pairing code or binding")
	ErrOwner         = errors.New("posture: device is not registered to this user")
	ErrDeviceSwap    = errors.New("posture: binding belongs to a different device")
)

// Reason maps an error to a stable audit reason code.
func Reason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnknownDevice):
		return "unknown_device"
	case errors.Is(err, ErrReplay):
		return "posture_replay"
	case errors.Is(err, ErrUnknownNonce):
		return "unknown_nonce"
	case errors.Is(err, ErrOwner):
		return "device_owner_mismatch"
	case errors.Is(err, ErrDeviceSwap):
		return "device_swap"
	case errors.Is(err, jose.ErrExpired), errors.Is(err, ErrLifetime):
		return "posture_expired"
	case errors.Is(err, jose.ErrAudience):
		return "wrong_audience"
	case errors.Is(err, jose.ErrSignature), errors.Is(err, jose.ErrKeyMismatch):
		return "bad_signature"
	}
	return "invalid_assertion"
}
