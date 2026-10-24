# gatekeep threat model

**Scope:** the gatekeep proxy, the posture agent protocol and the deployment pattern shown in the README: gatekeep in front of internal HTTP apps, with an OIDC IdP. The bundled demo IdP is a **test fixture**; its threats are noted, but it is not meant to protect anything.

**Method:** assets, actors, trust boundaries, then STRIDE per boundary. Each mitigation names the test that checks it.

## 1. Assets

| Asset | Why it matters |
|---|---|
| A1 Upstream applications and their data | The thing being protected |
| A2 Session cookies | Bearer credentials for A1 |
| A3 Cookie master secrets, upstream signing key | Forging A2 or upstream identity |
| A4 Device private keys (on devices) | Forging posture for a device |
| A5 Policy configuration | Defines who gets in |
| A6 Audit log | Accountability, detection |
| A7 OIDC client secret | Redeeming codes as gatekeep |

## 2. Actors

- **External attacker:** can send arbitrary HTTP to gatekeep, host malicious sites the victim visits, and observe or replay some traffic (for example captured URLs or cookies from a shared machine).
- **Malicious or curious insider:** a valid user who tries to exceed their policy, for example a contractor trying to write or a user on a non-compliant device.
- **Compromised device:** an enrolled device whose user controls the agent.
- **Misbehaving or compromised IdP:** issues malformed, expired or mis-audienced tokens. A fully compromised IdP is out of scope: it is the identity root of trust.
- **Network attacker on the upstream segment:** can reach upstreams directly, bypassing gatekeep.

## 3. Trust boundaries

1. Browser to gatekeep (HTTPS)
2. Agent to gatekeep (HTTPS, signed body)
3. gatekeep to IdP (HTTPS, pinned issuer, client secret)
4. gatekeep to upstream (HTTP(S) plus signed assertion)
5. gatekeep to its config, secrets and audit file (local filesystem and environment)

## 4. Threats and mitigations

### Spoofing

| Threat | Mitigation | Verified by |
|---|---|---|
| Forged ID token (attacker key, `alg=none`, HS256 with the public key, algorithm confusion) | Closed alg list `{RS256, ES256}` for ID tokens; alg must match key type; JWKS from the discovered `jwks_uri` over https only | `TestAlgorithmConfusionRejected`, `TestParseRejects`, `TestVerifier/forged key same kid` |
| Token issued for another app | `aud` must contain `client_id`; `azp` rules | `TestNegativeWrongAudience`, `TestVerifier/foreign azp` |
| Token from another issuer (mix-up) | Discovery issuer must equal configured issuer; `iss` must equal it; https endpoints required | `TestDiscoveryValidation`, `TestVerifier/wrong iss` |
| Expired or old token reuse | `exp` with leeway, `iat` required, `max_token_age` | `TestNegativeExpiredIDToken`, `TestVerifier/too old` |
| Replay of a captured callback (code plus login cookie) | Nonce consumed exactly once (checked before code exchange); IdP codes single-use; PKCE binds the code to the verifier inside the sealed cookie | `TestNegativeReplayedNonce`, `TestFullCodeFlow` (code reuse), `TestExchangeRejectsWrongVerifier` |
| Login CSRF / session fixation (victim lands on the attacker's callback) | `state` compared in constant time against the sealed login cookie; login cookie TTL; new random `sid` per login | `TestNegativeStateMismatchAndMissingLoginState` |
| Forged or tampered session cookie | AES-256-GCM AEAD with purpose-bound AAD; `__Host-` prefix blocks subdomain injection | `TestNegativeTamperedCookie`, `TestTamperDetected` (every byte flipped) |
| Spoofed identity headers to upstream | All inbound `X-Gatekeep-*` stripped; upstream verifies an ES256 assertion bound to route audience and 60 s expiry | `TestAnonymousRouteAndHeaderSpoofing`, `TestSanitizeOutbound`, `whoami` upstream |
| Forged posture | JWS signed by an enrolled device key; `typ` pinned; `aud` pinned to this proxy | `TestPostureNegatives` (rogue key), `TestVerifyRejects` |
| Using another user's device for posture | Pairing requires device owner == session subject | `TestPostureNegatives` (`device_owner_mismatch`) |
| Device swap on an existing binding | Binding pinned to device ID | `TestStorePairingAndBinding` (`ErrDeviceSwap`) |

### Tampering

| Threat | Mitigation | Verified by |
|---|---|---|
| Path tricks to match one route and reach another resource (`/public/../admin`, `//`, `\`) | Non-canonical paths rejected before routing; prefix match on segment boundaries | `TestPathAndRoutingEdgeCases`, `TestCanonicalPath`, `TestRouterMatch` |
| Upstream overwriting gatekeep cookies | Upstream `Set-Cookie` for gatekeep's cookie names dropped | `TestSanitizeOutbound` |
| Audit log edited, reordered or with records deleted | SHA-256 hash chain; verification on open; `audit-verify` | `TestTamperDetected`, `TestOpenFileContinuesChain` |
| Policy bypass through rule evaluation errors | Deny rules fail closed; allow errors never allow | `TestFailClosedOnDenyError`, `TestAllowErrorIsFalse` |

### Repudiation

- Every access decision, login, logout, pairing and posture report is logged with request ID, subject, device, rule, reason and status. `TestAuditDecisionCoverage` checks this, and every e2e scenario ends by verifying the chain.

### Information disclosure

| Threat | Mitigation |
|---|---|
| Session cookie leaked to upstream apps | gatekeep cookies removed from the forwarded `Cookie` header (`TestFullRedirectFlow` asserts the upstream saw none) |
| Credentials visible to policies or logs | `cookie` and `authorization` headers withheld from `request.headers`; the ID token is never stored; codes are stored hashed at the demo IdP |
| Error pages revealing internals | Only a reason code and request ID are shown; detail goes to the audit log |
| Clickjacking / sniffing / referrer leaks on gatekeep pages | Strict CSP (`default-src 'none'`, no script), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, HSTS (`TestGatekeepPageHeaders`, `TestHeaders`) |
| Username enumeration at the demo IdP | Unknown users are checked against a dummy hash of the same cost |

### Denial of service

| Threat | Mitigation |
|---|---|
| JWKS refetch amplification with random `kid`s | Refetch rate limit plus single-flight (`TestKeySetRateLimitAndStaleIfError`, `TestKeySetConcurrentSingleFlight`) |
| IdP outage | Stale-if-error JWKS; existing sessions keep working |
| Expensive policies | Per-rule CEL cost limit; exceeding it denies (`TestCostLimit`) |
| Oversized inputs | Token 16 KiB cap, cookie 3,800 B cap, request bodies limited on internal endpoints, `MaxHeaderBytes` and timeouts on the server |
| Replay cache exhaustion | Hard capacity; fails closed instead of evicting (`TestCapacityFailsClosed`). An attacker who fills it blocks new logins until entries expire; see residual risks |
| Brute-force at the demo IdP | Per-user lockout (`TestLoginFailuresAndLockout`) |

### Elevation of privilege

| Threat | Mitigation |
|---|---|
| Cross-site request riding a session (CSRF) | `SameSite=Lax`; unsafe methods need same-origin proof (`Sec-Fetch-Site`, then `Origin`, then `Referer`; none means reject); internal state changes also need an HMAC token bound to the session (`TestCSRFAndLogout`, `TestCheckOrigin`) |
| Open redirect after login | `rd` restricted to local paths; `//`, `/\`, absolute URLs, CR/LF and `/.gatekeep/*` (except the device page) rejected (`TestOpenRedirectBlocked`, `TestSafeReturnTo`) |
| Stale device state granting access | Posture older than `max_age` is ignored (`TestDevicePostureLifecycle`) |
| Revoked session reused | Logout puts the `sid` into the revocation set (`TestCSRFAndLogout`) |
| Plain-HTTP deployment exposing cookies | `public_url` must be https except on loopback; `Secure` and `__Host-` used over TLS |

## 5. Residual risks and out of scope

- **Compromised device owner.** Posture facts are self-reported and signed by a key the user controls. gatekeep proves *which enrolled device* reported, not that the facts are true. Mitigation would need hardware attestation (roadmap).
- **Single instance state.** A restart forgets consumed nonces, but those nonces are bound to login cookies that expire within `login_ttl` and to IdP codes that are single-use. A restart also forgets revocations: a logged-out cookie works again after a restart until its expiry. This is a known gap; a shared store would close it.
- **Replay-cache saturation:** about 200k entries per cache. Saturating it requires completing that many logins, which the IdP's own controls should limit.
- **Compromised IdP or stolen signing key:** out of scope (identity root of trust).
- **Upstream reachable without gatekeep:** only safe if the upstream verifies `X-Gatekeep-Assertion`, which the demo app does. Network isolation is the operator's job.
- **TLS termination in front of gatekeep:** `request.ip` is the TCP peer, so behind a load balancer it is the LB's address. Trusted-proxy parsing of `X-Forwarded-For` is deliberately not implemented.
- **Browser-side compromise** (malware, malicious extensions): out of scope.
- **Side channels** in the Go crypto primitives: relies on the Go standard library.

## 6. Ethics and use

This is a defensive access-control project. Every attack in the tests and demo targets local fixtures built in this repository: the demo IdP, gatekeep itself and a `whoami` upstream on loopback. Nothing targets third-party systems.
