# Decisions

Format: `- Ruling: <what> — <why> — <cost if wrong>`.

## Protocol and crypto

- Ruling: implement JOSE (JWS/JWK/JWT subset) in-repo on the Go standard library instead of a JWT library — keeps the security-critical parsing small and explicit (closed alg list, algorithm bound to key type, no `none`, no `crit`, size caps) and avoids library defaults such as accepting any alg the header names — cost if wrong: in-house crypto glue might have a subtle bug a mature library has already fixed; mitigated by unit tests for each rejection path, fuzzing of `Parse`/JWK and RFC test vectors.
- Ruling: accept only RS256 and ES256 for ID tokens, plus EdDSA/ES256 for device assertions — these cover mainstream IdPs and keep the matrix small — cost if wrong: an IdP that only offers PS256 or ES384 would need another alg (a small change in `jose`).
- Ruling: PKCE S256 is mandatory and `plain` is never offered — OAuth 2.1 / RFC 9700 guidance — cost if wrong: none known; every modern IdP supports S256.
- Ruling: client authentication is `client_secret_basic` only — simplest widely supported method — cost if wrong: IdPs that require `private_key_jwt` would need it added.
- Ruling: `iat` is required on ID tokens, with a `max_token_age` (default 10 min) — bounds how long a captured token is useful even when the IdP sets a long `exp` — cost if wrong: a provider omitting `iat` (non-compliant) would be rejected.
- Ruling: `ParseJWKSet` skips every key gatekeep cannot use — `use` other than `sig` (checked before parsing key material), unsupported kty/curve, and an `alg` gatekeep does not pair with the kty (RSA-OAEP, PS256, RS384, ES384, ...) — and errors only on malformed material of a usable signing key — real IdP JWKS documents mix in encryption and other-alg keys (Keycloak publishes an RSA-OAEP key by default), and rejecting the whole set broke every login — cost if wrong: a misconfigured signing key whose alg contradicts its kty is dropped silently; tokens it signed then fail as "unknown kid", which is still fail-closed.
- Ruling: the JWKS cache refetches on unknown kid, rate-limited to one fetch per 10 s with single-flight, and keeps stale keys on error — picks up rotation immediately without becoming a DoS amplifier — cost if wrong: a just-rotated key could be unusable for up to 10 s if a refetch happened right before the rotation.

## Sessions and CSRF

- Ruling: stateless AES-256-GCM cookies, plus an in-memory revocation set for logout — no session database; still supports logout — cost if wrong: revocations are lost on restart and not shared between replicas (documented limitation).
- Ruling: derive cookie keys with HKDF and bind the cookie purpose as AAD — one master secret can seal several cookie kinds without cross-use — cost if wrong: none identified.
- Ruling: key id = first byte of SHA-256(secret), and collisions are rejected at startup — lets operators reorder secrets during rotation — cost if wrong: about a 1/256 chance per pair that an operator must regenerate a secret.
- Ruling: one login-state cookie per browser, so concurrent logins in two tabs overwrite each other — keeps the cookie count bounded — cost if wrong: the older tab's callback fails with `state_mismatch` and that tab must start sign-in again.
- Ruling: CSRF defence = SameSite=Lax + mandatory same-origin proof on unsafe methods (Sec-Fetch-Site, then Origin, then Referer; none means reject) + an HMAC synchronizer token for gatekeep's own POST endpoints — layered and needs no state — cost if wrong: unusual clients that send unsafe requests without Origin/Referer are rejected; such routes can set `disable_csrf`.
- Ruling: the session cookie is SameSite=Lax, not Strict — the IdP redirect back to the callback is a cross-site top-level navigation, and Strict would drop the login cookie — cost if wrong: none for the protected methods, which are covered by the origin check.

## Device posture

- Ruling: link a device to a browser session through a short single-use pairing code typed into the agent, then a binding id for refreshes — works without a browser extension, mTLS or OS integration, and the device must be enrolled to the same subject — cost if wrong: an extra manual step per session; a production system would use mTLS or a platform authenticator (roadmap).
- Ruling: posture is stored server-side, keyed by session id, and is "stale" after `posture.max_age` (default 10 min) — freshness is enforced centrally, and the policy sees `device.present=false` when posture is stale — cost if wrong: not shared across replicas; agents must refresh more often than `max_age`.
- Ruling: managed attributes (disk encryption, firewall, screen lock, patch age) come from an MDM-style facts file; the agent itself observes only OS/arch/hostname/kernel — native probes are platform-specific and untestable in CI — cost if wrong: the posture is only as honest as the facts file (documented in Limitations and the threat model).
- Ruling: a posture assertion must be ≤ 2 min old on arrival and live at most 5 min — limits the replay window beyond the jti cache — cost if wrong: devices with badly skewed clocks are rejected (30 s leeway applies).

## Policy

- Ruling: CEL via cel-go with native Go struct types — CEL is non-Turing-complete, has bounded cost, and is the de-facto policy language (Kubernetes, Envoy, IAM conditions); native types give compile-time checking of attribute names — cost if wrong: cel-go is a large dependency (it pulls protobuf/antlr).
- Ruling: deny-overrides with default deny; an error in a deny rule denies, and an error in an allow rule never allows — fail closed — cost if wrong: a buggy deny rule (for example indexing a missing header) blocks access until fixed; this is visible as `deny_rule_error` in the audit log.
- Ruling: `require_device` runs as a gate before policy — makes "this route needs a fresh device" impossible to forget inside an expression — cost if wrong: none.
- Ruling: credentials (`cookie`, `authorization`) are withheld from `request.headers` — policies and policy test fixtures should never handle secrets — cost if wrong: a policy cannot inspect bearer tokens (not a goal).

## Proxy behaviour

- Ruling: `request.ip` is the TCP peer address; `X-Forwarded-For` is never trusted — trusting it without a configured trusted-proxy list is a classic bypass — cost if wrong: behind a load balancer, IP-based rules see the LB address; a trusted-proxy setting would be needed.
- Ruling: reject non-canonical paths (`..`, `.`, `//`, `\`) with 400 instead of normalising them — avoids any mismatch between how gatekeep routes a path and how the upstream resolves it — cost if wrong: a few legitimate clients that send `//` paths get 400.
- Ruling: sign an ES256 identity assertion per request for upstreams, in addition to plain headers — upstreams can verify identity cryptographically (IAP-style) — cost if wrong: one ECDSA signature per proxied request, the largest part of the ~60 µs per-request overhead measured by `BenchmarkGatewayAuthorizedRequest`.
- Ruling: inbound identity headers are matched case-insensitively with `_` treated as `-` before the `X-Gatekeep-` prefix check, and every match is deleted — WSGI/CGI/Rack upstreams read `X_Gatekeep_User` and `X-Gatekeep-User` as the same `HTTP_X_GATEKEEP_USER`, so stripping only the canonical spelling let an anonymous caller choose an identity (the oauth2-proxy header-smuggling class) — cost if wrong: a legitimate client header spelled `X_Gatekeep_...` is dropped (none expected).
- Ruling: plain-http `public_url` is allowed only on loopback — local development without certificates while making insecure deployment impossible — cost if wrong: none.
- Ruling: no `Docker`-based integration target — the e2e suite already runs the full system over real loopback TLS inside `go test`, with no Docker and no network — cost if wrong: none for this scope.

## Tooling and repo

- Ruling: YAML via `go.yaml.in/yaml/v3` (the maintained fork, already a transitive dependency of cel-go) with `KnownFields(true)` — strict config, typos fail at startup, no extra dependency — cost if wrong: none.
- Ruling: core coverage counts `internal/...` minus demo/test scaffolding (`internal/demo`, `internal/idp/idptest`, `internal/e2e`, `internal/bench`), measured across packages with `-coverpkg` so e2e tests count; the gate is 85 % — the e2e suite is the most meaningful test of the gateway — cost if wrong: per-package unit coverage of the gateway alone is lower (it is mostly exercised end to end).
- Ruling: the demo uses a simulated clock (fixed start, real elapsed time plus jumps) — "11 minutes later" happens instantly while latencies stay real — cost if wrong: none.
- Ruling: errcheck ignores `fmt.Fprint*` (CLI output) and the test files skip `noctx`/`gosec` — these are noise in those contexts; production code is fully linted — cost if wrong: an unchecked terminal write in a CLI.
