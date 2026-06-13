# polytoken

A configurable, multi-issuer JWT validation service written in Go. It validates tokens from any number of configured
issuers, each using its own signing scheme (HMAC shared-secret or RSA via JWKS), and routes each token to the right
validator at request time based on its `iss` claim.

## Why this exists

I built and ran a multi-issuer JWT setup in production using Java and Spring Security, where one issuer was a legacy
internal service signing tokens with a shared HMAC secret and another was Okta issuing asymmetrically-signed tokens
validated against a JWKS endpoint. Spring Security's out-of-the-box resource-server configuration assumes a single
issuer and is oriented around JWKS validation, so supporting a symmetric legacy issuer alongside an asymmetric one
required custom `JwtDecoder` wiring and issuer-based routing rather than the default auto-configuration.

This project is a clean-room reimplementation of that pattern in Go. I built it primarily to learn Go in depth (
idiomatic interfaces, concurrency, the standard library, testing) by porting an architecture I already understood,
rather than learning a new language and a new problem at the same time. Production systems would typically reach for a
maintained library like Auth0's `go-jwt-middleware`; this is a from-scratch implementation built to understand the
internals and the design tradeoffs (routing, key caching, rotation, algorithm pinning).

## How it works

A token arrives, and the service:

1. Reads the unverified `iss` claim to decide which validator should handle it (routing).
2. Hands the token to that validator, which performs full cryptographic verification (signature, expiry, issuer).
3. On success, produces a normalized `Principal` that downstream code consumes without needing to know which issuer or
   algorithm produced the token.

Routing and verification are deliberately separate. Routing reads unverified claims and is never a security decision; it
only picks which validator runs. The chosen validator then does the real cryptographic check, so a token claiming any
`iss` cannot bypass verification.

### Architecture

```
config (YAML)
   |
   v
factory  -->  builds a TokenValidator per issuer (HS256 or RS256)
   |
   v
resolver -->  routes a token to the matching validator by iss
   |
   v
validator -->  verifies signature + claims, returns a Principal
   |
   +-- HS256: shared-secret HMAC
   +-- RS256: RSA, public keys fetched and cached from a JWKS endpoint
```

The HTTP layer wraps this in middleware that extracts the bearer token, runs it through the resolver, and stores the
resulting `Principal` in the request context for handlers to read.

## Configuration

Issuers are declared in a YAML file. Each issuer has a name, the `iss` value it mints, a type, and type-specific
settings.

```yaml
issuers:
  - name: legacy-internal
    issuer: https://internal.example.com
    type: hs256
    hs256:
      secret: change-me

  - name: okta-prod
    issuer: https://example.okta.com/oauth2/default
    type: rs256
    rs256:
      jwksUrl: https://example.okta.com/oauth2/default/v1/keys
```

Adding an issuer is a config change with no code change. Configuration is validated at startup, so a misconfigured
issuer fails fast rather than at request time.

## Running it

```bash
go run ./cmd/polytokend
```

The service reads `config.yaml` and listens on `:8080`.

Health check (unauthenticated):

```bash
curl localhost:8080/healthz
# ok
```

Authenticated endpoint, which echoes the validated principal:

```bash
curl -H "Authorization: Bearer <token>" localhost:8080/whoami
```

A request with no token, an unrecognized issuer, an invalid signature, or an expired token returns `401 Unauthorized`.

## Design notes

**Algorithm pinning.** Each validator pins the accepted signing method (HS256 validators accept only HS256, RS256 only
RS256). This prevents algorithm-confusion attacks where a token's header claims a different algorithm than expected.

**JWKS caching and rotation.** RSA public keys are fetched from the issuer's JWKS endpoint and cached in memory, keyed
by key ID (`kid`). When a token presents a `kid` the cache has not seen, the cache refetches the key set, which handles
issuer key rotation transparently. The cache is safe for concurrent use: reads take a shared lock, and a refresh builds
a fresh key map and swaps it under a write lock without holding the lock during the network fetch.

**Extensibility.** Validator construction uses a small registry mapping issuer type to a constructor function. Adding a
new signing scheme means writing one constructor and registering it; no existing code changes.

## Testing

```bash
go test ./...
```

Tests cover each layer independently:

- Config parsing and validation, including malformed and incomplete issuers.
- HS256 validation across valid, expired, wrong-secret, wrong-issuer, and missing-claim cases.
- RS256 validation end to end, using a generated RSA keypair and a local test server that serves a matching JWKS
  document.
- JWKS cache key rotation, by mutating what the test server serves mid-test and asserting the cache recovers.
- Resolver routing, using interface-based test doubles to assert that a token is dispatched to the correct validator and
  that an unmatched token is rejected.

## Status and future work

The core is complete and tested: configuration, validator factory, both validators, the JWKS cache, the resolver, and
the HTTP middleware.

Planned:

- Refresh throttling on the JWKS cache to bound refetches under unknown-`kid` load.
- A token-minting helper for generating test tokens.
- Containerization (`Dockerfile` and `docker-compose` with a local issuer for end-to-end demos).
- Support for additional issuer types (for example, opaque-token introspection) to exercise the extensibility of the
  registry.

## License

MIT