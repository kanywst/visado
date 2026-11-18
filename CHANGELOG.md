# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a breaking change bumps the minor version and anything else bumps the patch. All crates share one version.

## [Unreleased]

### Added

- `deploy/lab`: Envoy, visado, OPA with the AuthZEN plugin and an echo upstream in Docker Compose, with eight scenarios in `demo.sh` that CI runs.
- A Dockerfile for the server.

## [0.1.0] - 2026-11-19

First release. Pre-alpha: delegation-chain verification is not implemented yet.

### Added

- `visado-txn-token`: mint, verify and replace OAuth Transaction Tokens (draft-ietf-oauth-transaction-tokens-11), and parse token requests. Errors have stable codes.
- Transaction Token conformance vectors in `conformance/txn-token/` (5 valid, 22 negative).
- `visado-authzen`: AuthZEN 1.0 access evaluation client that fails closed, with an agent-for-principal request profile and metadata discovery.
- `visado-credentials`: caller authentication with a WIT and a WPT (optionally binding a user access token through `oth`), or an OAuth access token alone. WPT `jti` replay is checked in memory.
- `visado-extauthz`: the decision pipeline and an Envoy ext_authz v3 gRPC service. It mints a Transaction Token, forwards one only from configured internal callers, and removes inbound credentials before the request goes upstream.
- `visado` binary: TOML configuration, ext_authz over gRPC, `/healthz` and `/.well-known/jwks.json` over HTTP, JSON audit events. Both listeners bind to loopback by default, and the server exits if either fails.
- Requests for authorities outside `allowed_authorities` and paths an upstream could resolve differently (dot segments, encoded dots or slashes, empty segments) are denied before authentication.
- OAuth issuers can carry a `subject_prefix`; with more than one issuer, every issuer needs one.
- Sender-constrained access tokens (`cnf`) are rejected until DPoP and mTLS binding exist. `scp` is read when `scope` is absent, and `nbf` is checked.

[Unreleased]: https://github.com/kanywst/visado/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kanywst/visado/releases/tag/v0.1.0
