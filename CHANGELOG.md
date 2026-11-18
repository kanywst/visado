# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a breaking change bumps the minor version and anything else bumps the patch. All crates share one version.

## [Unreleased]

### Added

- The gate verifies an AAT chain sent in `AAT-Chain` and `AAT-PoP` (see `docs/bindings.md`), reads the tool and arguments from an MCP `tools/call` body, requires the chain's holder to be the WIT key when a WIT is present, and passes the chain to the PDP and into the Transaction Token `tctx`. Configured with `[aat]` in the server file.
- `deploy/lab`: Envoy, visado, OPA with the AuthZEN plugin and an echo upstream in Docker Compose, with eight scenarios in `demo.sh` that CI runs.
- A Dockerfile for the server.
- OpenTelemetry: one `visado.authorize` span per decision with `visado.*` attributes, exported over OTLP when `[telemetry] otlp_endpoint` is set. The lab sends them to Jaeger.
- `scripts/check.sh` runs every CI check locally.
- `visado-chain`: the format-neutral delegation chain model (`NormalizedChain`, `Hop`, signer binding, link, assurance) and the `ChainDecoder` trait.
- `visado-chain-aat`: Attenuating Agent Token verification per draft-niyikiza-oauth-attenuating-agent-tokens-02, §8 steps 1 to 7, with errors that name the failing step. Not yet used by the server.
- The 229 published AAT JWS vectors in `conformance/aat/`, from tenuo-ai/tenuo (Apache-2.0), all passing. A root `NOTICE` file records the attribution.

### Changed

- `visado-chain`: `NormalizedChain` has `holder_proof`. `ChainDecoder::decode` sets it to `false`; `visado-chain-aat`'s `Verifier::verify` sets it to `true` after the PoP check.

### Fixed

- The gate no longer treats a request that is not one MCP tool call as the path tool: batches, non-JSON bodies, malformed `tools/call` and missing bodies are denied.
- A bearer-only caller can no longer present an AAT chain; only a WIT caller whose key is the chain's holder can.
- The server requires `aud` on the chain and `aat_aud` on the proof by default.

- `visado-chain-aat`: the PoP JWT signature (steps 7a and 7b) is checked before the arguments are matched against the constraints (6b), as §8 recommends. Constraint value sets are built once when the token is parsed, each argument's JCS form is computed once, and a token may carry at most `Limits::max_constraint_nodes` (default 1024) constraint nodes. A request with a wide `any` and large arguments no longer costs tens of milliseconds before the sender is authenticated.
- `visado-chain-aat`: duplicate JSON member detection is linear, so a header with thousands of members no longer costs time before the signature check.
- `visado-chain-aat`: JCS number serialization breaks ties between equally short digit strings to even, as RFC 8785 requires (`905750064395076.25` is `905750064395076.2`). Digits come from the `ryu` crate. Before, some numbers were judged admissible or not the wrong way round.
- `visado-chain-aat`: with two trust anchors that share a key under different issuers, the root is matched to the anchor whose issuer equals `iss`, not to the first anchor whose key verifies.
- `visado-chain-aat`: `decode()` rejects an `aud` that is not a string or an array of strings instead of reading it as unrestricted.

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
