# Assurance case

Why visado can be trusted to do the one thing it is for, and where that trust ends. Each claim points at the code, test or document that backs it. The threat analysis behind it is in [research/05-threats.md](research/05-threats.md); the pipeline is in [design.md](design.md).

## What you can expect

visado is an enforcement point. For each request that reaches it over ext_authz, it:

- admits the request only if the caller proved a workload credential issued by a trust anchor you configured, for this request;
- admits a delegation chain only if every verified hop is signed and linked to its parent and no hop widens the authority, audience or lifetime it was given;
- asks your AuthZEN PDP and admits the request only on a decision of exactly `true`;
- removes the inbound credentials and replaces them with a short-lived Transaction Token that names the principal, the caller and the chain;
- writes an audit event for every allow and for every deny the pipeline makes under the `visado::audit` target, without tokens. The three denials the gRPC service makes before the pipeline (`request.no_http_attributes`, `request.invalid_header` and `internal.clock`) have no event.

Any failure along the way denies the request with a stable reason code. There is no configuration that turns a verification or PDP error into an allow.

## What you cannot expect

- visado is pre-alpha and implements Internet-Drafts that are still changing. It is not ready to protect production traffic.
- It does not make policy decisions. A permissive PDP policy produces permissive decisions.
- It cannot see what an upstream does after a request is admitted. A malicious or compromised server behind the proxy can misuse the access it was given.
- It protects only traffic that reaches it. A deployment where clients can bypass the proxy, or where a downstream accepts the original credentials directly, is outside its control.
- An attacker who wrote the prompt that steered an agent does not appear in the delegation chain. visado checks who delegated what to whom, not why.
- The Transaction Token signing key is a file read at startup. Storage in a KMS or HSM and key rotation are open questions ([design.md](design.md#open-questions)).
- The chain view has no authentication. It is off by default and refuses a non-loopback listener unless `allow_remote` is set ([design.md](design.md#chain-view)).
- Audit events go to the log stream. They are not signed or hash-chained by visado.

## Trust boundaries

| Boundary | Across it | Trusted? |
| --- | --- | --- |
| Proxy to visado (ext_authz gRPC) | Request headers, body when configured, peer certificate | Headers and body are untrusted input. The peer certificate is trusted as far as the proxy terminated mTLS. |
| Caller credentials | WIT, WPT, HTTP signatures, X.509-SVIDs, JWT-SVIDs, access tokens, DPoP proofs | Untrusted until verified against configured anchors |
| Delegation chains | AAT, asor and `act` tokens | Untrusted until verified; `Declared` hops never reach the PDP |
| Inbound Transaction Token | `Txn-Token` header | Accepted only from a workload listed in `internal_callers` that proved possession of a key; denied otherwise |
| visado to the PDP | AuthZEN request and response | The response is untrusted: anything but status 200, a matching `X-Request-ID` and a boolean `true` denies |
| Configuration and key files | TOML, JWKs, bundles | Trusted. Whoever can write them controls visado. |

## Secure design principles

- **Fail closed.** Every error is a deny. The PDP client returns an error for a non-200 status, a non-boolean decision, a mismatched request id and a timeout (`crates/authzen/tests/http.rs`, `every_failure_is_an_error`).
- **Least privilege.** The Transaction Token's scope is never wider than what was authorized, and chain authority only narrows (`chain.scope_escalation`, `chain.audience_widened`, `chain.exp_extended`). Replacement keeps `txn`, `sub` and `aud` and never widens scope.
- **Complete mediation.** One `Check` call runs every step in order and stops at the first failure ([design.md](design.md#request-pipeline)).
- **No trust from the token itself.** Keys come from configured JWKs, JWK sets and bundles per trust domain, never from a URL inside a token. Audience is an exact string match.
- **Economy of mechanism.** No policy language and no token format of visado's own; published formats only ([scope.md](scope.md#principles)).
- **Defence in depth for chains.** Each format crate verifies its chain by its own draft, then the format-neutral invariant engine checks it again, and the two must agree on every published vector ([design.md](design.md#3-delegation-chain)).
- **Secure defaults.** Clock leeway defaults to 30 s and is capped at 60 s (`crates/credentials/src/lib.rs`). The chain view is off. Transaction Tokens live 60 s by default.

## Common weaknesses countered

| Weakness | Countermeasure | Evidence |
| --- | --- | --- |
| Memory safety (CWE-119 family) | Rust with `unsafe_code = "forbid"` across the workspace | `Cargo.toml` `[workspace.lints.rust]` |
| Algorithm confusion, `alg: none` (CWE-347) | Allow-listed algorithms: RS256, PS256, ES256 and EdDSA for access tokens, RS256 and ES256 for JWT-SVIDs | `ALGORITHMS` in `crates/credentials/src/oauth.rs` and `svid.rs` |
| Replay (CWE-294) | WPT `jti`, HTTP signature `nonce`, DPoP `jti`, AAT PoP `jti` and asor proof `jti` checked against bounded caches, one per proof type, with per-caller quotas; optional DPoP server nonces | [bindings.md](bindings.md#replay), `crates/chain/src/replay.rs` |
| Resource exhaustion from input (CWE-400) | Credentials capped at 16 KiB and `jti` at 256 bytes; chains capped at 32 hops; bounded replay caches and chain-view buffer | `crates/credentials/src/lib.rs`, `crates/chain/src/invariants.rs` |
| Panics on untrusted input (CWE-248) | The credential, Transaction Token, AAT and AuthZEN response parsers are fuzzed in CI on every push and pull request | `fuzz/`, `.github/workflows/ci.yml` |
| Spoofed Transaction Token (CWE-290) | An inbound `Txn-Token` from a caller not in `internal_callers` is denied (`txn.untrusted_hop`) | `crates/extauthz/src/gate.rs` |
| Credential leakage to logs (CWE-532) | Audit events and the chain view never hold a token, proof, signature or header value | `crates/extauthz/src/lib.rs`, [design.md](design.md#chain-view) |
| Credential passthrough (CWE-441) | `Authorization`, the WIT, HTTP signature and chain headers are removed before the request goes upstream | `STRIPPED_HEADERS` and `Gate::new` in `crates/extauthz/src/gate.rs` |
| DNS rebinding against the chain view (CWE-350) | `Host` checked against `allowed_hosts`, 421 otherwise | [design.md](design.md#chain-view) |
| Vulnerable dependencies (CWE-1395) | `cargo deny check` for RustSec advisories, licenses and sources on every push; Dependabot weekly | `deny.toml`, [dependencies.md](dependencies.md) |
| Weak TLS | `rustls` only, which speaks TLS 1.2 and 1.3; certificate verification is never disabled | `Cargo.toml` |

## Supply chain

- Every GitHub Action is pinned by commit, container images by digest, and `Cargo.lock` is built with `--locked`.
- Releases are built in GitHub Actions, signed with cosign keyless, and ship an SPDX SBOM and SLSA build provenance ([RELEASING.md](../RELEASING.md)).
- CodeQL and OpenSSF Scorecard run on every push to `main`.

## Keeping this current

A change that adds a trust boundary, a credential type or a way to admit a request updates this file in the same pull request.
