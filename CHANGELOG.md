# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a breaking change bumps the minor version and anything else bumps the patch. All crates share one version.

## [Unreleased]

### Added

- `visado-chain-asor`: step 7 of draft-asor-wimse-agent-delegation-chain-03 with Token Status Lists (draft-ietf-oauth-status-list-21, JWT format). `StatusListVerifier` checks a Status List Token (`typ`, signature under a configured key, `sub`, `iat`, `exp`, `nbf`, `ttl`, `bits`, ZLIB `lst`, size limits), a `StatusLists` source such as `MemoryStatusLists` holds verified lists, and `Verifier::with_status_lists` and `with_status_max_age` turn the check on. `INVALID` and `SUSPENDED` entries deny as `revoked`; an unknown, unfetched, invalid, expired or stale list, an index out of range, an unknown status value or another status mechanism deny as `status_unknown`. `AsorError::reason` gives the finer reason. `check()` runs step 7 too, so a `status` claim with no lists configured is `status_unknown`.
- 27 asor status list vectors in `conformance/asor-status/`, visado's own.
- `[asor.status]` in the server file: the Status List Tokens the gate holds, from a file (verified at startup) or fetched from an `https` or loopback `uri`, refreshed in the background (`refresh`, `timeout_ms`), trusted for at most `max_age` (default 300 s). See `docs/bindings.md`.
- `deploy/lab`: agentgateway v1.7.0 as a second front proxy on port 10001. Its `extAuthz` policy calls visado over gRPC with the raw body, from the internal authz network that Envoy also shares. `demo.sh` runs nine scenarios through it (no credentials, encoded slash, WIT+WPT with the Txn-Token check upstream, a PDP deny, AAT allow and deny, a signed request and a changed body, DPoP). agentgateway sends no peer certificate, so the mTLS scenarios stay on Envoy.
- `[pdp] context_in_subject` (default `false`) also sends the AuthZEN `context` members as `subject.properties`, for PDPs that do not pass `context` to the policy. Cerbos is one: it gives the policy subject properties as principal attributes. `visado-authzen` has `EvaluationRequest::with_context_in_subject` and `HttpPdp::with_context_in_subject`.
- `deploy/lab` runs with Cerbos 0.57.0 as the PDP too: `compose.cerbos.yaml` swaps OPA for Cerbos, `cerbos/http_resource.yaml` is the lab policy ported from Rego with its own tests, and CI runs `demo.sh` against both PDPs.

- RFC 9449 resource server nonces (§9), off by default. `visado_chain::dpop::Nonces` issues and checks stateless nonces (an issue time under a truncated HMAC-SHA256, accepted for a lifetime, under the first or any later key); `Expected::nonces` makes `verify` require one and report `Rejection::Nonce` after every other check. `Authenticator::with_dpop_nonces` requires a nonce in DPoP proofs for access tokens (`AuthError::DpopNonce`), and the gate gives the asor verifier the same nonces, or keeps the verifier's own (`Verifier::with_dpop_nonces`, `Verifier::dpop_nonces`, `AsorError::dpop_nonce`). A leaf proof's challenge advertises the leaf algorithms (`visado_chain_asor::DPOP_ALGS`, `Ed25519 ES256`). A proof refused only for its nonce is a 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` and the new codes `dpop.nonce_missing`, `dpop.nonce_invalid` or `dpop.nonce_expired`, and its `jti` is not recorded. Every 401 carries a fresh `DPoP-Nonce` with `Cache-Control: no-store`, and an allowed request with a DPoP proof gets the next one through ext_authz `response_headers_to_add`.
- `[dpop]` in the server file: `require_nonce`, `nonce_lifetime` (default 300 s, at most 3600 s) and `nonce_key_files` (base64url keys of at least 32 bytes; the first issues, all verify). Without key files a random key is made at startup.
- `deploy/lab` checks visado's reason code on every denial it decides (`credential.missing`, `pdp.deny`, `txn.untrusted_hop`, `aat.invocation_denied`, `aat.bad_signature`), and admits an OAuth client with a plain bearer access token (and refuses an expired one, `token.expired`) through `lab_methods bearer`.
- `deploy/lab` requires DPoP nonces. `demo.sh` walks the retry through Envoy and agentgateway: a proof without a nonce is 401 `dpop.nonce_missing` with `use_dpop_nonce` and a `DPoP-Nonce`, the retry with it is 200 with the next nonce, and a nonce visado did not issue is 401 `dpop.nonce_invalid`. `lab_methods dpop` takes `--nonce`.

- `visado-chain`: the format-neutral invariant engine (`invariants::Engine`). It checks any `NormalizedChain`: shape, links and signer bindings, an unchanging principal, monotone `exp`, depth limits read per profile (`DepthSemantics`: `AsorStrict`, `AatHolderCap`, `Uncapped`), audiences that only narrow, no repeated token, verified hops ending the chain, authorities that have an algebra and attenuate, checked status, holder proof, and the action. Each broken invariant has a stable `chain.*` code. `check_chain` runs the checks that need no request.
- `visado-chain`: the `AuthorityAlgebra` trait (`subsumes`, `permits`) and the `Algebras` registry; a type without an algebra is denied. `visado-chain-aat`, `visado-chain-asor` and `visado-chain-act` each implement it for their type (`Algebra`; `Verifier::algebra` for the verifier's limits).
- 39 chain invariant vectors in `conformance/chain-invariants/`, visado's own, and property tests for the AAT and asor algebras (reflexive, transitive, attenuation never widens). The engine is also run against every AAT, asor and act vector.
- The audit record of an accepted chain has a `depth_semantics` field.

### Changed

- `visado-extauthz`: `Outcome::Allow` has `response_headers` and `Outcome::Deny` has `headers`, for `DPoP-Nonce` and `Cache-Control`. `visado_chain::dpop::Expected` has a `nonces` field and `Rejection` a `Nonce` variant, and `AuthError` has `DpopNonce`.
- The gate runs every delegation chain through the invariant engine after the format's checks. It now also denies an asor or AAT child whose `aud` names an audience outside its parent's (`chain.audience_widened`), and any chain of more than 32 hops.
- `visado-chain`: `Hop` has two new fields, `principal` (the principal the hop's own token names) and `status` (`StatusCheck`: whether its status reference was checked). Code that builds a `Hop` must set them. The asor decoder marks a status reference `Unchecked` from `decode()` and `Valid` after step 7.
- `docs/design.md`: the `del_max_depth` open question is decided: the semantics is fixed per profile and reported in the audit record.
- `visado-chain-asor`: a `status` claim of the wrong shape (not a non-empty object, or a `status_list` without a non-negative integer `idx` and a non-empty string `uri`) is now `malformed` at parse, so `check()` and `decode()` reject it too.

## [0.3.0] - 2026-11-21

Adds the remaining workload authentication methods (HTTP signatures, mTLS, JWT-SVID, DPoP-bound access tokens), asor and RFC 8693 `act` delegation chains, and a chain view; the lab runs on SPIRE-issued SVIDs and exercises every method through Envoy. Breaking: the server refuses to start with an empty `allowed_authorities`, and denies access tokens with an `act` claim unless `[act]` is configured. For library users, `RequestView`, `CheckInput`, `GateConfig` and `AccessToken` have new fields, `CheckInput::body` is bytes, and `Method` and `AuthError` have new variants.

### Added

- `[[wit_issuers]]` takes `jwks_file`, a JWK set such as a SPIRE WIT bundle, instead of single key files. A key without `alg` gets the one algorithm its type allows; a key without `kid`, a repeated `kid` or an unsupported key fails startup. The lab uses it for SPIRE's bundle.
- `visado-credentials`: a WIT caller can sign the request with an HTTP message signature (draft-ietf-wimse-http-signature-08) instead of sending a WPT. The draft's profile and required components, `wimse-aud`, the `created`/`expires` window (`max_signature_lifetime`, default 60 s), nonce replay and a covered `Content-Digest` against the received body are checked. Failures are `httpsig.invalid` with status 400 and an RFC 9457 problem document.
- `visado-credentials`: mTLS with an X.509-SVID that Envoy terminated and passes in `source.certificate`, verified against one CA per trust domain (`[mtls]`). The certificate key is the AAT holder key. `[mtls]` needs a loopback `grpc_listen` unless `grpc_reachable_only_by_proxy = true`.
- `visado-credentials`: SPIFFE JWT-SVIDs as bearer tokens (`RS256`, `ES256`), verified against a JWT bundle per trust domain (`[jwt_svid]`).
- The PDP context and the Transaction Token `tctx` name the new methods `wit-httpsig`, `mtls` and `jwt-svid`.
- Credential headers longer than 16 KiB are denied (`credential.too_large`) before decoding.
- The audit event has a `detail` field with the reason an authentication failed.
- `visado-credentials`: DPoP-bound access tokens (RFC 9449) as `Authorization: DPoP` with one `DPoP` proof. The token's `cnf.jkt` must be the proof key's thumbprint; `htm`, `htu`, `iat` (`dpop_iat_window`, default 60 s), `ath` and `jti` replay are checked. The caller is `Method::OAuthDpop` with the proof key as `proof_key`, named `oauth-dpop` in the PDP context and `tctx`. New codes `dpop.invalid`, `dpop.replay`, `dpop.binding` and `token.dpop_bound`. Server nonces are not supported.
- A 401 for a DPoP failure carries `WWW-Authenticate: DPoP` with `error` (`invalid_dpop_proof` or `invalid_token`) and `algs`; other access token failures send `Bearer, DPoP algs="..."`.
- `visado-chain`: a shared `dpop` module with the RFC 9449 proof checks, used by `visado-chain-asor` and `visado-credentials`.
- Testkit fixtures: DPoP proofs and DPoP-bound access tokens, an HTTP signature signer, a workload CA and X.509-SVIDs, and a JWT-SVID signer with a SPIFFE bundle.
- `visado-chain-asor`: Agent Delegation Chain verification per draft-asor-wimse-agent-delegation-chain-03: the parse rules, steps 1 to 5, the DPoP proof of the leaf key (step 6) and the audience and action check (step 8), with denials named as in the draft's Table 2. A token with a `status` claim is denied as `status_unknown`, since status lists are not implemented.
- The 36 published asor-03 vectors in `conformance/asor/`, from attenu-io/attenu-guard v0.22.0 (Apache-2.0), all passing. `NOTICE` records the attribution.
- The gate verifies an asor chain sent in `Agent-Delegation-Chain` with a `DPoP` proof (see `docs/bindings.md`), with the same caller binding as AAT. Configured with `[asor]` in the server file, whose `required` has no default.
- `visado-chain`: `Profile::Asor03`, and the shared `json` (strict parser and JCS), `jose` (compact JWS parts and JWK thumbprints) and `replay` modules.
- `deploy/lab`: SPIRE v1.16.0 issues the workloads' WIT-SVIDs (experimental `enable_wit_svids`). A one-shot `wit-config` service writes visado's `[[wit_issuers]]` from the SPIRE WIT bundle before visado starts, and `demo.sh` signs WPTs and AAT holder proofs with the keys SPIRE issued.
- `deploy/lab` exercises the other caller methods through Envoy: WIT with an HTTP message signature (allowed, replayed nonce, body changed under the covered `Content-Digest`), mTLS on a second Envoy listener that terminates TLS with the gateway's SPIRE X.509-SVID and passes agent-a's X.509-SVID as `source.certificate` (allowed, unbound user token, certificate from another CA), SPIRE JWT-SVIDs (allowed, wrong audience) and a DPoP-bound access token (allowed, sent as `Bearer`). `spire-setup` writes the X.509 CA and the SPIFFE-format bundle for visado's `[mtls]` and `[jwt_svid]`, a `gateway-svid` one-shot writes Envoy's certificate, and a new `lab_methods` testkit example prints the signed and DPoP requests. `demo.sh` can check visado's error code as well as the status.

- `visado-chain-act`: reads the RFC 8693 `act` claim of a verified access token as a delegation chain (principal `sub`, actors from the least recent to the current one) and requires the current actor to be the authenticated caller, directly or through a mapping. Errors are `act.not_object`, `act.missing_sub`, `act.bad_issuer`, `act.too_deep` and `act.actor_mismatch`.
- The gate enforces `act` chains in a user token bound to a key-holding caller (see `docs/bindings.md`); a bearer token with an `act` claim is denied (`chain.unbound_caller`), as for AAT and asor. The PDP gets only the current actor and the kind of caller it was bound to (`caller_kind`), as RFC 8693 §4.1 keeps prior actors out of access control; the Transaction Token `tctx` also records the prior actors and the depth. Configured with `[act]` in the server file: `required` (no default), `max_actors` (default 8) and an `[act.actors]` mapping.
- 20 `act` vectors in `conformance/act/`, visado's own except for the claim sets of RFC 8693 Figures 5 and 6.
- `visado-chain`: `Profile::Rfc8693Act`, `ActorId::Subject` and `Link::Nested`.
- `visado-credentials`: `AccessToken` has `act`, `id` (`jti`), `issued_at` and `key_thumbprint` (the issuer key that verified it).
- The chain view, off by default (`[chain_view] enabled = true`): the gate keeps a summary of each recent decision in a bounded in-memory buffer (`capacity`, default 256), and the HTTP listener serves `GET /api/requests`, `GET /api/requests/{id}` and a page at `/chain` that draws principal, hops (verified or declared), caller, PDP decision and deny reason. Summaries hold identifiers and outcomes only, never tokens, proofs, headers or bodies. It shows caller and principal identities: the server refuses to start with it on a non-loopback `http_listen` unless `allow_remote = true`, and answers only the `Host` names in `allowed_hosts`. See `docs/design.md`.
- `visado-extauthz`: `RequestLog`, the `recent` module and `Gate::with_request_log`.
- `deploy/lab`: the chain view at `http://127.0.0.1:8080/chain`, published to the host's loopback address only.

### Changed

- The server refuses to start when `allowed_authorities` is empty; it used to warn.
- An access token with `cnf.jkt` sent as `Bearer` or as a user token is denied as `token.dpop_bound` instead of `token.sender_constrained`; any other `cnf` is still `token.sender_constrained`.
- asor DPoP proofs: the signature is checked before the key is compared with the leaf `cnf.jkt`, and `htu` is compared after lowercasing scheme and host and dropping a default port.
- The gate denies an asor chain from an OAuth client authenticated with DPoP (`chain.proof_conflict`).
- A delegation chain that names its principal (asor, `act`) on a forwarded Transaction Token must have the token's `sub` as its principal (`chain.principal_mismatch`), so a replacement token cannot record one user's chain in another user's transaction.
- The server refuses to start when `[aat]`, `[asor]` and `[act]` set different `required` values; a format with `required = false` used to let requests without any chain through next to one with `required = true`.
- The gate denies an access token that carries an `act` claim unless `[act]` is configured (`chain.unsupported`); it used to ignore the claim. A token with an `act` claim next to an `AAT-Chain` or `Agent-Delegation-Chain` header is `chain.ambiguous`.
- An internal caller may forward a `Txn-Token` after a WPT, an HTTP signature that covers it, or mTLS; bearer callers still cannot.
- The gate removes `Signature` and `Signature-Input` before the request goes upstream.
- The gate refuses a non-UTF-8 body for an AAT invocation itself; the service no longer replaces such a body with a marker.
- The strict JSON parser, the JWS helpers and the replay cache moved from `visado-chain-aat` to `visado-chain`. `visado-chain-aat` re-exports `ReplayCache` and `MemoryReplayCache`; its behaviour is unchanged.
- The lab's ext_authz filters set `pack_as_bytes: true`, as `docs/bindings.md` asks for signed bodies.
- `deploy/lab` no longer signs WITs with the fixed `wit-1` demo key. `lab_headers` and `lab_aat` take a directory of `spire-agent api fetch wit -output json` outputs as their first argument.
- The gate denies a request that carries both `AAT-Chain` and `Agent-Delegation-Chain` (`chain.ambiguous`). The chain context sent to the PDP and the Transaction Token has `principal` when the format names one.

## [0.2.0] - 2026-11-19

Adds AAT delegation-chain verification to the gate, the lab, tracing and the project site. Breaking: `[aat]` must set `required`, and the gate denies AAT requests that are not one tool call or a plain body-less request.

### Added

- The gate verifies an AAT chain sent in `AAT-Chain` and `AAT-PoP` (see `docs/bindings.md`), reads the tool and arguments from an MCP `tools/call` body, requires the chain's holder to be the WIT key when a WIT is present, and passes the chain to the PDP and into the Transaction Token `tctx`. Configured with `[aat]` in the server file.
- `deploy/lab`: Envoy, visado, OPA with the AuthZEN plugin and an echo upstream in Docker Compose, with thirteen scenarios in `demo.sh` that CI runs.
- A Dockerfile for the server.
- OpenTelemetry: one `visado.authorize` span per decision with `visado.*` attributes, exported over OTLP when `[telemetry] otlp_endpoint` is set. The lab sends them to Jaeger.
- `scripts/check.sh` runs every CI check locally.
- `visado-chain`: the format-neutral delegation chain model (`NormalizedChain`, `Hop`, signer binding, link, assurance) and the `ChainDecoder` trait.
- `visado-chain-aat`: Attenuating Agent Token verification per draft-niyikiza-oauth-attenuating-agent-tokens-02, §8 steps 1 to 7, with errors that name the failing step.
- The 229 published AAT JWS vectors in `conformance/aat/`, from tenuo-ai/tenuo (Apache-2.0), all passing. A root `NOTICE` file records the attribution.
- cargo-fuzz targets in `fuzz/` for Transaction Token verification and token requests, AAT chain verification and decoding, AuthZEN responses and caller authentication, seeded from the conformance vectors. CI runs each for 30 seconds.
- The Dockerfile pins its base images by digest, and Dependabot keeps the digests current.

### Changed

- `visado-chain`: `NormalizedChain` has `holder_proof`. `ChainDecoder::decode` sets it to `false`; `visado-chain-aat`'s `Verifier::verify` sets it to `true` after the PoP check.

### Fixed

- A chain verified on a forwarded Transaction Token is recorded in a replacement token (`tctx.chain:<caller>`) instead of being dropped.
- The gate accepts only two request forms with an AAT chain (one `tools/call`, or a body-less GET/HEAD/DELETE/OPTIONS without a query string) and denies the rest. `[aat] required = true` denies requests that carry no chain.
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

[Unreleased]: https://github.com/kanywst/visado/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kanywst/visado/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kanywst/visado/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kanywst/visado/releases/tag/v0.1.0
