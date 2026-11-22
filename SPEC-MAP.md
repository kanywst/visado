# Spec map

Pinned revisions and where the code departs from them. Checked 2026-11-22.

## Pinned revisions

| Spec | Revision | Crate | Status |
| --- | --- | --- | --- |
| [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/) | -11 | `visado-txn-token` | Mint, verify, replace, request parsing; 7 valid and 27 negative own vectors and four rejected keys |
| [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/01/) | -01 | (design) | Reference composition, not yet implemented |
| [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/) | -06 | (planned) | |
| [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/) | -02 | `visado-chain-aat` | §8 chain and PoP verification; 229/229 published vectors. Enforced by the gate (`docs/bindings.md`) |
| [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) | -03 | `visado-chain-asor` | §6 steps 1 to 8; 36/36 published vectors and 27 own status list vectors. Enforced by the gate (`docs/bindings.md`) |
| [draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/21/) | -21 | `visado-chain-asor`, `visado` | Status List Tokens in JWT format (§5.1) and their validation (§8.3), for asor step 7; HTTP fetch (§8.1, §8.2). No CWT, no aggregation (§9), no historical resolution (§8.4) |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) OAuth 2.0 Token Exchange | RFC | `visado-chain-act` | §4.1 `act` claim of an access token read as a chain; 20 own vectors (two from the RFC's figures). Enforced by the gate (`docs/bindings.md`). No token endpoint, no `may_act` |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) (DPoP) | RFC | `visado-chain` (`dpop`), `visado-credentials` | Proof checks of §4.3, the §7.1 resource server rules for DPoP-bound access tokens and resource server nonces (§9, with §8 and §8.2); also the asor leaf proof. No authorization server side (§5, §10) |
| [OpenID AuthZEN Authorization API](https://openid.net/specs/authorization-api-1_0.html) | 1.0 Final | `visado-authzen` | Single evaluation and metadata discovery; the server uses a configured endpoint |

WIMSE credentials (WIT, WPT, HTTP signatures per draft-ietf-wimse-http-signature-08, mTLS per draft-ietf-wimse-mutual-tls) come from [wimsey](https://github.com/kanywst/wimsey) 0.10.1, which keeps its own spec map. draft-ietf-wimse-http-signature-09 (2026-11-20) is a newer revision, not yet tracked (checked 2026-11-22). JWT-SVIDs follow the SPIFFE JWT-SVID and trust bundle specifications.

## Transaction Tokens: known divergences and choices

| Topic | Draft | visado |
| --- | --- | --- |
| Scope comparison | Not defined (§13.6) | Space-separated values compared as a set; narrower means subset |
| Call chain across replacement | MUST be preserved, method out of scope (§13.15) | `tctx` members carry over and cannot change; callers add chain data as new members |
| Lifetime extension on replacement | MAY, SHOULD limit (§13.15) | Caller passes `max_exp` to cap it |
| Missing REQUIRED claim | Not specified as an error class | Reported as `txn.malformed` (the claim set does not parse) |
| `aud` as an array | Not said; RFC 7519 §4.1.3 allows a string or an array | A Txn-Token is scoped to one trust domain, so an array is accepted only with exactly one element, the trust domain. A one-element array with another domain is `txn.audience_mismatch`; an empty array, more than one element (even if one is the trust domain) or an element that is not a non-empty string is `txn.invalid_claim` |
| `req_wl` with several workloads | Ambiguous (§9.2) | Opaque string, replaced on each replacement |
| Signature algorithms | Not restricted; no mandatory-to-implement algorithm. The only example is `RS256` (§9.1) | `Ed25519`, `EdDSA`, `ES256`, and `RS256` with RSA keys of at least 2048 bits and the exponent 65537 (any other `e` is refused at load as `txn.invalid_key`; `e = 1` would let anyone forge signatures), both to mint (`TxnSigningKey::from_rsa_jwk`, an RSA `[signing_key]` in the server) and to verify (`KeySet::with_rsa_key`). kontxt signs and verifies RS256 only |
| Subject token type for a WIT | No URN defined | Not handled in this crate; the service decides |

## AAT: known divergences and choices

No divergences: all 229 vectors in [conformance/aat](conformance/aat/) give the expected verdict, and every denial fails at the expected §8 step.

| Topic | Draft | visado |
| --- | --- | --- |
| Algorithms | Ed25519 required, others MAY (§9.11) | `Ed25519` and `ES256`. `EdDSA` is rejected |
| `crit` | Reject parameters not understood (§3.5) | No extension parameter is understood, so any `crit` is rejected |
| `kid` | MAY select among trust anchors | If an anchor has that `kid`, only those anchors are tried; otherwise every anchor whose key fits `alg`. Of the anchors whose key verifies the signature, the one whose issuer equals `iss` is used |
| Step order | Steps 6 and 7 may be reordered; PoP signature SHOULD come before 6b | PoP size, header and signature (7a, 7b) run before 6b and 6c, so an unsigned request costs no constraint matching. 7c to 7i run after 6c. No vector changes its reported step |
| Constraint nodes per token | Not limited beyond MAX_CONSTRAINT_DEPTH | At most `max_constraint_nodes` (default 1024) across all tools of one token; more fails 3n or 4o |
| Argument and PoP size | Not limited | Each at most `max_token_size` |
| PoP `jti` tracking | Required for tools with side effects (§7.3) | The caller passes a `ReplayCache` for those tools. The in-memory cache refuses new proofs when full |
| PoP `iat` (step 7g) | Within `pop_window` (30 s) either side of now | At most 30 s behind now and at most `pop_max_future` ahead (`max_proof_skew` in the server file, default 5 s), so a PoP `jti` is remembered at most that much past now. The vectors run with the symmetric window |
| Root `iss` is a URI | Required (step 3k) | A scheme, a colon, and no whitespace or control characters |
| JSON nesting | Not limited beyond MAX_CONSTRAINT_DEPTH | At most 256 levels; deeper payloads fail at signature-step parsing (3b, 4b, 7b) |
| Principal | AAT has no `sub` | `Principal::Unspecified` in the normalized chain |
| HTTP and MCP binding | Out of scope (§1) | `AAT-Chain` and `AAT-PoP` headers; tool and arguments from a JSON-RPC `tools/call` body (see `docs/bindings.md`) |
| Requests that are not one tool call | Not defined | Only two forms are accepted: a JSON-RPC `tools/call` object, and a GET, HEAD, DELETE or OPTIONS request with no body and no query string (tool `<METHOD> <path>`, arguments `{}`). Everything else is denied (`chain.bad_invocation`): batches, other JSON-RPC methods, non-JSON or unreadable bodies, malformed `tools/call`, query strings, and a missing body on POST, PUT or PATCH. A body the proxy cut short (`x-envoy-auth-partial-body` not `false`, or a `Content-Length` other than the body's length) is `chain.partial_body` |
| Requests without a chain | Not defined | `[aat]` must set `required` explicitly; with `false`, a request without `AAT-Chain` skips the chain checks and the server warns at startup |
| Chain and Txn-Token scope | Not defined | The chain gates the call (tool and arguments); the minted `scope` is not narrowed by it. The chain is carried as `tctx.chain` on a minted token, or `tctx.chain:<caller>` on a replacement of a forwarded token |
| Who may present a chain | Holder proves possession with the PoP | Only a caller that proved possession of a key for the request (WIT, mTLS with an Ed25519 or P-256 certificate key, or a DPoP client), and the leaf `cnf` must be that key; bearer-only callers are denied (`chain.unbound_caller`) |
| Audience (§9.5) | `aud` and `aat_aud` optional | The server requires both by default (`require_chain_aud`, `require_pop_aud`), so a chain cannot be replayed at another enforcement point |
| PoP replay | Shared state across replicas (§7.3) | In-memory cache per process of `replay_capacity` entries (default 100 000), at most `replay_key_quota` of them per holder key once the cache is half full (default 1562) |
| `aud` type | Checked at step 6c | Checked right after step 5 and reported as 6c, so `decode()` also rejects an `aud` that is not a string or an array of strings |
| `decode()` | Not defined | Steps 1 to 5 and the `aud` type check. No PoP, so the chain has `holder_proof: false` |

## asor: known divergences and choices

No divergences on the vectors: all 36 in [conformance/asor](conformance/asor/) give the expected verdict and the expected Table 2 outcome. The published set has no `status` claims; step 7 is tested by visado's own vectors in [conformance/asor-status](conformance/asor-status/). The rows below are where visado chose, or where it differs from the reference implementation (attenu-guard 0.22.0) on inputs no vector covers.

| Topic | Draft | visado |
| --- | --- | --- |
| Signer of `DT_i`, i > 0 | Unspecified; single-signer model (§6.4) | Every token must verify under the anchor that signed `DT_0` (`SignerBinding::RootAnchor` on every hop); a child signed by another trusted anchor is denied |
| Algorithms | Ed25519 required, ES256 MAY; fully specified (§3, step 1) | `Ed25519` and `ES256`, taken from the anchor key's type. `EdDSA` is not accepted. `HS256` exists only for the vectors, through `TrustAnchor::hs256`; the server cannot configure it |
| `typ` and `crit` | `at+jwt` (RFC 9068) | `typ` must be `at+jwt` or `application/at+jwt`, and any `crit` is rejected, both as `malformed`. attenu-guard checks neither |
| `cnf` | Carries the JWK thumbprint, proven with DPoP (§7) | `cnf.jkt` is required. attenu-guard also accepts `jwk` or `x5t#S256` at parse; neither can be used with DPoP step 6 |
| `iat`, `exp`, `nbf` | NumericDate | Integers only; a fraction is `malformed` |
| Missing `par_hash` on a child; `del_depth` or the root `del_max_depth` missing or of the wrong shape | Required claims (§3) | `malformed` at parse. attenu-guard names these `par_hash_mismatch` (step 2) and `depth_invalid` (step 3) |
| A `par_hash` of the wrong length | Step 2 | `par_hash_mismatch`; one that is not base64url is `malformed` |
| `NaN` or `Infinity` literals | `non_finite` | Not JSON, so `malformed`. A number that overflows a double, such as `1e400`, is `non_finite` |
| A child's `del_max_depth` | Rule 5 only; step 3 checks the root's (§6) | Checked for rule 5 against the nearest ancestor that carries one, and not used as a depth cap. `Hop::max_depth` is the root's `del_max_depth - 1` on every hop |
| Step 7, status lists | Deny when status cannot be established; a cached answer is trusted for its time to live | Token Status List (-21) in JWT format, from lists the operator configures; the gate never fetches a URI taken from a token. A cached list is trusted until `fetched_at + min(ttl, max_age)` (default `max_age` 300 s) and never past its `exp`. `INVALID` and `SUSPENDED` are `revoked`; any value but `VALID` is `status_unknown`, as is an index past the end of the list or a `status` claim without `status_list`. A `status` claim of the wrong shape is `malformed`. A token without one is not checked |
| Status list signer | Not defined; §11.3 of the status list draft suggests the token issuer's key | Separately configured keys (`StatusListVerifier`); `Ed25519` and `ES256`. A list with `iss` must name the key's issuer |
| Status list `iat`, `exp`, `nbf`, `ttl` | NumericDate; `ttl` a positive number | Integers only. `iat` required; `exp` and `nbf` checked at fetch and `exp` again at each request. A fetched list issued before the one held is refused (rollback) and the held one kept |
| Revoked parent | By local policy, treat the whole subtree as revoked | Every token in the chain is checked, so a revoked ancestor denies the chain |
| Cumulative constraints | Checked where the running total is held (step 8) | The library takes a `RunningTotals` source; the gate holds none, so a leaf with `max_lifetime` or `max_subtree` denies every call (`ceiling_exceeded`) |
| Per-action constraint with no matching parameter | Not defined | Denied (`ceiling_exceeded`), so an upstream default for an omitted argument cannot pass a ceiling. attenu-guard leaves it unbounded. A parameter of the wrong type is also `ceiling_exceeded` |
| Step 8 order | Audience, then the action against the leaf authority | Audience, scope, then each constraint in the token's order; the first failure is reported (attenu-guard collects every failing constraint) |
| DPoP proof | RFC 9449 | `typ` `dpop+jwt`, `Ed25519` or `ES256` with a public `jwk` whose thumbprint is the leaf `cnf.jkt`; `htm` and `htu` (without query or fragment, normalized as in the DPoP section below) match the request; `iat` at most 60 s behind now and `max_proof_skew` (default 5 s) ahead; `ath` required, over the leaf token; `jti` at most 256 bytes and accepted once per process. With `[dpop] require_nonce`, a `nonce` visado issued is required as well (RFC 9449 §4.3 item 10, §11.3); a proof refused only for it is reported as `dpop.nonce_*` with a 401 and a fresh nonce rather than `holder_binding_failed` |
| Size bounds | Not defined | At most 32 tokens, 64 KiB per token, 256 KiB per chain, 8 KiB per proof and 64 KiB of action parameters, checked before decoding |
| `check()` and `decode()` | Steps 1 to 5 and, if a status list is available, step 7 without a request (§6.1) | `decode()` runs the parse rules and steps 1 to 5; `check()` adds step 7 (a `status` claim with no lists configured is `status_unknown`) and the leaf audience, which is what the vectors test. Both return `holder_proof: false` |
| HTTP binding | Not defined | `Agent-Delegation-Chain` and `DPoP` headers; the format is chosen by the header, not by `typ`. The MCP tool name is the action's scope and its arguments the parameters (see `docs/bindings.md`) |
| Who may present a chain | The DPoP key holder | Only a WIT caller or an mTLS caller with an Ed25519 or P-256 certificate key, and the leaf `cnf.jkt` must be that key; bearer-only callers are denied (`chain.unbound_caller`) and a DPoP client is `chain.proof_conflict` |
| Principal and a forwarded Txn-Token | Not defined | The chain's `sub` must be the forwarded Transaction Token's `sub` (`chain.principal_mismatch`) |
| -01 vectors | Do not conform to -03 | Not run: every one lacks `cnf` and `client_id` |

## RFC 8693 act: choices

RFC 8693 publishes no test vectors. [conformance/act](conformance/act/) has visado's own 20 cases, two of them the claim sets of the RFC's Figures 5 and 6.

| Topic | RFC 8693 | visado |
| --- | --- | --- |
| Current and prior actors | The outermost `act` is the current actor; nested ones are prior actors, the most deeply nested the least recent (§4.1) | Hops run from the least recent actor to the current one; the current actor is the leaf |
| Access control | Consider only the top-level claims and the current actor; prior actors "are not to be considered in access control decisions" (§4.1) | The PDP gets the current actor only. Prior actors and the depth go to the Transaction Token `tctx` and are never compared with anything. The current actor's hop is `Verified`; prior actors are `Declared` |
| Who the current actor is | Not defined for a resource server | The current actor's `sub` must equal the authenticated caller's identifier, or the caller `[act.actors]` maps it to; otherwise `act.actor_mismatch` |
| Who may present a chain | Not defined | Only a caller that proved possession of a key for the request, as for AAT and asor; a bearer token with `act` is denied (`chain.unbound_caller`) |
| Actor identity | `act` claims identify the actor; `iss` with `sub` may be needed (§4.1) | `sub` is required and a non-empty string (`act.missing_sub`); `iss`, when present, a non-empty string (`act.bad_issuer`). The actor is named by its `iss`, or the token's issuer without one. Binding compares `sub` only: the token's issuer vouches for the whole claim |
| Non-identity claims in `act` | Not meaningful and not used (§4.1) | Ignored |
| Shape of `act` | A JSON object | Anything else, outermost or nested (including `null`), is `act.not_object` |
| Nesting depth | Not limited | At most `max_actors` actors (default 8, at most 32); more is `act.too_deep` |
| Authority per actor | Not defined | None is invented: the token's `scope` is what the call may use, and the chain narrows nothing |
| Token without `[act]` | | A token with an `act` claim is denied (`chain.unsupported`), not read as the subject's own token |
| `act` next to another chain | | `chain.ambiguous` with `AAT-Chain` or `Agent-Delegation-Chain` |
| Principal and a forwarded Txn-Token | | The token's `sub` must be the forwarded Transaction Token's `sub` (`chain.principal_mismatch`) |
| `may_act` (§4.4) | Who may become the actor | Not read |
| Token exchange endpoint (§2) | Defined | Not implemented |

## Invariant engine and authority algebras: choices

Every chain goes through the format-neutral invariant engine after its format's checks (see `docs/design.md`). It agrees with every AAT, asor-03, asor status and act vector; [conformance/chain-invariants](conformance/chain-invariants/) has its own 39 cases. Where it is stricter than a draft, the engine's rule wins and the request is denied with its `chain.*` code.

| Topic | Draft | visado |
| --- | --- | --- |
| Audience narrowing | AAT checks every token's `aud` against the enforcement point (§8 step 6c); asor checks only the leaf's (step 8) | A hop's `aud` must be a non-empty subset of the restriction in force; a hop without `aud` inherits it. An asor child whose `aud` names an audience its parent's does not, or an AAT child that adds an audience, is `chain.audience_widened` |
| Repeated actors | AAT allows a holder to derive a token for itself and keys to cycle (§6.2); only `jti` must not repeat (step 2c) | The engine refuses a repeated token (`id`), not a repeated holder. Nested `act` hops share their token's identifier and are not compared |
| `del_max_depth` | AAT: each token's cap, never raised (§4.3); asor: only `DT_0` bounds the chain (step 3) | Read per profile, fixed by the profile (`aat-holder-cap`, `asor-strict`, `uncapped` for `act`) and named in the audit record as `depth_semantics`. An asor child's own `del_max_depth` is still checked by rule 5 in the decoder; the engine sees only `DT_0`'s |
| Chain length | AAT: `MAX_DELEGATION_DEPTH`; asor: 32 tokens; RFC 8693: not limited | At most 32 hops, whatever the format |
| Authority types | One per format | `attenuating_agent_token`, `agent_delegation` and `rfc8693-act`, each from its format's own rules. Any other type is `chain.unknown_authority`; authorities of two types never subsume each other |
| Cumulative asor constraints | Checked where the running total is held | The algebra holds no totals, so `max_lifetime` and `max_subtree` permit nothing, as in the gate |
| `act` authority | None per actor (§4.1) | The empty object is the only well-formed authority; the gate asks an `act` chain no action, and the algebra refuses one if asked |
| Status | asor step 7 | A hop with a status reference records whether it was checked; a chain from `decode()` has it unchecked and is `chain.status_unchecked` |

## AuthZEN: choices

| Topic | Spec | visado |
| --- | --- | --- |
| Agent acting for a user | Not defined | `subject` is the agent (`type: agent`, or `client` for an OAuth client); the user is `context.principal` |
| `X-Request-ID` echo | PDP MUST echo it | A different echo is an error; a missing echo is tolerated |
| Non-boolean `decision` | Must be boolean | Treated as an error, so the request is denied |
| Batch and search APIs | Defined | Not used |

## WIMSE credentials: choices

| Topic | Draft | visado |
| --- | --- | --- |
| User token next to a WPT | Bound through `oth` | Read from `x-user-token` (configurable) and used only when `oth` binds it |
| WPT replay | `jti` | In-memory cache per process; when full, new proofs are rejected |
| Key selection | Not specified | The unverified `sub` trust domain and `kid` select a configured key; the signature is then checked |
| Proof `jti` length | Not limited | At most 256 bytes |
| Method selection | One method per request | Fixed order by headers (`docs/bindings.md`); a WIT with both `Authorization` and `Signature-Input` is a WPT if the scheme is `WPT`, otherwise denied |
| HTTP signature audience | `wimse-aud` against the recipient's configured audiences | Compared with the request's scheme, authority and path, like WPT `aud`; the authority must be in `allowed_authorities`, which visado refuses to start without |
| HTTP signature window | Tight `expires` (minutes) | `expires` minus `created` at most `max_signature_lifetime` (default 60 s, at most 300); the age of `created` at most that plus the clock leeway; `created` at most `max_proof_skew` (default 5 s) ahead of the clock |
| HTTP signature nonce | Replay defense is the recipient's | Recorded per workload until `expires` in the WPT replay cache; at most 256 bytes |
| HTTP signature body | `Content-Digest` covered when present | The digest is recomputed over the body Envoy sends (`with_request_body`); `sha-256` only; a missing body counts as empty and a partial body is denied; unless the request has exactly one `Content-Length: 0`, a body is assumed and `content-digest` must be covered |
| HTTP signature failures | 400, one problem type, no detail | `httpsig.invalid`, 400, `application/problem+json`; the detail goes to the audit record only |
| User token with an HTTP signature | Not defined | Read from `x-user-token` (configurable) and used only when the signature covers it; `Authorization` next to a signature is denied |
| mTLS certificate source | The TLS peer | Envoy's `source.certificate`; Envoy must terminate TLS and be the only client of the gRPC port, which the server enforces by requiring a loopback `grpc_listen` unless `[grpc_tls]` requires a client certificate or the top-level `grpc_reachable_only_by_proxy` is set |
| mTLS path validation | RFC 5280 path validation and revocation | One CA per trust domain that signs the leaf directly; no intermediates, name constraints or revocation. The leaf must not be a CA and its key usage, if present, must allow signatures only |
| mTLS with credential headers | Not defined | A WIT or `Authorization` header takes precedence; the certificate authenticates only a request with neither |
| Proof key for AAT chains | Not defined | The WIT `cnf` key (WPT and HTTP signature) or the certificate key (mTLS, Ed25519 or P-256); bearer methods have none and cannot present a chain |

## SPIFFE JWT-SVID: choices

| Topic | Spec | visado |
| --- | --- | --- |
| Algorithms | RS256 to PS512, ES256 to ES512 | `RS256` and `ES256` only |
| `typ` | `JWT` or `JOSE` if present | Same |
| `aud` | Required, validated | Required; one of `[jwt_svid] audiences`, exact match |
| `kid` | Optional | Selects the bundle key; without it only a bundle with one key works. Bundle keys must have `kid` |
| Bundle | SPIFFE trust bundle, keys with `use` | Read from a file per trust domain; only `use: jwt-svid` keys; no refresh |
| Telling it from an OAuth token | Not defined | `sub` is a SPIFFE ID and `iss` is not a configured OAuth issuer |
| Holder binding | Bearer | No proof key: no AAT chain, no Txn-Token forwarding, no user token |

## OAuth access tokens: choices

| Topic | Spec | visado |
| --- | --- | --- |
| Sender-constrained tokens (`cnf`) | RFC 9449, RFC 8705 | `cnf` with only a `jkt` string, or with Keycloak's `kc-jkt-type` `DPoP` next to it, is a DPoP-bound token (below). Any other `cnf`, including `x5t#S256` (RFC 8705), is rejected (`token.sender_constrained`) |
| `scope` vs `scp` | RFC 9068 uses `scope` | `scp` (string or array) is read when `scope` is absent |
| No scope in a user token | Txn-Tokens §13.14 | Denied (`token.no_scope`); the default scope applies only to a workload without a user token |
| Several issuers | | Each needs a `subject_prefix`, so `sub` and `client_id` cannot collide |
| `typ` | RFC 9068 `at+jwt` | Not required. An AAT `typ` (`aat+jwt`, `aat-pop+jwt`) is rejected (`token.delegation`) |
| Delegation-chain tokens | Not defined | A token with `del_depth`, `del_max_depth`, `par_hash`, `status`, an AAT proof claim or an `authorization_details` entry of type `agent_delegation` or `attenuating_agent_token` (any case, trimmed) is rejected (`token.delegation`): it is verified only on its chain path. An `[aat]` or `[asor]` anchor key in an OAuth issuer's JWKS stops startup |
| `authorization_details` shape | RFC 9396 §2: a JSON array | Anything else is rejected on the access-token path (`token.invalid`) |
| JWKS key `use`, `key_ops`, `alg` | RFC 7517 §4.2-4.4 | A key with `use` other than `sig`, `key_ops` without `verify`, or an `alg` other than the token's is not used. A token without `kid` verifies only when the JWKS holds exactly one key in total and that key passes these checks |

## DPoP (RFC 9449): choices

| Topic | RFC 9449 | visado |
| --- | --- | --- |
| Request | `Authorization: DPoP <token>` and one `DPoP` header (§7.1) | Same. No `DPoP` header, two of them, or a value with a comma (a proxy-joined pair) is `dpop.invalid` |
| `typ`, `alg`, `jwk` (§4.3 items 4 to 7) | `dpop+jwt`, asymmetric, public key only | `ES256`, `EdDSA` or `Ed25519` with a matching P-256 or Ed25519 JWK; private or symmetric members, `crit`, and every other `alg` are refused |
| `htm`, `htu` (items 8, 9) | Method; URI without query and fragment, normalized per RFC 3986 §6.2.2 and §6.2.3 | `htu` and `scheme://authority/path` of the request, each with scheme and host lowercased, the default port dropped and an empty path made `/`. Percent-encodings are compared as sent |
| `iat` (item 11) | Within an acceptable window | At most `dpop_iat_window` (default 60 s, at most 300 s) behind now and at most `max_proof_skew` (default 5 s, at most 60 s) ahead, so a proof's `jti` is remembered at most that much past now |
| `jti` (§11.1) | Not reused within the window | At most 256 bytes; recorded per proof key in the same bounded in-memory replay cache as WPT `jti` values, until `iat` plus the window. Not shared across replicas |
| `ath` (item 12) | Required with an access token | Required; base64url SHA-256 of the token as sent |
| Key binding (§6, §7.1) | `cnf.jkt` equals the proof key's RFC 7638 thumbprint | Same. A token without `cnf.jkt`, or a proof by another key, is `dpop.binding` (`invalid_token`) |
| Downgrade (§7.1) | A bound token must not be accepted as a bearer token | Denied as `Bearer` and as a user token next to a WPT or signature (`token.dpop_bound`) |
| Challenge (§7.1) | `WWW-Authenticate: DPoP` with `error` and `algs` | `DPoP error="invalid_dpop_proof"` for proof failures and replay, `error="invalid_token"` for token and binding failures; other access token failures send `Bearer, DPoP algs="ES256 EdDSA Ed25519"` |
| Resource server nonces (§9, item 10) | Optional; nonces opaque and unpredictable, at most one `DPoP-Nonce` per response (§8) | Off by default; `[dpop] require_nonce` turns them on for DPoP-bound access tokens and asor leaf proofs alike. A proof valid but for its `nonce` is a 401 `DPoP error="use_dpop_nonce"` (`dpop.nonce_missing`, `dpop.nonce_invalid`, `dpop.nonce_expired`). Checked after every other check, so a `use_dpop_nonce` answer means a retry with the nonce can succeed |
| Nonce form and lifetime (§8, §11.1, §11.2) | Out of scope; a nonce may carry the server's time | Stateless: version, issue time and a 16-byte HMAC-SHA256 tag, base64url (34 characters). Accepted for `nonce_lifetime` (default 300 s, at most 3600 s) and up to 5 s ahead of the clock. The first of `nonce_key_files` issues and all verify, so replicas can share a key and rotate it; without files the key is random per process. A nonce is not single use; `iat` is still checked against `dpop_iat_window` and `jti` replay as before |
| Providing nonces (§8, §8.2) | In the error response, or in any response for the next request | A fresh `DPoP-Nonce` on every 401 while nonces are required, with `Cache-Control: no-store`, and on every allowed request that carried a DPoP proof, through ext_authz `response_headers_to_add`. No `Cache-Control` is added to an allowed response, which answers a request with `Authorization`. No `Access-Control-Expose-Headers`: CORS is the proxy's |
| Authorization server side (§5, §8 as an AS, §10) | | Not implemented: visado is a resource server |
| Holder key | | The proof key is the caller's `proof_key`, so an AAT chain held by it is accepted. An asor chain is refused (`chain.proof_conflict`): its leaf proof would need the same `DPoP` header |
