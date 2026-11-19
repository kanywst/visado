# Spec map

Pinned revisions and where the code departs from them. Checked 2026-11-20.

## Pinned revisions

| Spec | Revision | Crate | Status |
| --- | --- | --- | --- |
| [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/) | -11 | `visado-txn-token` | Mint, verify, replace, request parsing |
| [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/01/) | -01 | (design) | Reference composition, not yet implemented |
| [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/) | -06 | (planned) | |
| [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/) | -02 | `visado-chain-aat` | §8 chain and PoP verification; 229/229 published vectors. Enforced by the gate (`docs/bindings.md`) |
| [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) | -03 | `visado-chain-asor` | §6 steps 1 to 6 and 8; 36/36 published vectors. Enforced by the gate (`docs/bindings.md`) |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) (DPoP) | RFC | `visado-chain` (`dpop`), `visado-credentials` | Proof checks of §4.3 and the §7.1 resource server rules for DPoP-bound access tokens; also the asor leaf proof. No server nonces (§8, §9) |
| [OpenID AuthZEN Authorization API](https://openid.net/specs/authorization-api-1_0.html) | 1.0 Final | `visado-authzen` | Single evaluation and metadata discovery |

WIMSE credentials (WIT, WPT, HTTP signatures per draft-ietf-wimse-http-signature-08, mTLS per draft-ietf-wimse-mutual-tls) come from [wimsey](https://github.com/kanywst/wimsey) 0.10.1, which keeps its own spec map. JWT-SVIDs follow the SPIFFE JWT-SVID and trust bundle specifications.

## Transaction Tokens: known divergences and choices

| Topic | Draft | visado |
| --- | --- | --- |
| Scope comparison | Not defined (§13.6) | Space-separated values compared as a set; narrower means subset |
| Call chain across replacement | MUST be preserved, method out of scope (§13.15) | `tctx` members carry over and cannot change; callers add chain data as new members |
| Lifetime extension on replacement | MAY, SHOULD limit (§13.15) | Caller passes `max_exp` to cap it |
| Missing REQUIRED claim | Not specified as an error class | Reported as `txn.malformed` (the claim set does not parse) |
| `req_wl` with several workloads | Ambiguous (§9.2) | Opaque string, replaced on each replacement |
| Signature algorithms | Not restricted | `Ed25519`, `EdDSA`, `ES256` only |
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
| Root `iss` is a URI | Required (step 3k) | A scheme, a colon, and no whitespace or control characters |
| JSON nesting | Not limited beyond MAX_CONSTRAINT_DEPTH | At most 256 levels; deeper payloads fail at signature-step parsing (3b, 4b, 7b) |
| Principal | AAT has no `sub` | `Principal::Unspecified` in the normalized chain |
| HTTP and MCP binding | Out of scope (§1) | `AAT-Chain` and `AAT-PoP` headers; tool and arguments from a JSON-RPC `tools/call` body (see `docs/bindings.md`) |
| Requests that are not one tool call | Not defined | Only two forms are accepted: a JSON-RPC `tools/call` object, and a GET, HEAD, DELETE or OPTIONS request with no body and no query string (tool `<METHOD> <path>`, arguments `{}`). Everything else is denied (`chain.bad_invocation`): batches, other JSON-RPC methods, non-JSON or unreadable bodies, malformed `tools/call`, query strings, and a missing body on POST, PUT or PATCH |
| Requests without a chain | Not defined | `[aat]` must set `required` explicitly; with `false`, a request without `AAT-Chain` skips the chain checks and the server warns at startup |
| Chain and Txn-Token scope | Not defined | The chain gates the call (tool and arguments); the minted `scope` is not narrowed by it. The chain is carried as `tctx.chain` on a minted token, or `tctx.chain:<caller>` on a replacement of a forwarded token |
| Who may present a chain | Holder proves possession with the PoP | Only a WIT caller, and the leaf `cnf` must be the WIT key; bearer-only callers are denied (`chain.unbound_caller`) |
| Audience (§9.5) | `aud` and `aat_aud` optional | The server requires both by default (`require_chain_aud`, `require_pop_aud`), so a chain cannot be replayed at another enforcement point |
| PoP replay | Shared state across replicas (§7.3) | In-memory cache of 100 000 entries per process |
| `aud` type | Checked at step 6c | Checked right after step 5 and reported as 6c, so `decode()` also rejects an `aud` that is not a string or an array of strings |
| `decode()` | Not defined | Steps 1 to 5 and the `aud` type check. No PoP, so the chain has `holder_proof: false` |

## asor: known divergences and choices

No divergences on the vectors: all 36 in [conformance/asor](conformance/asor/) give the expected verdict and the expected Table 2 outcome. The rows below are where visado chose, or where it differs from the reference implementation (attenu-guard 0.22.0) on inputs no vector covers.

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
| Step 7, status lists | Deny when status cannot be established | Not implemented: a token with a `status` claim is denied as `status_unknown`. A token without one is not checked |
| Cumulative constraints | Checked where the running total is held (step 8) | The library takes a `RunningTotals` source; the gate holds none, so a leaf with `max_lifetime` or `max_subtree` denies every call (`ceiling_exceeded`) |
| Per-action constraint with no matching parameter | Not defined | Denied (`ceiling_exceeded`), so an upstream default for an omitted argument cannot pass a ceiling. attenu-guard leaves it unbounded. A parameter of the wrong type is also `ceiling_exceeded` |
| Step 8 order | Audience, then the action against the leaf authority | Audience, scope, then each constraint in the token's order; the first failure is reported (attenu-guard collects every failing constraint) |
| DPoP proof | RFC 9449 | `typ` `dpop+jwt`, `Ed25519` or `ES256` with a public `jwk` whose thumbprint is the leaf `cnf.jkt`; `htm` and `htu` (without query or fragment, normalized as in the DPoP section below) match the request; `iat` within 60 s; `ath` required, over the leaf token; `jti` at most 256 bytes and accepted once per process. Server nonces are not supported |
| Size bounds | Not defined | At most 32 tokens, 64 KiB per token, 256 KiB per chain, 8 KiB per proof and 64 KiB of action parameters, checked before decoding |
| `check()` and `decode()` | Steps 1 to 5 without a request (§6.1) | `decode()` runs the parse rules and steps 1 to 5; `check()` adds the leaf audience, which is what the vectors test. Both return `holder_proof: false` |
| HTTP binding | Not defined | `Agent-Delegation-Chain` and `DPoP` headers; the format is chosen by the header, not by `typ`. The MCP tool name is the action's scope and its arguments the parameters (see `docs/bindings.md`) |
| Who may present a chain | The DPoP key holder | Only a WIT caller, and the leaf `cnf.jkt` must be the WIT key; bearer-only callers are denied (`chain.unbound_caller`) |
| -01 vectors | Do not conform to -03 | Not run: every one lacks `cnf` and `client_id` |

## AuthZEN: choices

| Topic | Spec | visado |
| --- | --- | --- |
| Agent acting for a user | Not defined | `subject` is the agent (`type: agent`); the user is `context.principal` |
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
| HTTP signature window | Tight `expires` (minutes) | `expires` minus `created` at most `max_signature_lifetime` (default 60 s, at most 300); the age of `created` at most that plus the clock leeway |
| HTTP signature nonce | Replay defense is the recipient's | Recorded per workload until `expires` in the WPT replay cache; at most 256 bytes |
| HTTP signature body | `Content-Digest` covered when present | The digest is recomputed over the body Envoy sends (`with_request_body`); `sha-256` only; a missing body counts as empty and a partial body is denied; unless the request has exactly one `Content-Length: 0`, a body is assumed and `content-digest` must be covered |
| HTTP signature failures | 400, one problem type, no detail | `httpsig.invalid`, 400, `application/problem+json`; the detail goes to the audit record only |
| User token with an HTTP signature | Not defined | Read from `x-user-token` (configurable) and used only when the signature covers it; `Authorization` next to a signature is denied |
| mTLS certificate source | The TLS peer | Envoy's `source.certificate`; Envoy must terminate TLS and be the only client of the gRPC port, which the server enforces by requiring a loopback `grpc_listen` unless `grpc_reachable_only_by_proxy` is set |
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
| Sender-constrained tokens (`cnf`) | RFC 9449, RFC 8705 | `cnf` with only a `jkt` string is a DPoP-bound token (below). Any other `cnf`, including `x5t#S256` (RFC 8705), is rejected (`token.sender_constrained`) |
| `scope` vs `scp` | RFC 9068 uses `scope` | `scp` (string or array) is read when `scope` is absent |
| No scope in a user token | Txn-Tokens §13.14 | Denied (`token.no_scope`); the default scope applies only to a workload without a user token |
| Several issuers | | Each needs a `subject_prefix`, so `sub` and `client_id` cannot collide |
| `typ` | RFC 9068 `at+jwt` | Not checked |

## DPoP (RFC 9449): choices

| Topic | RFC 9449 | visado |
| --- | --- | --- |
| Request | `Authorization: DPoP <token>` and one `DPoP` header (§7.1) | Same. No `DPoP` header, two of them, or a value with a comma (a proxy-joined pair) is `dpop.invalid` |
| `typ`, `alg`, `jwk` (§4.3 items 4 to 7) | `dpop+jwt`, asymmetric, public key only | `ES256`, `EdDSA` or `Ed25519` with a matching P-256 or Ed25519 JWK; private or symmetric members, `crit`, and every other `alg` are refused |
| `htm`, `htu` (items 8, 9) | Method; URI without query and fragment, normalized per RFC 3986 §6.2.2 and §6.2.3 | `htu` and `scheme://authority/path` of the request, each with scheme and host lowercased, the default port dropped and an empty path made `/`. Percent-encodings are compared as sent |
| `iat` (item 11) | Within an acceptable window | Within `dpop_iat_window` (default 60 s, at most 300 s) either side of now |
| `jti` (§11.1) | Not reused within the window | At most 256 bytes; recorded per proof key in the same bounded in-memory replay cache as WPT `jti` values, until `iat` plus the window. Not shared across replicas |
| `ath` (item 12) | Required with an access token | Required; base64url SHA-256 of the token as sent |
| Key binding (§6, §7.1) | `cnf.jkt` equals the proof key's RFC 7638 thumbprint | Same. A token without `cnf.jkt`, or a proof by another key, is `dpop.binding` (`invalid_token`) |
| Downgrade (§7.1) | A bound token must not be accepted as a bearer token | Denied as `Bearer` and as a user token next to a WPT or signature (`token.dpop_bound`) |
| Challenge (§7.1) | `WWW-Authenticate: DPoP` with `error` and `algs` | `DPoP error="invalid_dpop_proof"` for proof failures and replay, `error="invalid_token"` for token and binding failures; other access token failures send `Bearer, DPoP algs="ES256 EdDSA Ed25519"` |
| Server nonces (§8), authorization server side (§5, §10) | Optional | Not implemented: no `DPoP-Nonce`, no `use_dpop_nonce` |
| Holder key | | The proof key is the caller's `proof_key`, so an AAT chain held by it is accepted. An asor chain is refused (`chain.proof_conflict`): its leaf proof would need the same `DPoP` header |
