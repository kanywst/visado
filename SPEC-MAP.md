# Spec map

Pinned revisions and where the code departs from them. Checked 2026-11-19.

## Pinned revisions

| Spec | Revision | Crate | Status |
| --- | --- | --- | --- |
| [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/) | -11 | `visado-txn-token` | Mint, verify, replace, request parsing |
| [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/01/) | -01 | (design) | Reference composition, not yet implemented |
| [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/) | -06 | (planned) | |
| [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/) | -02 | `visado-chain-aat` | §8 chain and PoP verification; 229/229 published vectors. Enforced by the gate (`docs/bindings.md`) |
| [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) | -03 | `visado-chain-asor` | §6 steps 1 to 6 and 8; 36/36 published vectors. Enforced by the gate (`docs/bindings.md`) |
| [OpenID AuthZEN Authorization API](https://openid.net/specs/authorization-api-1_0.html) | 1.0 Final | `visado-authzen` | Single evaluation and metadata discovery |

WIMSE credentials (WIT, WPT, HTTP signatures, mTLS) come from [wimsey](https://github.com/kanywst/wimsey), which keeps its own spec map.

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
| Signer of `DT_i`, i > 0 | Unspecified; single-signer model (§6.4) | Every token must verify under a configured trust anchor whose issuer equals its `iss` (`SignerBinding::RootAnchor` on every hop) |
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
| Per-action constraint with no matching parameter | Not defined | Not bounded, as in attenu-guard. A parameter of the wrong type is `ceiling_exceeded` |
| Step 8 order | Audience, then the action against the leaf authority | Audience, scope, then each constraint in the token's order; the first failure is reported (attenu-guard collects every failing constraint) |
| DPoP proof | RFC 9449 | `typ` `dpop+jwt`, `Ed25519` or `ES256` with a public `jwk` whose thumbprint is the leaf `cnf.jkt`; `htm` and `htu` (without query or fragment) match the request; `iat` within 60 s; `ath` required, over the leaf token; `jti` at most 256 bytes and accepted once per process. Server nonces are not supported |
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

## OAuth access tokens: choices

| Topic | Spec | visado |
| --- | --- | --- |
| Sender-constrained tokens (`cnf`) | RFC 9449, RFC 8705 | Rejected until DPoP and mTLS binding are implemented |
| `scope` vs `scp` | RFC 9068 uses `scope` | `scp` (string or array) is read when `scope` is absent |
| No scope in a user token | Txn-Tokens §13.14 | Denied (`token.no_scope`); the default scope applies only to a workload without a user token |
| Several issuers | | Each needs a `subject_prefix`, so `sub` and `client_id` cannot collide |
| `typ` | RFC 9068 `at+jwt` | Not checked |
