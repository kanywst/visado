# Spec map

Pinned revisions and where the code departs from them. Checked 2026-11-18.

## Pinned revisions

| Spec | Revision | Crate | Status |
| --- | --- | --- | --- |
| [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/) | -11 | `visado-txn-token` | Mint, verify, replace, request parsing |
| [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/01/) | -01 | (design) | Reference composition, not yet implemented |
| [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/) | -06 | (planned) | |
| [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/) | -02 | `visado-chain-aat` | §8 chain and PoP verification; 229/229 published vectors. Enforced by the gate (`docs/bindings.md`) |
| [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) | -03 | (planned) | |
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
| HTTP signature audience | `wimse-aud` against the recipient's configured audiences | Compared with the request's scheme, authority and path, like WPT `aud`; the authority is constrained by `allowed_authorities` |
| HTTP signature window | Tight `expires` (minutes) | `expires` minus `created` and the age of `created` at most `max_signature_lifetime` (default 60 s, at most 300) |
| HTTP signature nonce | Replay defense is the recipient's | Recorded per workload until `expires` in the WPT replay cache; at most 256 bytes |
| HTTP signature body | `Content-Digest` covered when present | The digest is recomputed over the body Envoy sends (`with_request_body`); `sha-256` only; a missing body counts as empty and a partial body is denied |
| HTTP signature failures | 400, one problem type, no detail | `httpsig.invalid`, 400, `application/problem+json`; the detail goes to the audit record only |
| User token with an HTTP signature | Not defined | Read from `x-user-token` (configurable) and used only when the signature covers it; `Authorization` next to a signature is denied |
| mTLS certificate source | The TLS peer | Envoy's `source.certificate`; Envoy must terminate TLS and be the only client of the gRPC port |
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
| Sender-constrained tokens (`cnf`) | RFC 9449, RFC 8705 | Rejected until DPoP and mTLS binding are implemented |
| `scope` vs `scp` | RFC 9068 uses `scope` | `scp` (string or array) is read when `scope` is absent |
| No scope in a user token | Txn-Tokens §13.14 | Denied (`token.no_scope`); the default scope applies only to a workload without a user token |
| Several issuers | | Each needs a `subject_prefix`, so `sub` and `client_id` cannot collide |
| `typ` | RFC 9068 `at+jwt` | Not checked |
