# Spec map

Pinned revisions and where the code departs from them. Checked 2026-11-19.

## Pinned revisions

| Spec | Revision | Crate | Status |
| --- | --- | --- | --- |
| [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/) | -11 | `visado-txn-token` | Mint, verify, replace, request parsing |
| [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/01/) | -01 | (design) | Reference composition, not yet implemented |
| [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/) | -06 | (planned) | |
| [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/) | -02 | `visado-chain-aat` | §8 chain and PoP verification; 229/229 published vectors. Not yet used by ext_authz |
| [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) | -03 | (planned) | |
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
| Step order | Steps 6 and 7 may be reordered; PoP signature SHOULD come before 6b | Steps run in the draft's order, so the reported step matches the vectors |
| Argument and PoP size | Not limited | Each at most `max_token_size` |
| PoP `jti` tracking | Required for tools with side effects (§7.3) | The caller passes a `ReplayCache` for those tools. The in-memory cache refuses new proofs when full |
| Root `iss` is a URI | Required (step 3k) | A scheme, a colon, and no whitespace or control characters |
| JSON nesting | Not limited beyond MAX_CONSTRAINT_DEPTH | At most 256 levels; deeper payloads fail at signature-step parsing (3b, 4b, 7b) |
| Principal | AAT has no `sub` | `Principal::Unspecified` in the normalized chain |

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
