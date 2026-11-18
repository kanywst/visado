# Spec map

Pinned revisions and where the code departs from them. Checked 2026-11-18.

## Pinned revisions

| Spec | Revision | Crate | Status |
| --- | --- | --- | --- |
| [draft-ietf-oauth-transaction-tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/) | -11 | `visado-txn-token` | Mint, verify, replace, request parsing |
| [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/01/) | -01 | (design) | Reference composition, not yet implemented |
| [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/) | -06 | (planned) | |
| [draft-niyikiza-oauth-attenuating-agent-tokens](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/) | -02 | (planned) | |
| [draft-asor-wimse-agent-delegation-chain](https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/) | -03 | (planned) | |
| [OpenID AuthZEN Authorization API](https://openid.net/specs/authorization-api-1_0.html) | 1.0 Final | (planned) | |

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
