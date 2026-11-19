# Bindings

How visado reads credentials and delegation chains from a request. The AAT draft leaves bindings to separate specifications (§1), and the asor draft defines DPoP for the proof but no header for the chain, so the chain headers below are visado's own until bindings are published.

## WIMSE

| Item | Carried in |
| --- | --- |
| Workload Identity Token | `Workload-Identity-Token` header |
| Workload Proof Token | `Authorization: WPT <token>` |
| User access token next to a WPT | `X-User-Token` (configurable), bound through the WPT `oth` claim |
| Transaction Token from an earlier hop | `Txn-Token`, bound through the WPT `tth` claim |

## OAuth

`Authorization: Bearer <access token>` when the caller has no WIT.

## AAT

| Item | Carried in |
| --- | --- |
| Chain | `AAT-Chain` header: the tokens in compact serialization, root first, separated by `,` |
| Proof of possession | `AAT-PoP` header |
| Tool and arguments, MCP | The JSON-RPC body of a `tools/call` request: `params.name` is the tool, `params.arguments` the arguments, read as the exact JSON text received |
| GET, HEAD, DELETE or OPTIONS with no body and no query string | Tool `<METHOD> <path>`, arguments `{}` |

Rules:

- A comma cannot appear in a compact JWS, so a proxy that joins repeated headers with commas does not change the meaning of `AAT-Chain`.
- Only a caller with a WIT may present a chain, and the leaf token's `cnf` key must be the WIT's `cnf` key. The workload that proves possession of the WIT is then the holder the chain was delegated to. A bearer-only caller is denied.
- Anything else is denied rather than guessed: a JSON-RPC batch, any other JSON-RPC method, a body that is not JSON or not UTF-8, a malformed `tools/call`, a query string, or a missing body on POST, PUT or PATCH.
- `[aat]` must set `required` explicitly. With `required = false` a request without `AAT-Chain` skips every chain check, and the server logs a warning at startup; with `required = true` such a request is denied.
- What a verified chain does: the gate denies the call unless the chain permits this tool with these arguments. It does not narrow the minted Transaction Token's `scope`, which comes from the user token or `default_scope`, because AAT tool grants and OAuth scopes are different vocabularies. The chain goes to the PDP as `context.chain` and into the token: as `tctx.chain` when the gate mints a new token, or, when the caller forwards a Transaction Token, as a new member `tctx.chain:<caller>` in a replacement token (scope, `txn`, `sub` and `aud` unchanged, lifetime not extended). A downstream service that needs the delegated limits must read these members. Within one transaction a caller can record one chain: forwarding the same transaction again with a different chain is denied, since `tctx` members never change.
- By default the chain must name this enforcement point in `aud` and the proof must carry `aat_aud`.
- Reading MCP arguments needs the request body. In Envoy, set `with_request_body` on the ext_authz filter.

## asor

| Item | Carried in |
| --- | --- |
| Chain | `Agent-Delegation-Chain` header: the Delegation Tokens in compact serialization, root first, separated by `,` |
| Proof of possession | `DPoP` header (RFC 9449): a proof by the leaf `cnf.jkt` key over the request method and URI, with `ath` over the leaf token |
| Action | The JSON-RPC body of a `tools/call` request, read as for AAT: `params.name` is the action's scope, `params.arguments` its parameters |

Rules:

- The chain format is chosen by the header, not by the token `typ`: asor tokens are plain RFC 9068 access tokens (`at+jwt`), so `typ` cannot tell them from other access tokens. A request that carries both `AAT-Chain` and `Agent-Delegation-Chain` is denied (`chain.ambiguous`).
- As for AAT, only a WIT caller may present a chain, and the leaf `cnf.jkt` must be the thumbprint of the WIT's `cnf` key, so the DPoP proof is made with the WIT key. A bearer-only caller is denied (`chain.unbound_caller`), a missing `DPoP` header is a 401 (`chain.missing_pop`), and a leaf held by another key is `chain.holder_mismatch`.
- The DPoP `htu` is compared with `scheme://authority/path` of the request, both without query or fragment. `ath` is required, since a Delegation Token is an access token (RFC 9449 §4.2). `iat` must be within 60 seconds of now, and a proof `jti` is accepted once per process.
- The tool name is the action's scope and is matched with the draft's covering relation (§4.1), so a tool name is usually an opaque scope matched exactly, or a dotted literal such as `crm.read` that a wildcard can cover. A per-action constraint reads the argument named by its `key`; an absent argument is not bounded by it. A body-less GET, HEAD, DELETE or OPTIONS request has the tool `<METHOD> <path>`, which is never a valid scope, so it is denied (`asor.scope_not_granted`).
- The gate holds no running totals, so a leaf with a `max_lifetime` or `max_subtree` constraint denies every call (`asor.ceiling_exceeded`), and a leaf with a constraint type visado does not implement denies every call (`asor.unknown_constraint`). Status lists are not implemented: a token with a `status` claim is denied (`asor.status_unknown`).
- `[asor]` takes `audiences`, `trust_anchors` (as for `[aat]`) and `required`, which has no default. A request without a chain is denied when `[aat]` or `[asor]` sets `required = true`; a chain of either configured format satisfies it.
- A verified chain goes to the PDP and the Transaction Token as for AAT, with the Principal (`sub`) added as `principal`.
