# Bindings

How visado reads credentials and delegation chains from a request. The AAT draft leaves bindings to separate specifications (§1), and the asor draft defines DPoP for the proof but no header for the chain, so the chain headers below are visado's own until bindings are published.

## Choosing the method

Which method a request uses is decided by the headers it carries, in this order:

1. `Workload-Identity-Token` and `Authorization: WPT`: WIT with WPT.
2. `Workload-Identity-Token` and `Signature-Input`, with no `Authorization`: WIT with an HTTP message signature. An `Authorization` header next to a signature is denied (`credential.ambiguous`).
3. `Authorization: Bearer` with no WIT: a JWT-SVID if `[jwt_svid]` is configured, `sub` is a SPIFFE ID and `iss` is not a configured OAuth issuer; otherwise an OAuth access token.
4. `Authorization: DPoP` with no WIT: a DPoP-bound OAuth access token with its `DPoP` proof.
5. None of these, `[mtls]` configured and a peer certificate in the check request: mTLS.

A credential header longer than 16 KiB is denied (`credential.too_large`) before it is decoded.

An inbound `Txn-Token` is accepted only from a workload in `internal_callers` that proved possession of a key for the request: WIT with WPT (`tth`), WIT with a signature that covers it, or mTLS. A bearer caller or an OAuth client cannot forward one (`txn.untrusted_hop`). When the request also carries a delegation chain that names its principal (asor `sub`, the `sub` of a token with an RFC 8693 `act` claim), that principal must be the forwarded token's `sub`, or the request is denied (`chain.principal_mismatch`); an AAT chain names no principal and is not compared.

## WIMSE

### WPT

| Item | Carried in |
| --- | --- |
| Workload Identity Token | `Workload-Identity-Token` header |
| Workload Proof Token | `Authorization: WPT <token>` |
| User access token next to a WPT | `X-User-Token` (configurable), bound through the WPT `oth` claim |
| Transaction Token from an earlier hop | `Txn-Token`, bound through the WPT `tth` claim |

### HTTP message signatures

draft-ietf-wimse-http-signature-08, a profile of RFC 9421.

| Item | Carried in |
| --- | --- |
| Workload Identity Token | `Workload-Identity-Token` header, which the signature must cover |
| Signature | `Signature-Input` and `Signature`; the one tagged `wimse-workload-to-workload` is used, so an intermediary may add its own |
| User access token | `X-User-Token` (configurable), which the signature must cover |
| Transaction Token from an earlier hop | `Txn-Token`, which the signature must cover |
| Body | `Content-Digest` (`sha-256` only), which the signature must cover when present |

Rules:

- The signature must cover `@method`, `@path` and `@query`, and `Content-Type`, `Content-Digest`, `Authorization`, `Txn-Token` and `Workload-Identity-Token` when the request carries them. `created`, `expires`, `nonce`, `tag` and `wimse-aud` are required; `keyid` and `alg` are refused. The key is the WIT's `cnf` key.
- `wimse-aud` must equal the request's scheme, authority and path without the query, the same string a WPT's `aud` is compared with. The authority must be in `allowed_authorities`; visado refuses to start with an empty list.
- `expires` minus `created` and the age of `created` are at most `max_signature_lifetime` (default 60 s), with the usual clock leeway. The `nonce` (at most 256 bytes) is recorded until `expires` in the same bounded replay cache as WPT `jti` values.
- Covering `Content-Digest` binds only the header. visado also hashes the body it receives, so Envoy must send it: set `with_request_body` on the ext_authz filter, with `pack_as_bytes: true` so a body that is not UTF-8 arrives unchanged, and a `max_request_bytes` large enough for the bodies you sign. A body Envoy did not send is treated as empty, so a signed non-empty body is then denied. A partial body (`x-envoy-auth-partial-body: true`, from `allow_partial_message`) is denied. HTTP/2 needs no length header, so a request without exactly one `Content-Length: 0` is taken to have a body and must cover `Content-Digest`, whatever the method; a client signing a GET over HTTP/2 covers the digest of the empty body.
- Envoy sends repeated headers joined with commas in `headers`, or separately in `header_map` with `encode_raw_headers`. visado joins repeated fields with a comma and a space, as RFC 9421 does, so set `encode_raw_headers` if a covered header can repeat.
- Every failure (the WIT, the signature, its parameters, the digest, a replayed nonce) is `httpsig.invalid` with status 400 and an RFC 9457 `application/problem+json` body of type `wimse-signature-invalid`, as the draft requires the response not to say which check failed. The audit record has the detail.

### mTLS

draft-ietf-wimse-mutual-tls with a Workload Identity Certificate, which is a SPIFFE X.509-SVID.

| Item | Carried in |
| --- | --- |
| Client certificate | The TLS handshake with Envoy. Envoy passes it to visado as `CheckRequest.attributes.source.certificate` (URL-encoded PEM) when the ext_authz filter sets `include_peer_certificate: true` |

Rules:

- Envoy must terminate the client's TLS itself, request a client certificate (`require_client_certificate: true`), and validate it against the same CA. The handshake is what proves the client holds the private key; visado sees only the certificate. `source.certificate` is filled from Envoy's own connection state, not from a request header, so a client cannot forge it. If something in front of Envoy terminates TLS, the field is empty (or describes the wrong peer) and mTLS must not be configured. visado never reads `X-Forwarded-Client-Cert`.
- Only Envoy may reach visado's gRPC port: certificates are public, so a client that could call ext_authz directly could put any workload's certificate in the field. `[mtls]` is refused unless `grpc_listen` is a loopback address or `[mtls] grpc_reachable_only_by_proxy = true` records that the network enforces this.
- The certificate must be one PEM block (no chain), issued directly by the one CA configured for the trust domain in its URI SAN, with an Ed25519 or P-256 CA key, within its validity window, with exactly one URI SAN, not a CA, and, if key usage is present, allowing signatures and not certificate or CRL signing. Chain building through intermediates, name constraints and revocation are not implemented. Without `[mtls]` the certificate is ignored.
- The certificate is used only when the request carries no `Workload-Identity-Token` and no `Authorization`. A user token header is denied (`credential.unbound_user_token`): nothing ties it to the certificate.

### SPIFFE JWT-SVID

| Item | Carried in |
| --- | --- |
| JWT-SVID | `Authorization: Bearer <token>` |

Rules:

- `alg` is `RS256` or `ES256`; `typ`, if present, is `JWT` or `JOSE`; `sub` is a SPIFFE ID; `aud` is required and must contain one of `[jwt_svid] audiences`; `exp` is required and `nbf` is checked when present.
- The key comes from the JWT bundle configured for the trust domain in `sub`: a SPIFFE bundle file whose keys with `use: jwt-svid` are used, selected by `kid` (without `kid` only if the bundle has one key). Keys are never fetched.
- A JWT-SVID is a bearer token: it proves nothing about who sends it. The caller cannot present an AAT chain or forward a Transaction Token, and a user token header is denied.

## OAuth

| Item | Carried in |
| --- | --- |
| Bearer access token | `Authorization: Bearer <access token>`, when the caller has no WIT and the token is not a JWT-SVID |
| DPoP-bound access token | `Authorization: DPoP <access token>` |
| DPoP proof (RFC 9449) | `DPoP` header, exactly one |

The caller is the token's `client_id` (or `azp`), and the user is its `sub`.

Rules for DPoP:

- The token must have `cnf.jkt` and no other `cnf` member, and it must equal the RFC 7638 thumbprint of the proof's `jwk`. A token with `cnf.jkt` sent as `Bearer`, or as the user token next to a WPT or a signature, is denied (`token.dpop_bound`).
- The proof's `typ` is `dpop+jwt`, its `alg` `ES256`, `EdDSA` or `Ed25519`, and its `jwk` a public key. `htm` must be the request method and `htu` the request's `scheme://authority/path`, both without query or fragment, compared after lowercasing scheme and host and dropping a default port. `iat` must be within `dpop_iat_window` (default 60 s) of now. `ath` is required. The `jti` (at most 256 bytes) is accepted once per proof key, in the same bounded replay cache as WPT `jti` values. Server nonces are not supported.
- A failed proof is a 401 with `WWW-Authenticate: DPoP error="invalid_dpop_proof", algs="ES256 EdDSA Ed25519"` (`dpop.invalid`, or `dpop.replay`). A token not bound to the proof key, a bound token sent as `Bearer`, and any other token failure under the `DPoP` scheme send `error="invalid_token"` (`dpop.binding`, `token.dpop_bound`, or the token's own code). Other access token failures send `Bearer, DPoP algs="ES256 EdDSA Ed25519"`.
- The PDP context and the Transaction Token `tctx` name the method `oauth-dpop`; `req_wl` is `oauth-client:<client_id>`, as for a bearer token. The gate removes `Authorization` and `DPoP` before the request goes upstream.
- The proof key is the caller's key for the request, so the client may present an AAT chain whose leaf it holds. It cannot present an asor chain (`chain.proof_conflict`, 400): the asor leaf proof would need the same `DPoP` header.

## RFC 8693 act

| Item | Carried in |
| --- | --- |
| Chain | The `act` claim of the user token next to a WIT (bound through the WPT `oth` or the HTTP signature). An mTLS caller cannot send a user token, so it cannot present one |

Rules:

- The token is verified as any access token first (issuer, key, audience, lifetime). The `act` claim is then read as a chain: the principal is the token's `sub`, the current actor is the outermost `act`, and each nested `act` is a prior actor, the most deeply nested the least recent. Every `act` must be a JSON object with a non-empty string `sub` and, if present, a non-empty string `iss`; otherwise `act.not_object`, `act.missing_sub` or `act.bad_issuer`. More than `max_actors` actors (default 8) is `act.too_deep`. Other members of an `act`, such as `exp` or `aud`, are ignored, as RFC 8693 §4.1 says.
- As for AAT and asor, only a caller that proved possession of a key for the request may present a chain. A bearer token with an `act` claim is denied (`chain.unbound_caller`): nothing shows that the actor it names is the party sending it.
- The current actor must be the caller: its `sub`, as the token writes it, must equal the caller identifier (the WIT `sub`), or, when `[act.actors]` maps that `sub`, the caller it is mapped to. Otherwise `act.actor_mismatch`. The issuer's `subject_prefix` applies to the token's `sub` and `client_id`, not to `act.sub`. The actor's `iss` is recorded but not compared, since the token's issuer vouches for the whole claim. Prior actors are never compared with anything.
- RFC 8693 §4.1 says prior actors are "informational only and are not to be considered in access control decisions". The PDP therefore gets only the current actor: `context.chain` has `profile` (`rfc8693-act`), `issuer`, `principal`, `actor` (`{iss, sub}`) and `caller_kind`, the kind of caller the actor was bound to (`workload`; `client` is reserved for OAuth clients, which cannot present a chain today). The Transaction Token's `tctx.chain` (or `tctx.chain:<caller>` on a replacement) adds `prior_actors`, least recent first, and `depth`.
- RFC 8693 gives no actor an authority of its own, so visado does not narrow anything by the chain: what the token grants is its `scope`, as for any access token.
- An access token with an `act` claim next to an `AAT-Chain` or `Agent-Delegation-Chain` header is `chain.ambiguous`. Without `[act]`, a token with an `act` claim is denied (`chain.unsupported`) rather than read as the subject's own token.
- `[act]` takes `required` (no default; a token with an `act` claim satisfies it, as either other chain format does), `max_actors` (1 to 32) and the `[act.actors]` table. The `may_act` claim is not read.
- The audit detail of an `act.actor_mismatch` names the actor and the caller, never the token.

## AAT

| Item | Carried in |
| --- | --- |
| Chain | `AAT-Chain` header: the tokens in compact serialization, root first, separated by `,` |
| Proof of possession | `AAT-PoP` header |
| Tool and arguments, MCP | The JSON-RPC body of a `tools/call` request: `params.name` is the tool, `params.arguments` the arguments, read as the exact JSON text received |
| GET, HEAD, DELETE or OPTIONS with no body and no query string | Tool `<METHOD> <path>`, arguments `{}` |

Rules:

- A comma cannot appear in a compact JWS, so a proxy that joins repeated headers with commas does not change the meaning of `AAT-Chain`.
- The leaf token's `cnf` key must be the key the caller proved possession of for this request: the WIT's `cnf` key with a WPT or an HTTP signature, or the certificate's key over mTLS (Ed25519 or P-256 only). That workload is then the holder the chain was delegated to. An OAuth client with a DPoP-bound token holds its DPoP proof key. A bearer caller (a bearer access token or a JWT-SVID) has no such key and is denied (`chain.unbound_caller`).
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
- As for AAT, only a WIT caller may present a chain, and the leaf `cnf.jkt` must be the thumbprint of the WIT's `cnf` key, so the DPoP proof is made with the WIT key. A bearer-only caller is denied (`chain.unbound_caller`), an OAuth client authenticated with DPoP is denied because its `DPoP` header already proves its access token (`chain.proof_conflict`), a missing `DPoP` header is a 401 (`chain.missing_pop`), and a leaf held by another key is `chain.holder_mismatch`.
- The DPoP `htu` is compared with `scheme://authority/path` of the request, both without query or fragment and normalized as for DPoP-bound access tokens. `ath` is required, since a Delegation Token is an access token (RFC 9449 §4.2). `iat` must be within 60 seconds of now, and a proof `jti` is accepted once per process.
- The tool name is the action's scope and is matched with the draft's covering relation (§4.1), so a tool name is usually an opaque scope matched exactly, or a dotted literal such as `crm.read` that a wildcard can cover. A per-action constraint reads the argument named by its `key`; an absent argument fails the constraint (`asor.ceiling_exceeded`). A body-less GET, HEAD, DELETE or OPTIONS request has the tool `<METHOD> <path>`, which is never a valid scope, so it is denied (`asor.scope_not_granted`).
- The gate holds no running totals, so a leaf with a `max_lifetime` or `max_subtree` constraint denies every call (`asor.ceiling_exceeded`), and a leaf with a constraint type visado does not implement denies every call (`asor.unknown_constraint`). Status lists are not implemented: a token with a `status` claim is denied (`asor.status_unknown`).
- `[asor]` takes `audiences`, `trust_anchors` (as for `[aat]`) and `required`, which has no default. A request without a chain is denied when the chain formats set `required = true`; a chain of any configured format satisfies it. Every configured format among `[aat]`, `[asor]` and `[act]` must set the same value, or the server refuses to start.
- A verified chain goes to the PDP and the Transaction Token as for AAT, with the Principal (`sub`) added as `principal`.
