# Bindings

How visado reads credentials and delegation chains from a request. The AAT draft leaves bindings to separate specifications (§1), so the AAT binding below is visado's own until one is published.

## Choosing the method

Which method a request uses is decided by the headers it carries, in this order:

1. `Workload-Identity-Token` and `Authorization: WPT`: WIT with WPT.
2. `Workload-Identity-Token` and `Signature-Input`, with no `Authorization`: WIT with an HTTP message signature. An `Authorization` header next to a signature is denied (`credential.ambiguous`).
3. `Authorization: Bearer` with no WIT: a JWT-SVID if `[jwt_svid]` is configured, `sub` is a SPIFFE ID and `iss` is not a configured OAuth issuer; otherwise an OAuth access token.
4. None of these, `[mtls]` configured and a peer certificate in the check request: mTLS.

A credential header longer than 16 KiB is denied (`credential.too_large`) before it is decoded.

An inbound `Txn-Token` is accepted only from a workload in `internal_callers` that proved possession of a key for the request: WIT with WPT (`tth`), WIT with a signature that covers it, or mTLS. A bearer caller cannot forward one (`txn.untrusted_hop`).

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
- `wimse-aud` must equal the request's scheme, authority and path without the query, the same string a WPT's `aud` is compared with. Set `allowed_authorities`, so the authority in that string is one this gate protects.
- `expires` minus `created` and the age of `created` are at most `max_signature_lifetime` (default 60 s), with the usual clock leeway. The `nonce` (at most 256 bytes) is recorded until `expires` in the same bounded replay cache as WPT `jti` values.
- Covering `Content-Digest` binds only the header. visado also hashes the body it receives, so Envoy must send it: set `with_request_body` on the ext_authz filter, with `pack_as_bytes: true` so a body that is not UTF-8 arrives unchanged, and a `max_request_bytes` large enough for the bodies you sign. A body Envoy did not send is treated as empty, so a signed non-empty body is then denied. A partial body (`x-envoy-auth-partial-body: true`, from `allow_partial_message`) is denied.
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

`Authorization: Bearer <access token>` when the caller has no WIT and the token is not a JWT-SVID.

## AAT

| Item | Carried in |
| --- | --- |
| Chain | `AAT-Chain` header: the tokens in compact serialization, root first, separated by `,` |
| Proof of possession | `AAT-PoP` header |
| Tool and arguments, MCP | The JSON-RPC body of a `tools/call` request: `params.name` is the tool, `params.arguments` the arguments, read as the exact JSON text received |
| GET, HEAD, DELETE or OPTIONS with no body and no query string | Tool `<METHOD> <path>`, arguments `{}` |

Rules:

- A comma cannot appear in a compact JWS, so a proxy that joins repeated headers with commas does not change the meaning of `AAT-Chain`.
- The leaf token's `cnf` key must be the key the caller proved possession of for this request: the WIT's `cnf` key with a WPT or an HTTP signature, or the certificate's key over mTLS (Ed25519 or P-256 only). That workload is then the holder the chain was delegated to. A bearer caller (an OAuth access token or a JWT-SVID) has no such key and is denied (`chain.unbound_caller`).
- Anything else is denied rather than guessed: a JSON-RPC batch, any other JSON-RPC method, a body that is not JSON or not UTF-8, a malformed `tools/call`, a query string, or a missing body on POST, PUT or PATCH.
- `[aat]` must set `required` explicitly. With `required = false` a request without `AAT-Chain` skips every chain check, and the server logs a warning at startup; with `required = true` such a request is denied.
- What a verified chain does: the gate denies the call unless the chain permits this tool with these arguments. It does not narrow the minted Transaction Token's `scope`, which comes from the user token or `default_scope`, because AAT tool grants and OAuth scopes are different vocabularies. The chain goes to the PDP as `context.chain` and into the token: as `tctx.chain` when the gate mints a new token, or, when the caller forwards a Transaction Token, as a new member `tctx.chain:<caller>` in a replacement token (scope, `txn`, `sub` and `aud` unchanged, lifetime not extended). A downstream service that needs the delegated limits must read these members. Within one transaction a caller can record one chain: forwarding the same transaction again with a different chain is denied, since `tctx` members never change.
- By default the chain must name this enforcement point in `aud` and the proof must carry `aat_aud`.
- Reading MCP arguments needs the request body. In Envoy, set `with_request_body` on the ext_authz filter.
