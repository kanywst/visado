# Design (draft)

Status: v0.3.0. Steps 1 to 6 are implemented: caller authentication by WIT with WPT or HTTP signatures, mTLS, JWT-SVID and OAuth access tokens, bearer or DPoP-bound; AAT, asor-03 and RFC 8693 `act` chains (decoders and per-format checks, then the format-neutral invariant engine and an authority algebra per detail type); audit events, OpenTelemetry spans and the chain view. Items marked Open need a decision before the code that depends on them.

## Request pipeline

One ext_authz `Check` call runs these steps in order and stops at the first failure.

```text
inbound request (via Envoy / Istio / agentgateway ext_authz)
  1. sanitize      check the target; accept Txn-Token only from an allow-listed hop; ignore and strip forwarding headers
  2. authenticate  CredentialVerifier plugins -> CallerIdentity (workload id, key binding, assurance)
  3. chain         ChainDecoder plugins -> NormalizedChain -> invariant engine -> authority algebra
  4. authorize     AuthZEN 1.0 evaluation request -> decision (fail closed)
  5. mint          Txn-Token (typ txntoken+jwt) -> ok_response header, Authorization removed
  6. record        audit record + OpenTelemetry span + reason code
```

### 1. Sanitize

- Deny requests for authorities outside `allowed_authorities`, and request targets an upstream could read differently from the path the PDP sees (`request.unnormalized_path`, listed in `docs/bindings.md`).
- An inbound `Txn-Token` is accepted only from a workload listed in `internal_callers` that proved possession of a key for the request (WIT with WPT or HTTP signature, or mTLS). It is verified and forwarded unchanged. From anyone else it is denied (`txn.untrusted_hop`).
- Never forward the inbound access token downstream (MCP security best practices, Txn-Token draft §13).
- Never read `Forwarded` or `X-Forwarded-*` for a decision. On an allow, remove the ones a client can set to name another host, port, prefix or path (`Forwarded`, `X-Forwarded-Host`, `-Port`, `-Prefix`, `-Uri`, and `X-Original-URL`, `X-Rewrite-URL`), whatever the previous hop. `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Client-Cert` stay with the proxy, which sets or sanitizes them (Envoy `use_remote_address`, `forward_client_cert_details`).

### 2. Authenticate

`CredentialVerifier` implementations, chosen by what the request carries:

| Verifier | Input | Built on |
| --- | --- | --- |
| `wit-wpt` | `Workload-Identity-Token` + `Authorization: WPT` | `wimsey-wit`, `wimsey-wpt` |
| `wit-httpsig` | WIT + RFC 9421 signature | `wimsey-httpsig` (needs `with_request_body` for digests) |
| `mtls` | peer certificate from `CheckRequest.attributes.source` | `wimsey-mtls`, SPIFFE X.509-SVID, one CA per trust domain |
| `jwt-svid` | bearer JWT-SVID | `jsonwebtoken`, SPIFFE bundle file per trust domain |
| `oauth-at` | bearer or DPoP-bound access token | `jsonwebtoken` (RS256 needed for Dex and Keycloak), configured JWKS |

Trust rules:

- Trust anchors and JWKS locations are configured per trust domain. Keys are never fetched from URLs found inside a token.
- Audience is an exact string match.
- Clock leeway is configurable with a 60 s ceiling.
- WPT `jti`, HTTP signature `nonce` and DPoP `jti` replay are checked against a bounded cache.
- DPoP proofs can be required to carry a server-provided nonce (RFC 9449 §9). Nonces are stateless (an issue time under an HMAC), so replicas that share the key accept each other's.

Method selection, the Envoy settings each method needs, and their limits are in [bindings.md](bindings.md).

### 3. Delegation chain

Three layers, so a new draft is a new plugin:

1. `ChainDecoder` per format parses, canonicalizes, checks signatures and links (`par_hash`, `sd_hash`, receipts, or nesting only), and produces a `NormalizedChain`. The format's request checks (proof of possession, status, audience, action) follow in the same crate.
2. A format-neutral invariant engine (`visado_chain::invariants::Engine`) then checks the normalized chain again, whatever the format. The per-format checks stay; the engine must agree with them, and the gate runs it on every chain after them. In order, each with its deny code:
   - shape: one to 32 hops, depths `0..n` in order (`chain.malformed`)
   - links: the first hop is the root, signed by the trust anchor; every later hop names its parent's actor as delegator and is signed by the key its binding names, the parent's `cnf` or the anchor; a nested hop shares its parent's token (`chain.link_mismatch`)
   - the principal never changes (`chain.principal_altered`)
   - `exp` is monotone: no hop outlives its parent (`chain.exp_extended`)
   - depth limits hold, read per profile (`DepthSemantics::{AsorStrict, AatHolderCap, Uncapped}`, see below; `chain.depth_exceeded`)
   - audiences only narrow: a hop's audience is a non-empty subset of the restriction in force, and a hop without one inherits it (`chain.audience_widened`)
   - no delegation token repeats (`chain.token_repeated`). A holder may repeat: AAT-02 §6.2 lets a holder derive a token for itself, and the AAT vectors cycle keys
   - verified hops end the chain and the leaf is verified (`chain.unverified`)
   - every verified hop's authority type has an algebra (`chain.unknown_authority`), and each verified hop's authority is subsumed by its verified parent's (`chain.scope_escalation`)
   - status holds: no status reference is left unchecked (`chain.status_unchecked`)
   - proof of possession holds: `holder_proof` is true (`chain.no_holder_proof`)
   - the action is allowed: the leaf's authority permits it (`chain.action_denied`)
3. An `AuthorityAlgebra` per RAR detail type implements `subsumes(parent, child)` and `permits(leaf, action)`; an `Algebras` registry maps a type to its algebra, and unknown types are denied. Each format crate implements its own type, from the same rules its decoder applies: `attenuating_agent_token` (AAT §8 step 4p and step 6b), `agent_delegation` (asor §4.3 rules 1 to 3 and step 8, without running totals) and `rfc8693-act` (only the empty authority, which subsumes only itself and permits a request only when no action is asked of the chain, since RFC 8693 gives an actor no authority; the gate asks none of an `act` chain).

`del_max_depth` means different things in the two drafts, so the engine reads `Hop::max_depth` per profile, fixed by the profile rather than configured, and the audit record of an accepted chain names it (`depth_semantics`):

- `AsorStrict` (asor-03): only the first hop's bound limits the chain. `Hop::max_depth` is `DT_0.del_max_depth - 1` on every hop; every depth must be at most it.
- `AatHolderCap` (AAT-02): every hop carries its own cap. Each depth is at most its hop's `max_depth`, and no hop raises its parent's.
- `Uncapped` (RFC 8693 `act`): no per-hop bound; the adapter's `max_actors` and the engine's 32 hops apply.

```rust
struct NormalizedChain { profile: Profile, principal: Principal, root: TrustRef, hops: Vec<Hop>, holder_proof: bool }
struct Hop {
    depth: u32, max_depth: Option<u32>, actor: ActorId, principal: Principal, delegator: Option<ActorId>,
    signer: KeyThumbprint, signer_binding: SignerBinding, // RootAnchor | ParentCnf
    link: Link,                                           // Root | ParHash | Nested
    authority: Authority, validity: Validity, audience: Option<Vec<String>>, cnf: Option<Cnf>,
    status: Option<StatusCheck>,                          // Unchecked | Valid
    assurance: Assurance,                                 // Verified | Declared
}
```

Only `Verified` hops are used for authorization, and only when `holder_proof` is true: the presenter proved possession of the leaf key for this request. `ChainDecoder::decode` checks the chain only and sets it to false. `Declared` hops, such as prior actors in a nested RFC 8693 `act` claim, go to the audit record and Txn-Token context only.

Order of formats:

1. AAT (draft-niyikiza-oauth-attenuating-agent-tokens-02): 229 published vectors, and each hop is signed by the parent's `cnf` key.
2. asor (draft-asor-wimse-agent-delegation-chain-03): 36 published vectors; every hop is signed by a trust anchor, the leaf key is proven with DPoP, and each `status` reference is checked against a Token Status List the gate holds.
3. RFC 8693 `act` adapter: the actors of a verified access token's `act` claim, signed by its issuer. The current actor is `Verified` once it is bound to the authenticated caller; prior actors stay `Declared` and never reach the PDP, as RFC 8693 §4.1 requires. Its actors have no key; the gate reads the chain only from a user token bound to a WIT caller, which proved possession of its WIT key for the request, so `holder_proof` is true there.
4. Delegate SD-JWT once it has vectors.

### 4. Authorize

AuthZEN 1.0 `POST /access/v1/evaluation`, PDP endpoint discovered from `/.well-known/authzen-configuration` or configured.

Open: the agent-and-principal profile. AuthZEN does not say how to carry an agent acting for a user. Proposal:

- `subject` is the leaf agent (`type: agent`, `id`: workload identifier).
- `context.principal` is the original subject.
- `context.chain` carries the hop list and a chain digest.
- `context.assurance` records which hops were verified.

To be proposed to the AuthZEN WG once it works end to end.

- `X-Request-ID` is set to the `txn` value and checked in the echo.
- Timeouts, transport errors, non-200 responses or a non-boolean `decision` all deny.
- The PDP endpoint must be `https` or a loopback `http` address: whoever answers it decides the request. `[pdp] allow_insecure_http = true` allows plain `http` to another host, for a network nothing else can reach, and logs a warning at startup. `bearer_env` always needs `https` or loopback. The endpoint, the OTLP endpoint and the status list URIs must not carry `user:password@`; the startup log names the PDP by `scheme://host:port` only.
- `[pdp] context_in_subject` also copies the `context` members into `subject.properties`, for PDPs that do not pass `context` to the policy (Cerbos).

### 5. Mint the Transaction Token

Per draft-ietf-oauth-transaction-tokens-11:

- Header `typ: txntoken+jwt`, signed with the trust domain's key: `Ed25519` or `ES256`, or `RS256` when `[signing_key]` names an RSA private JWK of at least 2048 bits (for recipients that verify RS256 only, such as kontxt). JWKS is published at `/.well-known/jwks.json`.
- Claims:
  - `aud`: trust domain
  - `txn`: UUID, also the correlation id everywhere
  - `sub`: principal
  - `scope`: never wider than the authorized scope
  - `req_wl`: caller workload id
  - `iat`, `exp`: short, default 60 s
  - `tctx`: chain digest, leaf actor, verified depth
  - `rctx`: request metadata
- Injected with `ok_response.headers` (`Txn-Token`, overwrite), with `Authorization` in `headers_to_remove`. The txn id and chain digest also go into `dynamic_metadata` for later filters and access logs.
- A token endpoint (RFC 8693 profile) serves services that want a Txn-Token without the gateway, and handles replacement: `txn`, `sub` and `aud` stay the same, scope never widens, and expired tokens are refused.
- Open: there is no `subject_token_type` URN for a WIT. Use a private URN and propose one to the WIMSE and OAuth WGs.

### 6. Record

- Audit record with the AIMS §11 minimum:
  - agent id
  - delegating subject
  - resource or tool
  - action and decision
  - timestamp and correlation id (`txn`)
  - posture or risk input
  - remediation and its cause
- Records are hash-chained and never contain whole tokens.
- OpenTelemetry: one `visado.authorize {target}` span with these attributes, plus one `visado.hop` span event per hop:
  - `visado.chain.subjects`
  - `visado.chain.depth`
  - `visado.decision`
  - `visado.deny.hop`
  - `visado.txn`
- GenAI and MCP semantic-convention attributes are added where they apply.
- Deny reasons are stable, language-neutral codes shared with the conformance vectors, for example:
  - `credential.audience_mismatch`
  - `wpt.replay`
  - `chain.link_mismatch`
  - `chain.scope_escalation`
  - `pdp.unavailable`

### Chain view

Off by default. With `[chain_view] enabled = true` the gate keeps a summary of each recent decision in a bounded in-memory ring buffer (`capacity`, default 256, at most 10000; 0 keeps none; the oldest entry is dropped first, and everything is lost on restart). Denials of unauthenticated requests are recorded too, so anyone who can reach the proxy can push real entries out: the view is a debugging aid, not an audit trail, which is the `visado::audit` log. The HTTP listener serves:

| Route | Returns |
| --- | --- |
| `GET /api/requests?limit=N` | `{"capacity": n, "requests": [...]}`, newest first; `limit` defaults to 100 and is capped by the capacity |
| `GET /api/requests/{id}` | one summary, or 404 `{"error": "not_found"}` |
| `GET /chain` | a single page (plain HTML, CSS and JS in `crates/server/ui/`, embedded with `include_str!`; no build step, no CDN) that polls the list every 2 s and draws principal → hops → caller → PDP → decision, with verified hops solid, declared hops dashed and the deny reason on the decision |

A summary holds:

- `id`: the check's own identifier (the `txn` the gate would mint with), unique per check
- `txn`: the transaction, which a forwarded Transaction Token keeps across hops
- `time`, `method`, `resource` (`scheme://authority/path`, no query)
- `caller`, `auth_method`, `principal`, each once known
- `decision`, `status`, `code`
- `pdp`: `{"result": "allow" | "deny"}` or `{"result": "error", "code": ...}`, or `null` when the PDP was not asked
- `chain`: `profile`, `issuer`, `principal`, `holder_proof`, and per hop `depth`, `actor_kind` (`key`, `name` or `subject`), `actor`, `actor_issuer`, `assurance` (`verified` or `declared`), `link` (`root`, `par_hash` or `nested`) and the holder key thumbprint; only for a chain that verified

It never holds a token, proof, signature, digest, header value, body or the hop's authority. The request path is shown as received, without the query: an upstream that puts a secret in the path (`/hooks/<secret>`) exposes it here, as it does in access logs. Strings are cut to 256 characters and chains to 32 hops (`hops_omitted` counts the rest).

> [!WARNING]
> The chain view shows caller and principal identities, the resources they called and why requests were denied, to anyone who can reach the HTTP listener. It has no authentication. The server refuses to start with it enabled on a non-loopback `http_listen` unless `allow_remote = true`; set that only when the network limits who reaches the port. Requests whose `Host` is not in `allowed_hosts` (default `localhost`, `127.0.0.1`, `[::1]`) get 421, so a page that rebinds its DNS name to the loopback address cannot read the view through a visitor's browser.

## Deployment modes

1. ext_authz server (v0): `tonic` + `envoy-types` gRPC. One server covers Envoy, Istio (`CUSTOM` action) and agentgateway, which vendors the same proto. The port listens on loopback unless `[grpc_tls]` requires the proxy's client certificate or `grpc_reachable_only_by_proxy` is set ([bindings.md](bindings.md#choosing-the-method)).
2. Token endpoint and UI (v0): `axum` for the RFC 8693 endpoint, JWKS, health, and the chain view (`/api/requests`, `/chain`; see [Chain view](#chain-view)). The token endpoint is not built yet.
3. agentgateway ExtMcp (later): tool-aware AuthZEN requests at the MCP method layer.
4. Standalone PEP (later, only if asked): `hyper` 1.x + `tower` + `rustls`. Not `pingora`, which brings its own lifecycle and OpenSSL by default.

## Workspace layout

```text
crates/
  txn-token     mint, verify, replace (published on its own)
  chain         ChainDecoder trait, NormalizedChain, invariants, algebra
  chain-aat     AAT decoder
  chain-asor    asor decoder
  chain-act     RFC 8693 act adapter
  authzen       AuthZEN 1.0 client and the agent profile
  credentials   CredentialVerifier trait and verifiers (wraps wimsey)
  extauthz      Envoy ext_authz server
  server        binary: config, token endpoint, JWKS, UI, telemetry
  conformance   vectors, generator and runner (format as in wimsey)
deploy/aims-lab compose file for the end-to-end lab and the attack demos
crates/server/ui/  chain view (plain HTML, CSS and JS), embedded with include_str!
```

## Reference lab (aims-lab)

```text
user --login--> Dex (ID-JAG issuance, master build)
agent A --ID-JAG--> Keycloak 26.7+ (Resource AS, experimental feature) --> access token
agent A (SPIRE WIT-SVID) --WIT+WPT, delegation token--> [Envoy + visado] --Txn-Token--> agent B
agent B --> [Envoy + visado] --> MCP server
visado --AuthZEN--> OPA with the AuthZEN plugin
```

Known setup constraints, from reading the code (not yet run):

- the Dex client id must equal the Keycloak clientId
- the ID-JAG audience must be the Keycloak realm issuer
- Keycloak users must be pre-linked by Dex's opaque `sub`

The lab also hosts the attack demos in [research/05-threats.md](research/05-threats.md):

- agent-to-agent escalation
- token passthrough and replay
- chain splicing across tenants
- one malicious-server case that visado does not stop

## Open questions

- Which ID-JAG revision to accept: the MCP extension cites -04 and the latest is -06. Proposal: accept both and record which one passed.
- The Txn-Token draft does not define a representation of the call chain across replacement. Proposal: carry the chain digest in `tctx` and note it as a divergence.
- Key storage beyond files (KMS/HSM) and per-trust-domain key separation.
- Name of the WIT `subject_token_type` URN to propose.
