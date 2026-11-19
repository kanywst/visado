# Design (draft)

Status: unreleased, after v0.2.0. Steps 1 to 6 are implemented: caller authentication by WIT with WPT or HTTP signatures, mTLS, JWT-SVID and OAuth access tokens (no DPoP yet); AAT, asor-03 and RFC 8693 `act` chains (decoders and per-format checks; no separate invariant engine or authority algebra); audit events and OpenTelemetry spans. DPoP for access tokens and the chain view are not. Items marked Open need a decision before the code that depends on them.

## Request pipeline

One ext_authz `Check` call runs these steps in order and stops at the first failure.

```text
inbound request (via Envoy / Istio / agentgateway ext_authz)
  1. sanitize      strip Txn-Token, X-Forwarded-*, and WIMSE headers unless the previous hop is allow-listed over mTLS
  2. authenticate  CredentialVerifier plugins -> CallerIdentity (workload id, key binding, assurance)
  3. chain         ChainDecoder plugins -> NormalizedChain -> invariant engine -> authority algebra
  4. authorize     AuthZEN 1.0 evaluation request -> decision (fail closed)
  5. mint          Txn-Token (typ txntoken+jwt) -> ok_response header, Authorization removed
  6. record        audit record + OpenTelemetry span + reason code
```

### 1. Sanitize

- Deny requests for authorities outside `allowed_authorities`, and paths with dot segments, encoded dots or slashes, or empty segments.
- An inbound `Txn-Token` is accepted only from a workload listed in `internal_callers` that proved possession of a key for the request (WIT with WPT or HTTP signature, or mTLS). It is verified and forwarded unchanged. From anyone else it is denied (`txn.untrusted_hop`).
- Never forward the inbound access token downstream (MCP security best practices, Txn-Token draft §13).

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
- WPT `jti` and HTTP signature `nonce` replay are checked against a bounded cache.

Method selection, the Envoy settings each method needs, and their limits are in [bindings.md](bindings.md).

### 3. Delegation chain

Three layers, so a new draft is a new plugin:

1. `ChainDecoder` per format parses, canonicalizes, checks signatures and links (`par_hash`, `sd_hash`, receipts, or nesting only), and produces a `NormalizedChain`.
2. A format-neutral invariant engine checks:
   - the principal never changes
   - `exp` is monotone
   - depth limits hold (`DepthSemantics::{AsorStrict, AatHolderCap}`)
   - audiences only narrow
   - no actor repeats
   - status and proof of possession hold
   - the action is allowed
3. An `AuthorityAlgebra` per RAR detail type implements `subsumes(parent, child)` and `permits(leaf, action)`. Unknown types are denied.

```rust
struct NormalizedChain { profile: Profile, principal: Principal, root: TrustRef, hops: Vec<Hop>, holder_proof: bool }
struct Hop {
    depth: u32, max_depth: Option<u32>, actor: ActorId, delegator: Option<ActorId>,
    signer: KeyThumbprint, signer_binding: SignerBinding, // RootAnchor | ParentCnf | AuthServer | Unverified
    link: Link,                                           // ParHash | SdHash | Receipt | NestedOnly
    authority: Authority, validity: Validity, cnf: Option<Cnf>, status: Option<StatusRef>,
    assurance: Assurance,                                 // Verified | Declared
}
```

Only `Verified` hops are used for authorization, and only when `holder_proof` is true: the presenter proved possession of the leaf key for this request. `ChainDecoder::decode` checks the chain only and sets it to false. `Declared` hops, such as prior actors in a nested RFC 8693 `act` claim, go to the audit record and Txn-Token context only.

Order of formats:

1. AAT (draft-niyikiza-oauth-attenuating-agent-tokens-02): 229 published vectors, and each hop is signed by the parent's `cnf` key.
2. asor (draft-asor-wimse-agent-delegation-chain-03): 36 published vectors; every hop is signed by a trust anchor, and the leaf key is proven with DPoP.
3. RFC 8693 `act` adapter: the actors of a verified access token's `act` claim, signed by its issuer. The current actor is `Verified` once it is bound to the authenticated caller; prior actors stay `Declared` and never reach the PDP, as RFC 8693 §4.1 requires. Its actors have no key; the gate accepts the chain only from a caller that proved possession of a key for the request, so `holder_proof` is true there.
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

### 5. Mint the Transaction Token

Per draft-ietf-oauth-transaction-tokens-11:

- Header `typ: txntoken+jwt`, signed with the trust domain's key. JWKS is published at `/.well-known/jwks.json`.
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

## Deployment modes

1. ext_authz server (v0): `tonic` + `envoy-types` gRPC. One server covers Envoy, Istio (`CUSTOM` action) and agentgateway, which vendors the same proto.
2. Token endpoint and UI (v0): `axum` for the RFC 8693 endpoint, JWKS, health, `/api/requests/{id}/chain` with SSE, and an embedded single-page chain view.
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
ui/             chain view (React Flow), embedded at build time
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
- `del_max_depth` semantics differ between AAT and asor. Proposal: per-profile setting, reported in the audit record.
- The Txn-Token draft does not define a representation of the call chain across replacement. Proposal: carry the chain digest in `tctx` and note it as a divergence.
- Key storage beyond files (KMS/HSM) and per-trust-domain key separation.
- Name of the WIT `subject_token_type` URN to propose.
