# visado: competitor/adjacent landscape (2026-11-18)

## TL;DR

- Nobody ships an AIMS-shaped composition (WIMSE WIT/WPT verification + agent delegation chain + Txn-Token minting + AuthZEN PEP) as one component. The pieces exist separately: zeroid (agent IdP/OBO), kontxt (Txn-Tokens behind agentgateway ext_authz), tokenetes (Txn-Tokens on K8s/SPIFFE, maintenance mode), agentgateway (JWT + CEL + an ext_authz-based AuthZEN PEP + RFC 8693).
- The closest competitor is **aramase/kontxt**: Go, Txn-Token draft-08, an Envoy ext_authz adapter, and agentgateway as data plane. That is visado's data path minus WIMSE/AIMS/AuthZEN. It is 26 stars, a single maintainer, with no push since 2026-06-12.
- **tokenetes is effectively in maintenance mode, not archived.** The main author has not committed since 2025-07. Since then the only activity is dependency/CI bumps (2026-07) by Atul Tulshibagwale, now at CrowdStrike.
- Proxy foundation: **don't build a proxy.** Use tonic plus envoy-types for ext_authz (the primary mode) and axum for the token/AuthZEN HTTP endpoints. If you later need a standalone PEP, use hyper 1.x / hyper-util, not pingora.

## Open-source teardown

| Project | Lang / License | Stars / last push | Specs claimed | Overlap vs visado |
|---|---|---|---|---|
| tokenetes/tokenetes (ex-Tratteria) | Go / Apache-2.0 | 66 / 2026-10-29 | draft-ietf-oauth-transaction-tokens | Txn-Token issuer only |
| highflame-ai/zeroid | Go / Apache-2.0 | 213 / 2026-11-18 | OAuth 2.1, RFC 8693/7523/9449/7591/9396/9068, CIBA, CIMD, ID-JAG, WIMSE/SPIFFE URIs, WIMSE proof tokens, SSF/CAE | Agent IdP and delegation; no Txn-Token, no AuthZEN PEP |
| alibaba/open-agent-auth | Java / Apache-2.0 | 92 / 2026-03-15 | draft-liu-agent-operation-authorization, draft-ietf-wimse-workload-creds, OIDC, W3C VC, OPA | WIT use; own token (AOAT) |
| Delego-Dev/delego | Python / Apache-2.0 | 25 / 2026-06-11 | own "delego wire spec" 0.3 | Intent-bound action approval; not identity |
| microsoft/agent-governance-toolkit | Python (+Rust core) / MIT | 6,576 / 2026-11-17 | Own RFC-2119 specs (AgentMesh Identity & Trust), SPIFFE/DID/mTLS, OPA/Cedar | In-process SDK governance |
| Infisical/agent-vault | Go / MIT + ee/ | 2,515 / 2026-11-15 | none (MITM credential proxy) | Credential brokering; superseded by hosted product |
| kagenti -> rossoctl/rossoctl (AuthBridge) | Python/Go / Apache-2.0 | 304 / 2026-11-14 | RFC 8693, SPIFFE, Keycloak | Sidecar JWT validation + exchange |
| agentgateway/agentgateway | Rust / Apache-2.0 | 6,285 / 2026-11-18 (v1.7.0, 2026-10-27) | JWT/OIDC, MCP auth, RFC 8693, ID-JAG/XAA, AuthZEN (example), Envoy ext_authz/ext_proc | Data plane; visado's host |
| IBM/mcp-context-forge | Python / Apache-2.0 | 4,849 / 2026-11-18 | OAuth, JWT, RFC 8693 token exchange, RBAC, plugins | MCP gateway/registry |
| stacklok/toolhive | Go / Apache-2.0 | 2,343 / 2026-11-18 | OIDC, RFC 8693/OBO, Cedar authz, embedded auth server with SPIFFE + ID-JAG | MCP runtime + authz |
| aramase/kontxt | Go / Apache-2.0 | 26 / 2026-06-12 | Txn-Tokens draft-08, RFC 8693, CEL | Closest twin |
| zalando-incubator/agentic-identity-broker | Go (+React UI) / MIT | 80 / 2026-11-18 (v0.1.147, 2026-11-17) | OAuth2 AS (proxy/local/hybrid), RFC 8693 exchange + impersonation, CIMD, DCR, PKCE, RFC 8707; CEL + OPA; Envoy ext_proc | Same gateway slot (agentgateway sidecar); consent/vault/3rd-party token focus |

### tokenetes

- **Architecture:** three parts: a TraT issuance service, a K8s controller (`tconfigd`) for config CRDs, and per-service verification sidecars (`tokenetes-agent`). A gateway exchanges the user access token for a TraT. Repo layout is `service/`, `kubernetes/`, `docs/`.
- **Hard-wired:** CNCF/Palark both state that apps "must use SPIFFE for service-to-service trust". Config flows through a K8s controller.
- **Activity:**
  - v1.0.1 shipped 2025-07-21.
  - The top contributor, kchiranjewee63 (98 commits), last committed 2025-07.
  - The 2026 commits are a Go/crypto bump and a golangci v2 migration by `tulshi` (Atul Tulshibagwale, profile: "Senior Director, Continuous Identity Strategy at CrowdStrike", Txn-Token co-author and SSF/AuthZEN co-chair).
  - tokenetes-agent: last push 2025-04, 3 stars.
- **Open issues (5):** configurable `sub` claim (#81, 2026-05), scope→`purp` (#78), a dependabot PR, and #86 opened by tulshi (2026-10).
- **CNCF health:** "Concerning (46)".
- **SGNL:** CrowdStrike announced the deal 2026-01-08 (~$740M) and closed it 2026-02-20.
- **Verdict (inference):** not abandoned on paper. It is a single-person, maintainer-of-last-resort project with no feature work since 2025. Risk of CNCF archival review.

### zeroid (Highflame)

- **What it is:** a full agent IdP with Postgres-backed OAuth AS (the Postgres part is inferred from `migrations/`).
- **Tokens:** the WIMSE URI is `sub`, with `spiffe://{domain}/{account}/{project}/{type}/{id}` identities.
- **Delegation:** RFC 8693 OBO with scope attenuation, `delegation_depth`, and cascade revocation via SSF/CAE.
- **Other features:** pluggable attestation, plus DPoP, CIMD and ID-JAG.
- **Activity:** created 2026-03, 66 open issues.
- **vs visado:** it *issues* identities; visado *verifies* and enforces. Complementary. zeroid could be an upstream issuer visado validates. Do not build an AS.

### open-agent-auth (Alibaba)

- Three-layer binding: ID Token → WIT → AOAT.
- Request-level virtual workloads with temporary keys.
- W3C VC audit, OPA/RAM/ACL policy.
- Spring/Java, public beta, quiet since 2026-03.
- Spec: an individual draft (draft-liu-...), not the WG direction.

### delego

- Deterministic intent-hash binding.
- Single-use approvals bound to an action fingerprint.
- Ed25519 hash-chained audit.
- Rides credential brokers (explicitly Agent Vault).
- Not identity. It is a possible AuthZEN PDP-side idea, not a competitor.

### Microsoft Agent Governance Toolkit

- Pip-installable in-process governance: policy (YAML/OPA/Cedar via the "Agent Control Specification", Rust core), identity "SPIFFE/DID/mTLS" (e.g. `did:mesh:agent-1`), trust scoring, audit, an MCP security gateway.
- Five language SDKs, high stars.
- Own specs, no IETF Txn-Token/AuthZEN (code search: 0 AuthZEN hits).
- vs visado: SDK-in-the-agent vs network PEP. Different layer.

### Infisical agent-vault

- MITM HTTP credential proxy: agents never hold secrets.
- The README now says the OSS repo is "no longer recommended", in favor of hosted Infisical Agent Vault.
- License: MIT core + `ee/`.
- Orthogonal: secret injection, not identity verification.

### Kagenti → now "rossoctl" (IBM-led)

- `kagenti/kagenti` redirects to `rossoctl/rossoctl`.
- AuthBridge sidecar setup: an operator injects Envoy + a Go processor + spiffe-helper + Keycloak client registration.
- Inbound plugin `jwt-validation`, outbound plugin `token-exchange` (RFC 8693, audience-scoped).
- Maintainers are IBM Research. "Road to CNCF" is listed in the leads' responsibilities.
- vs visado:
  - Keycloak-centric exchange, no Txn-Token/WIMSE WIT verification.
  - Potential consumer of visado as its ext_authz.
  - Watch for CNCF positioning collision.

### agentgateway (Linux Foundation, Solo.io-originated)

- **Security policies:** JWT, basic, API key, OIDC browser auth, HTTP and network CEL authorization, MCP authentication (OAuth 2.0/JWT), MCP authorization (CEL over `mcp.tool.name` etc.), backend auth, CSRF, CORS, external authorization.
- **Code:** `http/{jwt,ext_authz,ext_proc,authorization,oauth}.rs`, `auth/oauth/cross_app_access.rs` (ID-JAG).
- **Extension points:**
  1. Envoy-compatible `extAuthz`, gRPC or HTTP. It supports `includeRequestHeaders`, a body, CEL `metadata`, `includeResponseHeaders`, conditional per-`mcp.tool`.
  2. `extProc`.
  3. **`ExtMcp`**, a new gRPC service "modeled on Envoy ext_authz, but at the MCP method layer". `CheckRequest` gets method, params, headers and CEL metadata. It returns pass/mutated/error plus a `HeaderMutation` and a KV bag exposed as `extMcp.<key>` to CEL.
  4. `CredentialProvider.FetchSecret(uri, actor_spiffe_id)`.
- **AuthZEN:** `examples/mcp-authzen` already makes agentgateway an AuthZEN PEP (ext_authz HTTP mode with a CEL-built AuthZEN body, Keycloak as PDP) and does RFC 8693 `oauthTokenExchange` for backend auth.
- **No WIMSE, no Txn-Token** (code search 0 hits).

### IBM mcp-context-forge

- Python MCP/A2A/REST gateway and registry.
- Auth: basic, JWT (symmetric `JWT_SECRET_KEY` by default), OAuth with token-exchange service and cache, RBAC, plugin framework.
- No AuthZEN. SPIFFE appears only in plugin docs.

### stacklok toolhive

- MCP server runtime with per-request authn/authz.
- `pkg/auth` has `obo`, `upstreamswap`, `tokensource`, `awssts`, `dcr`.
- `pkg/authz` uses Cedar (plus an HTTP authorizer).
- `pkg/authserver` is an embedded AS with SPIFFE bundle sources, ID-JAG, authorization_details and delegated-agent flows.
- It is drifting toward the agent-IdP space.

### kontxt (Anish Ramasekar, `aramase`)

- **Components:** TTS (RFC 8693 → `txntoken+jwt`, `tctx`/`rctx`, CEL issuance rules), an ext_authz adapter with generation and verification modes, a controller, and a Go SDK.
- **CRDs:** `TxTokenConfig`, `TransactionType`, `ServiceTokenRequirement`, `TokenPolicy`.
- **Integrations:** agentgateway standalone or the `istio-agentgateway` GatewayClass.
- **Inference:** the author is a K8s SIG-Auth maintainer at Microsoft. I did not verify the affiliation via his GitHub profile.
- **Hard-wired:** `req_wl` = K8s SA, K8s-only.

### zalando-incubator/agentic-identity-broker (high priority)

- **Basics:**
  - Go + React consent SPA, MIT, 80 stars.
  - Created 2026-07-09, pushed 2026-11-18, release v0.1.147 (2026-11-17). Very fast cadence: 94 open issues, ADRs up to 047, spec-kit `specs/`.
- **Governance:** MAINTAINERS lists only two core maintainers, both @zalando.de (Magnus Jungsbluth, Jan Brennenstuhl). They hold 207 of ~280 commits. Effectively Zalando-only, in the zalando-incubator org.
- **What it is:**
  - Consent-driven OAuth2 broker plus a token vault for third-party SaaS tokens (Google, GitHub, Databricks, Linear).
  - Tokens are envelope-encrypted with AWS KMS + DynamoDB; app data lives in Postgres.
  - User auth is delegated to a trusted reverse proxy (principal header/JWT). The broker itself does not authenticate users.
  - OAuth2 server modes: `proxy` (front an upstream AS), `local` (mint its own JWTs with managed asymmetric keys + JWKS), `hybrid`.
  - CIMD inbound and outbound (`private_key_jwt`), DCR, PKCE.
- **Delegation chain representation:**
  - Not a token chain. Delegation is a stored **Grant** (principal → agent → permission sets across services, at most one active grant per user+agent, optional `valid_until`) plus a shared per-user-per-service session.
  - The subject token carries the user (`sub`) and agent (`azp`) via configurable CEL extraction.
  - Only "impersonation" (Feature 037/ADR 045) mints a broker JWT with a single-level `act.iss`/`act.sub` (privileged client such as a Slack bridge acting for a user).
  - No nested `act`, no agent→agent multi-hop.
- **Tokens minted:**
  - Local JWT access tokens (`agent_id`, `sub`, `scope`, optional `act`).
  - JWE session tokens during authorization.
  - Otherwise it returns the *third-party provider's* access token from the vault via RFC 8693.
- **Specs absent:** ARCHITECTURE.md and the docs site have zero mentions of Txn-Token, WIMSE, SPIFFE, AuthZEN or ID-JAG (grep of the full ARCHITECTURE.md, plus the docs intro and delegation pages).
- **agentgateway integration:**
  - A standalone `extproc-token-exchange` binary implements Envoy **ext_proc** (not ext_authz).
  - agentgateway does `jwtAuth` and puts the raw token + resource URI into trusted `aib.tokenexchange` metadata.
  - ExtProc calls the broker's `/oauth2/token` (RFC 8693, gateway authenticated by `client_assertion`). It replaces `Authorization: Bearer <exchanged>` and caches by (subjectToken, resourceURI) with singleflight.
  - Three fail-closed gates:
    1. Broker CEL on the exchange.
    2. Embedded OPA in ExtProc on the request/MCP body.
    3. A human tool-approval gate (long-poll synced).
  - Re-auth is an MCP 403 `insufficient_scope` + elicitation challenge.
- **Overlap with visado:**
  - Same deployment slot: a gRPC sidecar to agentgateway that validates the inbound JWT and swaps the outbound credential.
  - Both claim "delegation chains for on-behalf-of".
  - Both do per-request policy (OPA/CEL vs AuthZEN).
  - Both do MCP tool-level gating.
- **Differences:**
  - It is user-consent and SaaS-credential-vault centric (outbound to *external* OAuth providers). visado is workload-identity and intra-domain-call-chain centric.
  - Identity: it trusts bearer JWTs + a proxy header. visado verifies WIMSE WIT/WPT / SVID proof of possession.
  - Chains: its delegation is a DB grant, plus single `act` for impersonation. visado verifies a cryptographic multi-hop chain in tokens.
  - Output: it injects a third-party access token. visado mints a Txn-Token.
  - Policy: its PDP is embedded OPA/CEL. visado uses an external, standard AuthZEN PDP.
  - Protocol: ext_proc (streaming, body access) vs visado's ext_authz (single Check).
  - It is a stateful app (Postgres, KMS, DynamoDB, UI). visado should stay near-stateless.
- **Positioning (inference):** complementary. visado sits *in front* (verify agent workload + chain → AuthZEN → Txn-Token for internal hops). The broker sits *at the egress* to third-party SaaS. Don't build consent UI or a token vault. Consider an interop demo: visado-issued Txn-Token / verified chain as the broker's subject token.
- Sources: <https://github.com/zalando-incubator/agentic-identity-broker> (ARCHITECTURE.md, MAINTAINERS, README), <https://agenticidentitybroker.dev/docs/introduction> , <https://agenticidentitybroker.dev/docs/concepts/delegation-and-consent>

## Commercial

- **Aembit:** Workload IAM extended to "IAM for Agentic AI". GA April 2026. Blended Identity (agent+human), managed MCP Authorization Server (OAuth 2.1 / DCR), MCP Identity Gateway VM, secretless credential injection. CrowdStrike AIDR integration (2026-09).
- **Keycard:** launched 2025-10 with $38M (a16z, Acrew, Boldstart). Founders ex-Snyk and Auth0 (Jared Hanson). Task-scoped short-lived tokens, policy at runtime, SDKs, "federated trust fabric". Fortune Cyber 60 (2026-10).
- **Astrix:** NHI discovery-first. The Agent Control Plane is pre-approved profiles + short-lived creds. Agent Policies (allow/flag/block) launched at RSAC 2026. Posture/inventory, not a protocol PEP.
- **Defakto (ex-SPIRL):** SPIFFE/WIMSE-grounded NHI platform, Series B $30.75M (2025-10). Pieter Kasselman (Defakto) is lead author of draft-ietf-wimse-aims-01 (2026-11-02). They are the most likely commercial AIMS implementer. Position visado as the vendor-neutral OSS reference, and invite them as reviewers.

## Integration points

### Envoy ext_authz v3 (gRPC)

- **Service:** implement `envoy.service.auth.v3.Authorization/Check(CheckRequest) -> CheckResponse`.
- **Input:** `CheckRequest.attributes` (AttributeContext). Headers, path and the optional body live under `attributes.request.http`. Peer certificate/principal is in `attributes.source`. Route `context_extensions` and `metadata_context` are also present.
- **Allow and inject a Txn-Token:** `status=OK` + `ok_response`:
  - `headers`: `Txn-Token: <jwt>` via `HeaderValueOption`. The docs say `append` defaults false = overwrite. In current core v3, use `append_action: OVERWRITE_IF_EXISTS_OR_ADD`.
  - `headers_to_remove`: the inbound `Authorization` / client-supplied `Txn-Token` and WIMSE headers, so credentials aren't forwarded.
  - Also available: `response_headers_to_add`, `query_parameters_to_set/remove`.
- **Deny:** `denied_response{status, headers (e.g. WWW-Authenticate), body}`.
- **Error:** `error_response`, which honors `failure_mode_allow`.
- **Metadata:** `CheckResponse.dynamic_metadata` lands under `envoy.filters.http.ext_authz` for downstream filters and logs. Put txn id / agent chain there.
- **Ordering:** only one of denied/ok/error may be set.
- **Rust:** `envoy-types` 0.7.7 (pre-compiled protos, tonic `AuthorizationServer`, `CheckRequestExt`/`CheckResponseExt` helpers, MSRV 1.88) + `tonic` 0.14.9.
- **Envoy config:** set `with_request_body` if WPT/HTTP-sig verification needs the body digest.

### agentgateway

- Same ext_authz proto (it vendors `ext_authz.proto`), so one server covers Envoy, Istio and agentgateway.
- Add an **ExtMcp** implementation later for MCP-method-aware decisions (tool name/args into the AuthZEN `resource`/`action`).
- Its native AuthZEN example is a CEL-templated HTTP call. visado's value is doing it with verified identity + chain + Txn-Token issuance in one hop.

### Istio

- Register in `meshConfig.extensionProviders[].envoyExtAuthzGrpc{service,port}`.
- Attach with `AuthorizationPolicy action: CUSTOM, provider.name`. Only ext_authz is supported. Off-mesh authorizers need a ServiceEntry.
- kontxt shows the `istio-agentgateway` GatewayClass path.

### Rust crates (crates.io, 2026-11-18)

| Crate | Version | Updated |
|---|---|---|
| tonic | 0.14.9 | 2026-10 |
| envoy-types | 0.7.7 | 2026-09 |
| hyper | 1.12.0 | 2026-10 |
| axum | 0.8.9 | 2026-04 |
| pingora | 0.9.1 | 2026-11, 27.9k stars |
| rustls | 0.23.46 | 2026-11 |
| jsonwebtoken | 12.0.0 | 2026-11 |
| josekit | 0.10.3 | 2025-05, OpenSSL-backed, stale |
| spiffe | 0.19.0 | 2026-10, Workload API / SVIDs |

- **JOSE:** use jsonwebtoken 12 for JWS sign/verify, or a thin layer over `aws-lc-rs`/`ring`. josekit pulls OpenSSL and is stale.
- **HTTP Message Signatures (WIMSE WPT alt):** I did not survey crate maturity. Expect to implement RFC 9421 yourself.

### Proxy foundation recommendation

1. **Primary: no proxy.** visado = tonic ext_authz server + axum HTTP surface (token endpoint, AuthZEN client, JWKS, health). Rationale: Envoy, Istio and agentgateway all speak ext_authz. agentgateway already is the Rust agent data plane (6.3k stars, LF). Competing with it is a losing position.
2. **If a standalone PEP mode is needed: hyper 1.x + hyper-util + tower + rustls.**
   - Same Tokio/tower stack as tonic/axum, so ext_authz logic can be reused as a tower layer.
   - rustls is first-class.
   - Small dependency and audit surface for a security component.
3. **Avoid pingora for now.**
   - Its own server lifecycle/runtime model doesn't compose with tonic/axum.
   - rustls support is still labeled "experimental"; default builds want OpenSSL/BoringSSL (clang/perl).
   - It is built for high-throughput CDN-style proxying, which visado doesn't need.
4. axum is an app framework, not a proxy. Use it for endpoints only.

## visado's differentiation in one paragraph

visado is the only open, vendor-neutral, Rust implementation that composes the AIMS stack end to end at the enforcement point. It verifies WIMSE workload credentials (WIT + WPT / HTTP-sig proof of possession) and SPIFFE SVIDs. It validates the agent delegation chain (RFC 8693 `act` nesting / ID-JAG from any issuer such as zeroid, Keycloak or Okta). It asks an AuthZEN PDP for the decision, and mints a draft-conformant Txn-Token carrying the verified chain and context. All of this happens in one ext_authz call that drops into Envoy, Istio and agentgateway unchanged. Competitors each own one slice:

- tokenetes/kontxt: Txn-Tokens, K8s-only, no WIMSE/AuthZEN.
- zeroid/toolhive authserver: issuance.
- agentgateway: CEL policy + a templated AuthZEN example.
- AGT: in-process SDK.
- Aembit/Keycard/Defakto: closed SaaS.

visado should be the spec-tracking conformance reference (test vectors, interop with draft revisions), not another platform.

## Things to avoid overlapping

- **Not an OAuth AS / agent IdP:** no client registration, DCR, CIBA, consent (zeroid, toolhive authserver, Keycloak). Mint only Txn-Tokens.
- **Not a data plane/gateway:** no routing, MCP multiplexing, LLM proxying (agentgateway, context-forge, toolhive).
- **Not a policy engine:** be the AuthZEN PEP/client. Ship at most a trivial test PDP (Cedar/OPA/AGT ACS live elsewhere).
- **Not a credential vault/broker, consent UI, or secret injector** (Agent Vault, Zalando agentic-identity-broker, agentgateway CredentialProvider, Aembit). The Zalando broker owns user consent + third-party SaaS token vault behind agentgateway ext_proc. visado stays ext_authz + Txn-Token for internal hops.
- **Not a K8s operator/CRD suite in v1** (kontxt, tokenetes, rossoctl). Keep config file/xDS-free and portable. K8s comes later as packaging.
- **Not intent/HITL approval or prompt inspection** (delego, AGT, Astrix posture).
- **Don't fork tokenetes.** Instead offer migration notes, and possibly co-maintainership or a conformance-suite collaboration with Atul Tulshibagwale / the kontxt author.

## Confidence / gaps

- Star counts and dates are from GitHub API on 2026-11-18.
- Commercial capability claims come mostly from vendor blogs and press.
- kontxt author affiliation is inference.
- Pingora rustls status is as stated in its current README.

## Sources

- tokenetes: <https://github.com/tokenetes/tokenetes> , <https://www.cncf.io/projects/tokenetes/> , <https://palark.com/blog/cncf-sandbox-2025-jan/> , <https://github.com/cncf/sandbox/issues/115> , <https://github.com/tulshi>
- SGNL deal: <https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-acquire-sgnl-transform-identity-security-ai-era> , <https://www.cnbc.com/2026/01/08/crowdstrike-ai-cybersecurity-sgnl-acquisition.html> , <https://app.dealroom.co/news/note/crowdstrike-acquires-sgnl-for-637-1m-sec-feb-2026>
- <https://github.com/highflame-ai/zeroid>
- <https://github.com/alibaba/open-agent-auth>
- <https://github.com/Delego-Dev/delego>
- <https://github.com/microsoft/agent-governance-toolkit>
- <https://github.com/Infisical/agent-vault>
- <https://github.com/rossoctl/rossoctl> (docs/security/authbridge.md, MAINTAINERS.md)
- agentgateway: <https://github.com/agentgateway/agentgateway> (crates/protos/proto/ext_mcp.proto, credprovider.proto, examples/mcp-authzen) , <https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/> , <https://agentgateway.dev/docs/standalone/latest/documentation/mcp/mcp-authz/>
- <https://github.com/IBM/mcp-context-forge>
- <https://github.com/stacklok/toolhive>
- <https://github.com/aramase/kontxt>
- <https://github.com/zalando-incubator/agentic-identity-broker> , <https://agenticidentitybroker.dev/docs/introduction> , <https://agenticidentitybroker.dev/docs/concepts/delegation-and-consent>
- Aembit: <https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/>
- Keycard: <https://finance.yahoo.com/news/keycard-launches-solve-ai-agent-130900959.html> , <https://www.globenewswire.com/news-release/2026/10/28/3390586/0/en/keycard-named-to-the-fortune-cyber-60-one-year-after-launching-identity-and-access-for-ai-agents.html>
- Astrix: <https://www.helpnetsecurity.com/2026/03/23/astrix-security-ai-agent-security-platform-expansion/> , <https://astrix.security/learn/blog/meet-ai-agent-control-plane/>
- Defakto: <https://www.defakto.security/blog/introducing-defakto-the-future-of-non-human-identity-security/> , <https://fintech.global/2025/10/27/defakto-raises-30-75m-to-secure-non-human-identities/>
- AIMS: <https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/>
- Envoy: <https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto>
- Istio: <https://istio.io/latest/docs/tasks/security/authorization/authz-custom/>
- Rust: <https://github.com/flemosr/envoy-types> , <https://github.com/cloudflare/pingora> , <https://crates.io/crates/tonic> , <https://crates.io/crates/jsonwebtoken> , <https://crates.io/crates/spiffe>
