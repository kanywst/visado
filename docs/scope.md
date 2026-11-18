# Scope

visado is the enforcement point that turns **any inbound workload credential plus any agent delegation chain** into **one verified, attenuated, auditable call chain per request**, and hands it downstream as an IETF Transaction Token. It aims to be the open reference implementation of the IETF WIMSE AIMS composition at that point.

Everything else is somebody else's job, and visado integrates with them instead of replacing them.

## Design rules

- **Standards in, standards out.** Inputs are WIMSE credentials, SPIFFE SVIDs, OAuth access tokens (including those obtained with an ID-JAG) and delegation tokens from published drafts. Outputs are Transaction Tokens, AuthZEN requests, OpenTelemetry spans and audit records. No visado-specific token format.
- **Pluggable on every axis.** Credential verifiers, chain decoders, the PDP and the deployment mode are interfaces. Adding a draft or a vendor is a plugin, not a fork.
- **No policy of its own.** Decisions come from an external AuthZEN 1.0 PDP. visado ships at most a trivial test PDP.
- **Fail closed.** Any verification error, PDP error or non-boolean decision denies the request.
- **Protocol-neutral core.** MCP is the flagship demo, but the core works for any HTTP or gRPC call, including A2A.

## In scope

| Area | What visado does |
| --- | --- |
| Caller authentication | Verify WIT with WPT, HTTP Message Signatures or mTLS (via `wimsey`), X.509-SVID and JWT-SVID, and OAuth access tokens with optional DPoP |
| Delegation chains | Decode AAT, asor and RFC 8693 `act` into one normalized chain, check cross-format invariants, and check that authority only narrows |
| Authorization | Build an AuthZEN 1.0 evaluation request for the leaf agent, the principal and the chain, and enforce the answer |
| Transaction Tokens | Mint Txn-Tokens (draft-ietf-oauth-transaction-tokens), verify inbound ones on internal hops, and support replacement |
| Audit and visibility | Emit the AIMS audit record, OpenTelemetry spans with the chain, and a per-request chain view |
| Deployment | Envoy-compatible ext_authz (Envoy, Istio, agentgateway, kgateway) and a token endpoint |

## Out of scope

| You want | Use instead |
| --- | --- |
| Issuing workload identities | SPIRE, Omega, any WIMSE issuer |
| End-user login, ID-JAG issuance | Dex, Keycloak, Okta, Entra, Casdoor |
| An OAuth authorization server or agent IdP (DCR, CIBA, consent) | Keycloak, zeroid, ToolHive's auth server |
| Policy evaluation | Any AuthZEN 1.0 PDP: OPA with an AuthZEN plugin, Cerbos, Cedar-based PDPs, Omega |
| L7 routing, MCP multiplexing, LLM proxying | agentgateway, Envoy, IBM ContextForge |
| Vaulting third-party SaaS tokens, consent UI | Zalando Agentic Identity Broker, Infisical Agent Vault |
| Prompt inspection, intent or human approval | Dedicated guardrail and approval tools |
| A Kubernetes operator and CRDs (in v1) | Plain configuration first; an operator only if adopters ask |

## Relationship to neighbouring projects

| Project | Relationship |
| --- | --- |
| [wimsey](https://github.com/kanywst/wimsey) | Library dependency for WIMSE primitives. WIMSE fixes land there, not here |
| SPIFFE/SPIRE | Upstream issuer of WIT-SVIDs and X.509-SVIDs |
| Transaction Token implementations (tokenetes, kontxt) | Interop targets; share conformance vectors rather than fork |
| agentgateway | Host data plane through its ext_authz (and later ExtMcp) extension |
| Zalando Agentic Identity Broker | Complementary: visado verifies inbound and internal hops; the broker handles egress to SaaS |
| Delegation-chain libraries (Tenuo, attenu-guard) | Sources of test vectors to cross-check against |
