# Scope

visado sits at an enforcement point. For each request it verifies the caller's workload credential and the agent delegation chain behind it, asks an AuthZEN PDP for a decision, and passes the verified chain downstream as a Transaction Token. It follows the composition described in draft-ietf-wimse-aims.

## Principles

- Inputs and outputs are published formats: WIMSE credentials, SPIFFE SVIDs, OAuth access tokens, delegation tokens from IETF drafts, Transaction Tokens, AuthZEN requests, OpenTelemetry. There is no visado token format.
- Credential verifiers, chain formats, the PDP and the deployment mode are plugins.
- visado has no policy language. Decisions come from an AuthZEN 1.0 PDP.
- Any verification error, PDP error or non-boolean decision denies the request.
- The core does not depend on MCP. MCP is the main demo.

## In scope

| Area | visado |
| --- | --- |
| Caller authentication | WIT with WPT, HTTP Message Signatures or mTLS (via `wimsey`), X.509-SVID, JWT-SVID, OAuth access tokens with optional DPoP |
| Delegation chains | AAT, asor and RFC 8693 `act` decoded into one model; invariants and attenuation checked |
| Authorization | AuthZEN 1.0 evaluation for the leaf agent, the principal and the chain |
| Transaction Tokens | Mint, verify on internal hops, replace |
| Audit | AIMS audit record, OpenTelemetry spans, per-request chain view |
| Deployment | Envoy-compatible ext_authz (Envoy, Istio, agentgateway, kgateway) and a token endpoint |

## Out of scope

| Need | Use |
| --- | --- |
| Issuing workload identities | SPIRE, any WIMSE issuer |
| User login, ID-JAG issuance | Dex, Keycloak, Okta, Entra, Casdoor |
| OAuth authorization server, agent IdP | Keycloak, zeroid, ToolHive |
| Policy evaluation | Any AuthZEN 1.0 PDP |
| Routing, MCP multiplexing, LLM proxying | agentgateway, Envoy, ContextForge |
| Vaulting SaaS tokens, consent UI | Zalando Agentic Identity Broker, Infisical Agent Vault |
| Prompt inspection, human approval | Guardrail and approval tools |
| Kubernetes operator and CRDs | Not planned for v1 |

## Neighbours

| Project | Relationship |
| --- | --- |
| [wimsey](https://github.com/kanywst/wimsey) | Library dependency for WIMSE primitives; WIMSE fixes go there |
| SPIFFE/SPIRE | Issues the WIT-SVIDs and X.509-SVIDs visado verifies |
| tokenetes, kontxt | Other Transaction Token implementations; interop and shared vectors |
| agentgateway | Hosts visado through ext_authz, later ExtMcp |
| Zalando Agentic Identity Broker | Handles egress to SaaS; visado handles inbound and internal hops |
| Tenuo, attenu-guard | Delegation-chain test vectors to cross-check against |
