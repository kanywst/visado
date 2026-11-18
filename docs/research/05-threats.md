# visado threat research (as of 2026-11-18)

## TL;DR

- Many of the agent/MCP "authz" incidents are really prompt injection running as a principal with too much privilege, where the user legitimately holds that privilege. Chain verification plus Txn-Tokens plus a per-request PDP stops the **multi-hop escalation**, **passthrough / audience**, **stolen-bearer replay** and (sometimes) **cross-tenant** cases. It does **not** stop malicious server code (postmark-mcp), hosting-infra compromise (Smithery), or single-hop injection where the user already had the access (Supabase, GitHub MCP unless the txn is scoped).
- Strongest launch story: ServiceNow agent-to-agent escalation (AppOmni, Nov 2025). Agent B ran with the initiating admin's privileges after a low-privilege attacker's ticket hijacked agent A. That is exactly what hop-by-hop scope attenuation is for.
- Be explicit in the blog about what visado does **not** fix. Stating the limits is what makes the rest credible.

## 1. Incidents (2025-2026): failure in identity terms vs visado coverage

| Incident | Identity/authz failure | visado (chain + Txn-Token + PDP)? |
|---|---|---|
| **GitHub MCP** (Invariant, 2025-05-26). A malicious public issue led the agent to put private-repo data (salary, relocation plans, a private project name) into a public PR [1] | One user credential covered public and private repos in one session. No per-transaction resource scoping. "No CVE, architectural" [1] | **Partial.** Blocked only if the Txn-Token `tctx` pins the transaction to one repo and the PDP denies other repos. Invariant's own fix is "one repo per session" [1]. Chain verification alone does nothing because the delegation was legitimate. |
| **Supabase MCP** (General Analysis, Jul 2025; controlled demo, no customer breach). A support-ticket injection made Cursor SELECT `integration_tokens` and write the result into the ticket [2], [3] | The agent used `service_role`, which bypasses RLS. "No permissions were violated" [2] | **Mostly no.** visado can stop the RLS-bypass key from being used (gateway mints a Txn-Token with `sub`=developer, so downstream applies the user's policy). If the developer can read that table, the read still works. Supabase's fix was read-only mode plus project scoping [4]. |
| **Asana MCP** (found 2025-06-04, offline 06-05 to 06-17). Data could be seen by "other Asana MCP users" in other orgs [5], [6] | Tenant isolation bug inside the server. Root cause not disclosed [5]. The "~1,000 customers" figure comes from secondary sources; The Register says the count was undisclosed [5], [6]. Third-party caching theory is unverified. | **Only if** the downstream data layer checks the Txn-Token `tctx.tenant` against the resource's tenant on every request. A gateway in front cannot see bugs inside the server. |
| **postmark-mcp** (Koi, Sep 2025). v1.0.16 added a hidden BCC to an attacker address. About 1,500 weekly downloads per Koi's estimate [7], [8] | Supply chain. The server legitimately held the Postmark key and abused it inside its own code. | **No.** The abuse happened downstream of any gateway. Only egress controls or package provenance help. |
| **Tool poisoning / cross-server shadowing** (Invariant, Apr 2025). A malicious tool description redirected a trusted `send_email` or WhatsApp tool [9] | The model trusted descriptions from another server. The call was authorized as the user. | **Partial.** A PDP over tool arguments (recipient allowlist, PII egress) can block it. Delegation chains do not record where the prompt came from. |
| **ServiceNow Now Assist agent-to-agent** (AppOmni, 2025-11-19). A low-privilege user's field content hijacked agent A, which used discovery to recruit agent B. B ran "with the privilege of the user who started the interaction" (admin) to change records, assign roles and send email. ServiceNow called it intended behavior and updated its docs [10] | No attenuation across hops. No per-hop authorization of A→B. Ambient user privilege. | **Yes, if B's calls go through visado.** The A→B hop needs an explicit delegation, B's scope must be a subset of A's (read-only triage), and the PDP requires a step-up or human-direct chain for `assign_role`. Caveat: the attacker who wrote the ticket never appears in the chain. |
| **Salesloft Drift** (UNC6395, 2025-08-08 to 08-18). Stolen OAuth access and refresh tokens were used to bulk-export Salesforce data [11], [12] | Long-lived bearer tokens with no sender constraint, replayed from attacker infrastructure. A SaaS integration, not MCP. | **Only if** the resource requires workload-bound PoP (WIMSE WPT) or only accepts traffic via the gateway. Short-lived Txn-Tokens limit the replay window. Stolen refresh tokens used directly at Salesforce bypass any gateway. |
| **Smithery hosting** (GitGuardian; found 2025-06-10, published 2025-10-22). Path traversal leaked a fly.io token that controlled more than 3,000 hosted MCP servers and the keys clients had sent them [13] | A single over-powered infrastructure credential. | **No.** This is the case against visado as a central hub: its key is the same kind of single point of failure (see section 4). |
| **MCP "confused deputy"** (spec). Static client ID + DCR + consent cookie lets an attacker obtain an auth code [14] | Missing per-client consent at an OAuth proxy. | **Out of scope** unless visado acts as an OAuth proxy/AS. If it does, it has to meet section 2. |

## 2. MCP spec: exact requirements (modelcontextprotocol.io, draft; current protocol 2026-07-28, which deprecates DCR) [14], [15]

- **Token passthrough:** "MCP servers **MUST NOT** accept any tokens that were not explicitly issued for the MCP server." [14] The authorization spec says servers "**MUST** validate that access tokens were issued specifically for them as the intended audience" (RFC 8707), "**MUST** only accept tokens that are valid for use with their own resources", and "**MUST NOT** accept or transit any other tokens." Clients **MUST** send `resource` in both authorization and token requests [15].
- **Confused deputy (OAuth proxy servers):** MCP proxies **MUST** keep a per-user registry of approved `client_id`s and check it *before* the third-party flow. The consent UI **MUST** show the client name, scopes and `redirect_uri`, with CSRF protection and `frame-ancestors`/XFO. Consent cookies **MUST** use the `__Host-` prefix, Secure, HttpOnly, SameSite=Lax, be signed, and be bound to the `client_id`. `redirect_uri` is matched by exact string. `state` **MUST** be cryptographically random, stored only after consent, single-use, and short-lived (around 10 min) [14].
- **State handles:** servers "**MUST NOT** treat possession of a state handle as authentication" and **SHOULD** key state as `<user_id>:<handle>`, with user_id taken from the verified token [14].
- **Scope minimization:** start with a minimal scope set and step up through `WWW-Authenticate scope=`. Listed mistakes include wildcard scopes and "treating claimed scopes in token as sufficient without server-side authorization logic" [14]. That last point supports having a PDP.

## 3. Spec and framework threat models: what visado must honour

- **Txn-Tokens** (draft-ietf-oauth-transaction-tokens-11, 2026-07-30), section 13 [16]: lifetime "MUST be kept short" (not replay-resistant); `txn` SHOULD be unique in the trust domain (replay detection); refresh tokens MUST NOT be used to request them; the Txn-Token "MUST NOT contain the access token presented to the external endpoint"; no scope expansion relative to the subject token; unknown scope MUST be rejected, never treated as unconstrained; replacement tokens MUST NOT change `txn`/`sub`/`aud` or expand scope; a Txn-Token MUST NOT be used as an OAuth access token or as workload authentication; workloads MUST authenticate the TTS and get configuration from a trusted source.
- **WIMSE arch** (draft-ietf-wimse-arch-09, 2026-11-17), section 4 [17]: TLS protection holds only "between each adjacent pair of TLS endpoints" (middleboxes); bearer tokens leak through logs and headers; binding tokens to workload identity "reduces the impact of a stolen token"; one shared signing key across trust domains "permits forgery of credentials for all of those domains"; authentication is not authorization. Section 3.4.3: a transport identity must not be assumed to match the application-layer caller.
- **OWASP.** Agentic AI Threats & Mitigations (Feb 2025) has T1 to T15. The relevant ones are T2 Tool Misuse, T3 Privilege Compromise, T8 Repudiation, T9 Identity Spoofing, T12 Agent Communication Poisoning and T13 Rogue Agents. v1.1 (Dec 2025) extends the list to T17 [18]. The Top 10 for Agentic Applications (2025-12-09) has ASI03 Identity & Privilege Abuse, which covers un-scoped delegation, cached credentials and cross-agent confused deputy; the recommended mitigation is time-bound, least-privilege agent identity plus tool-level authorization [19]. Confidence is medium here: I read secondary summaries, not the OWASP PDF.
- **CSA MAESTRO** (2025-02-06) is a 7-layer method that emphasises threats crossing layers. visado sits at L4 (deployment), L6 (security, cross-cutting) and L7 (ecosystem) [20].
- **CoSAI "Agentic IAM"** (TSC-approved 2026-03-20): agents as first-class identities, zero standing privilege, SPIFFE SVIDs plus short-lived OAuth, "on-behalf-of token chains with scope attenuation at every hop," immutable audit [21]. This matches visado's design almost exactly; cite it.

## 4. STRIDE threat model for visado

| # | Threat | Mitigation requirement |
|---|---|---|
| S1 | Forged WIT or delegation token (rogue or untrusted issuer) | Pin trust anchors per trust domain. Reject `alg=none`/HS*. Select keys by `iss`+`kid` only from configured JWKS, never from the token's own `jku`/`x5u`. |
| S2 | WPT replay or stolen WIT | WPT must carry `jti`, short `exp` (60s or less), `aud`=visado's exact URI and a hash binding to the WIT/request. Keep a `jti` cache for the max lifetime plus skew. Reject reuse (`wpt.replay`). |
| S3 | Audience confusion | Exact string match of `aud` against the configured canonical URI (no normalization, as in the MCP `iss` rule [15]). A token for API-A presented at API-B gives `token.audience_mismatch`. |
| S4 | Header injection behind proxies | Strip any inbound `Txn-Token`, `X-Forwarded-*` and XFCC unless they come from an allow-listed hop over mTLS. Never derive identity from headers set by an untrusted hop (WIMSE 3.4.3 / 4.1). |
| T1 | Chain truncation (dropping a low-trust hop) | Each link is signed and binds the hash of its parent. Verify `sub` continuity, that delegate equals the next presenter's WIT `sub`, and a depth limit. |
| T2 | Chain splicing (a valid link grafted onto another chain) | Bind links to a chain-root `txn` / `cnf`. Reject links whose parent hash or root differs (`chain.link_mismatch`). |
| T3 | Scope escalation along the chain | Enforce monotonic attenuation (child scope must be a subset of the parent's). Unknown scope means deny (Txn-Token 13.14) [16]. |
| R1 | Unattributable actions | Append-only, signed audit records: `txn`, full actor chain, PDP decision ID, policy version, reason code. Never log raw tokens. |
| I1 | Txn-Token leakage | Short TTL. Never embed the external access token (13.4). Strip the inbound access token before forwarding (no passthrough). Redact tokens from logs and error bodies. Use mTLS between hops. |
| I2 | Chain or PII disclosure in errors | Return a reason code only; details go to the audit log. Generalize internal names (WIMSE 3.4.10.1). |
| D1 | PDP or JWKS outage | **Fail closed** by default. Bounded timeouts and circuit breaker. Cache JWKS with a stale-if-error cap. Size/depth limits on chains. Bound the `jti` cache. |
| E1 | PDP fail-open, or an "allow" on error/unknown | A non-200 or unparseable AuthZEN response means deny. `decision` must be strictly the boolean `true`. Make fail-open impossible to configure for write actions. |
| E2 | visado signing-key compromise (the Smithery-class hub risk) | Keys in KMS/HSM, non-exportable. A separate key per trust domain (WIMSE 4.5) [17]. Short Txn-Token TTL. Automated rotation and a published JWKS. Downstreams verify `iss`. |
| E3 | Txn-Token used as an access token, or visado used as a confused deputy | Downstreams must reject a Txn-Token as Bearer (13.13). visado never attaches its own standing credentials to forward a request it cannot attribute to a verified chain. |
| X1 | Clock skew | Bounded leeway (30 to 60s, configurable, logged). Reject `iat` in the future beyond leeway. NTP health check. Skew combines with S2 to widen the replay window. |

## 5. Demo scenarios (docker-compose: `agent-a`, `agent-b`, `mock-mcp`, `mock-api`, `visado`, `pdp` (e.g. OPA/Cedar via AuthZEN), `issuer`)

Reason codes are proposals.

1. **"The helpful intern recruits the admin"** (modelled on ServiceNow/AppOmni [10]). A low-privilege user files a ticket with embedded instructions. The read-only triage agent A delegates to admin agent B, which calls `assign_role(attacker, admin)`.
   *Without:* B uses the initiating admin's session token and the role is granted.
   *With visado:* the A→B delegation carries `scope=tickets:read`, and B's request asks for `roles:write`. Result: 403 `chain.scope_escalation`. If attenuation passes, the PDP denies with `pdp.deny:requires_human_direct_chain`.
2. **"Your token, my API"** (token passthrough and replay [14], [11]). A naive MCP server forwards the user's bearer token downstream. A rogue MCP server in the same session captures it and replays it from another container to a second API.
   *Without:* the downstream accepts it because it doesn't check `aud`.
   *With visado:* the first hop gives `token.audience_mismatch`. The replay from the attacker container fails because there is no valid WPT for the bound workload key (`wpt.binding_mismatch`). A re-sent WPT gives `wpt.replay`.
3. **"Spliced chain, borrowed tenant"** (Asana-style cross-tenant [5] combined with chain splicing). The attacker agent in tenant B takes a valid delegation link issued for Alice@tenant-A (from a leaked log), grafts it onto its own chain and asks for tenant-A records.
   *Without:* the server trusts the outermost `sub` and returns tenant-A data.
   *With visado:* `chain.link_mismatch` (parent hash or root `txn` differs). With a correctly formed chain, the Txn-Token `tctx.tenant=B` against resource tenant A gives `pdp.deny:tenant_mismatch`.

**Recommended honesty slide:** run postmark-style BCC exfiltration through visado and show that it **succeeds**, because the malicious code sits behind the gateway. That draws a clean scope boundary and pre-empts critics.

## Gaps and confidence

- Asana root cause and customer count: unconfirmed. Supabase was a lab demo, not a breach. ServiceNow: sources disagree on whether a later platform fix shipped [10].
- OWASP wording comes from secondary summaries. Check it against the official PDFs before quoting.
- The WIMSE header names and WPT claims in section 4 are my design inference. Check them against draft-ietf-wimse-s2s-protocol.

## Sources

1. <https://invariantlabs.ai/blog/mcp-github-vulnerability>
2. <https://generalanalysis.com/blog/supabase-mcp-blog>
3. <https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/>
4. <https://supabase.com/blog/defense-in-depth-mcp>
5. <https://www.theregister.com/security/2025/06/18/asana-mcp-server-back-online-after-plugging-a-data-leak-hole/1199951>
6. <https://www.nudgesecurity.com/post/asana-mcp-server-data-exposure-incident>
7. <https://www.paloaltonetworks.com/blog/security-operations/first-malicious-mcp-in-the-wild-the-postmark-backdoor-thats-stealing-your-emails/>
8. <https://www.darkreading.com/application-security/malicious-mcp-server-exfiltrates-secrets-bcc>
9. <https://github.com/invariantlabs-ai/mcp-injection-experiments>
10. <https://appomni.com/ao-labs/ai-agent-to-agent-discovery-prompt-injection/>
11. <https://arcticwolf.com/resources/blog/widespread-salesforce-data-theft-via-compromised-salesloft-drift-oauth-tokens/>
12. <https://www.cybersecuritydive.com/news/hackers-steal-data-salesforce-instances/758676/>
13. <https://blog.gitguardian.com/breaking-mcp-server-hosting/>
14. <https://modelcontextprotocol.io/specification/draft/basic/security_best_practices>
15. <https://modelcontextprotocol.io/specification/draft/basic/authorization>
16. <https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/>
17. <https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/>
18. <https://github.com/luckyPipewrench/pipelock/blob/main/docs/owasp-agentic-top15-mapping.md>
19. <https://docs.modulos.ai/frameworks/owasp-top-10-agentic>
20. <https://kenhuangus.github.io/maestro-site/>
21. <https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/whitepapers/agentic-identity-and-access-control.md>
