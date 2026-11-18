# visado: observability, UI, launch research (2026-11-18)

## TL;DR

- No OTel semconv for identity/authz exists yet. Reuse `gen_ai.agent.*`, `gen_ai.tool.name`, `mcp.*` (all Development, now in the separate semantic-conventions-genai repo). Put the chain under your own `visado.*` namespace and track GenAI PR #291 (agent authz attributes). `enduser.id` was deprecated in core v1.45 and moved to the client-side repo.
- Rust: opentelemetry 0.33.1 (2026-10-08). Logs and metrics are stable, traces are still beta. Pin opentelemetry*, and pair it with tracing-opentelemetry 0.34.
- Audit: OCSF API Activity (6003) with `actor.authorizations` and `actor.invoked_by`. CAEP 1.0/SSF 1.0 are Final (Sept 2025), so use them for revocation signals. AIMS needs tamper-evident audit records. PR #176 keeps the transcription mapping for audit.
- UI: a static SPA embedded in the binary, using React Flow with a left-to-right dagre/ELK layout and one-hop-per-node plus allow/deny coloring. The screenshot to aim for is one request with the hop that got denied lit up red.
- Launch: agent-identity Show HNs score low (Zalando AIB 25 pts, Nov 2026). Projects took off on a narrative hook: a threat model (Agent Vault 156), a story (Cloudflare "Claude wrote it"), research-first (mcp-scan), or a foundation donation at a conference (agentgateway). Proposed window: IETF 128 hackathon (Mar 6-7, 2027, inferred), then KubeCon EU, then AGNTCon NA.

## 1. Observability

### OTel semconv state

- The GenAI and MCP attributes moved to `open-telemetry/semantic-conventions-genai`, and the core registry marks `mcp.*` and `gen_ai.agent.id` as "Deprecated: moved". Everything there is Development stability. <https://opentelemetry.io/docs/specs/semconv/registry/attributes/mcp/> , <https://github.com/open-telemetry/semantic-conventions-genai>
- Agent spans are `create_agent` (CLIENT), `invoke_agent`/`invoke_workflow` (INTERNAL), `plan`, and execute_tool. `gen_ai.agent.id` must be a provider-assigned stable ID, not an in-memory instance ID. `gen_ai.conversation.id` is set only when a real ID exists. The spec has no guidance on span links and defines no identity attributes. <https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md>
- MCP spans are named `{mcp.method.name} {target}` (for example `tools/call get_weather`) and carry `mcp.session.id`, `mcp.protocol.version`, `jsonrpc.request.id`, and `gen_ai.tool.name`. Metrics are `mcp.{client,server}.operation.duration`. The spec recommends these over the RPC semconv. <https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md>
- `enduser.*`: v1.45.0 deprecated `enduser.id`/`enduser.pseudo.id` in core and moved them to semantic-conventions-client-side (v0.1.0-dev). `enduser.role` maps to `user.roles`. `enduser.scope` was removed with no replacement. <https://github.com/open-telemetry/semantic-conventions/releases/tag/v1.45.0> , <https://github.com/open-telemetry/semantic-conventions/pull/4238>
- Authz attributes are only proposals so far. GenAI issue #180 and PR #291 add `gen_ai.agent.*` trust/authz attributes and defer `fga.*` decision-path attributes. Their invariant is that a deny is a span with no child execute span. OpenLLMetry PR #4701 proposes `gen_ai.authz.decision`. <https://github.com/open-telemetry/semantic-conventions-genai/pull/291> , <https://github.com/traceloop/openllmetry/pull/4701>
  - Inference: this is an opening. visado could become the reference emitter and comment on #291 with a chain-aware shape.

### How to emit a chain (my recommendation; not in any spec)

- Use one SERVER span per request, `visado.authorize {gen_ai.tool.name}`, with these attributes:
  - `visado.chain.depth` (int)
  - `visado.chain.subjects` (string[]: `human:alice`, `agent:planner`, `agent:coder`, `tool:github`)
  - `visado.decision` (allow|deny)
  - `visado.deny.hop` (int)
  - `visado.txn_token.jti`
  - `authzen.policy.id`
  - plus `gen_ai.agent.name`, `gen_ai.tool.name`, `mcp.method.name`, `mcp.session.id`
- Add one span event per hop (`visado.hop`) carrying the subject, act claim, token type, scope narrowing and hop verdict. Events have timestamps, which plain attributes lack. <https://grafana.com/blog/2024/08/15/all-about-span-events-what-they-are-and-how-to-query-them/>
- Add a span link to the upstream agent's span context when an inbound `traceparent` exists or the token carries a trace ref, so cross-trace delegation stays navigable.
- Tempo TraceQL can query span, event and link scopes, for example `{ event:name = "visado.hop" }` and `{ link:traceID != "" }`. <https://grafana.com/blog/grafana-tempo-2-6-release-performance-improvements-and-new-traceql-features/> , <https://grafana.com/docs/tempo/latest/traceql/construct-traceql-queries/>
- Caveat: Jaeger and Tempo show events and links as a list, not a graph. That is why the dedicated UI (section 2) is needed.

### Rust SDK maturity

- opentelemetry-rust 0.33.1 (Oct 8 2026): OTLP logs and metrics exporters are stable, traces are beta. The 1.0 planned for June 2025 has slipped. <https://opentelemetry.io/docs/languages/rust/> , <https://github.com/open-telemetry/opentelemetry-rust/blob/main/docs/migration_0.28.md>
- tracing-opentelemetry (tokio-rs) is versioned separately: 0.34 pairs with otel 0.33. Expect breaking changes, so bump everything in lockstep. <https://docs.rs/tracing-opentelemetry>
- Note: the claim that 0.33.1 made logs/metrics OTLP stable comes from search-result summaries. Check it against the GitHub release notes before quoting.

### Audit formats

- AIMS (draft-ietf-wimse-aims-01, 2026-11-02): audit, delegation and authz depend on a stable WIMSE identifier, and audit records MUST be tamper-evident. <https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/>
- PR #176 (nik-kale) adds privacy text. Where stable IDs are not acceptable, the AS uses claims transcription (OAUTH-ID-CHAIN section 2.5) and keeps the mapping for audit. During review the text was softened to defer to deployment policy. Merge status is not visible. <https://github.com/ietf-wg-wimse/draft-ietf-wimse-aims/pull/176>
  - Implication: visado's audit record should store both pre- and post-transcription subject IDs, gated by policy.
- CAEP 1.0 / SSF 1.0 / RISC 1.0 are Final (vote Sept 2025). An interop profile is in progress. Use them as an output, for example emitting `session-revoked`/`token-claims-change` SETs when a chain is revoked. <https://openid.net/three-shared-signals-final-specifications-approved/>
- OCSF:
  - API Activity (6003) is the best fit per request. `actor.authorizations[]` carries decision and policy, and `actor.invoked_by` is a natural slot for the delegator. <https://schema.ocsf.io/1.3.0/objects/actor>
  - Authorize Session (3003) is session-level only.
  - Open issue #1736 debates mapping agent behavior to OCSF, so there is no settled agent mapping yet. <https://github.com/ocsf/ocsf-schema/issues/1736>
  - Inference: put the full chain in `unmapped` or a profile until OCSF settles.

## 2. UI

### How comparable tools show access paths

- Teleport Graph Explorer:
  - Paths always run left to right: Users, User Groups, Actions, Resource Groups, Resources.
  - It shows allow and deny paths, and deny wins.
  - Right-click filters the graph to one path.
  - There is also a SQL editor and a `tsh access-graph` CLI.
  - Enterprise only.
  - <https://goteleport.com/docs/identity-security/usage/graph-explorer/> , <https://goteleport.com/docs/identity-security/>
- Astrix: an "Identity Graph" of agents, MCP servers, NHIs, secrets and owners, with each agent mapped to a human owner. <https://astrix.security/product/ai-agent-discovery/>
- Aembit: no graph view found, only a "blended identity" audit trail. The SACR/buyer guidance says to ask for a two-hop demo where the final tool log retains the full chain. <https://aembit.io/blog/human-vs-ai-identity-why-ai-agents-are-breaking-identity/> , <https://softwareanalyst.substack.com/p/emerging-agentic-identity-access>
  - Inference: this exact demo is visado's screenshot.
- OpenFGA Playground:
  - A check is shown visually as the tuple path that proves it (Expand API).
  - Community tools add a step-by-step "proof" view and a share-link that encodes the whole store in the URL (no backend).
  - OpenFGA Studio uses React Flow.
  - <https://docs.fga.dev/intro/playground> , <https://github.com/hiren0ded/fga-playground>
- Kiali dropped Cytoscape for PatternFly Topology (2.0 deprecated it, 2.8 removed it). <https://kiali.io/news/release-notes/>
- Hubble UI: a React SPA plus a Go backend, with live flows drawn as animated edges. The graph library is not confirmed. <https://github.com/cilium/hubble-ui>

### What makes a screenshot compelling (synthesis)

- One request, a linear left-to-right chain, and each edge labeled with the token step (ID token, then ID-JAG/OBO, then Txn-Token) plus the scope narrowing (`repo:*` to `repo:foo:read`).
- The deny hop highlighted red, with the AuthZEN reason inline.
- A side panel with the decoded Txn-Token and the AuthZEN request/response.
- A "copy as TraceQL / open in Grafana" link.

### Recommendation

- Serve a static SPA from the gateway, embedded with `rust-embed`/`include_dir` at `/ui`. It reads a JSON `/api/requests/{id}/chain` endpoint and an SSE live tail.
- Use React Flow (`@xyflow/react`) with a dagre/ELK LR layout. Chains are small DAGs, so Cytoscape's large-graph strengths are not needed.
- Add a share-by-URL mode (chain JSON in the fragment, as fga-playground does) so people can paste chains into issues.
- Add a `visado explain <req-id>` TUI/CLI twin, similar to Teleport's `tsh access-graph` and openfga-tui.

## 3. Launch playbook

### Evidence (HN, via Algolia)

- Infisical "Show HN: Agent Vault" (2026-04-22): 156 pts. <https://news.ycombinator.com/item?id=47865822>
  - The post had a clear threat model (credential vs data exfiltration), cited prior art (Anthropic/Vercel/Cloudflare brokering), listed design decisions as bullets, admitted the DX was rough, and asked for feedback.
  - It had no live demo and leaned on Infisical's brand.
- Cloudflare workers-oauth-provider: not a Show HN. The thread "Cloudlflare builds OAuth with Claude and publishes all the prompts" (June 2025) went viral on the AI-authorship story, and a critique post followed. <https://news.ycombinator.com/item?id=44159166> , <https://news.ycombinator.com/item?id=44215667>
  - I could not verify the 889 pts figure.
- Better Auth:
  - "Launch HN" (YC P25, May 2025): 259 pts.
  - Third-party posts did better: Val Town's migration post got 304 pts, and the TechCrunch raise got 282.
  - Earlier self-posts got 10 to 73 pts.
  - <https://hn.algolia.com/api/v1/search?query=better%20auth&tags=story>
- mcp-scan: launched 2025-04-11 right after Invariant's tool-poisoning disclosures. Its HN posts got 1 to 6 pts, yet it reached about 3.2k stars and Snyk acquired the company (now snyk/agent-scan). Cisco's mcp-scanner got 168 pts. <https://invariantlabs.ai/blog/introducing-mcp-scan> , <https://github.com/invariantlabs-ai/mcp-scan>
- agentgateway: Rust, contributed to the LF at Open Source Summit EU on 2025-08-25, and now under AAIF. Its traction came from foundation and enterprise quotes, not HN (max 2 pts). <https://www.opensourceforu.com/2025/09/linux-foundation-strengthens-open-source-agentic-ai-with-solo-ios-agentgateway/>
- ToolHive: negligible HN presence (2 pts).
- Same category as visado:
  - Zalando "Agentic Identity Broker" Show HN (2026-11-06): 25 pts. It integrates with agentgateway via RFC 8693, uses a one-command `just compose-up-detached`, and asked for UI/UX feedback. <https://github.com/zalando-incubator/agentic-identity-broker>
  - Agent Passport: 14 pts.

### Takeaways

- Inference: a bare "agent identity gateway" Show HN will probably land at 10 to 30 pts.
- Lead with a hook instead:
  - (a) a research post, such as "we replayed N agent delegation chains and found scope widening", mcp-scan style; or
  - (b) a visual: an HN-native title showing the chain, for example "Show HN: Visado – see every hop of an AI agent's delegation chain (Rust)".
- Keep the format "Show HN: Name – plain-language what it does", with no buzzword stack.
- README order:
  1. A GIF/asciinema of the chain UI above the fold
  2. `docker compose up` / `cargo install` with a one-command demo that runs human, agent, agent and tool locally, and ends on a deny
  3. "Why" (threat model, 3 bullets)
  4. Specs implemented (Txn-Token, AuthZEN, WIMSE, AIMS) with versions
  5. Compare table (agentgateway, AIB, Aembit)
  6. Status/limits
- Interop with agentgateway and AIB is a credibility lever, since AIB already pairs with agentgateway.

### Calendar

- IETF 127 SF is Nov 14-20, 2026 (now). <https://www.ietf.org/meeting/upcoming/>
- IETF 128 Kuala Lumpur is Mar 6-12, 2027. The hackathon is probably Mar 6-7; that is inferred from the usual Sat-Sun pattern and not confirmed. <http://www.mail-archive.com/ietf-announce@ietf.org/msg26949.html>
  - IETF 126's hackathon drew about 800 registrants and about 70 projects. <https://www.ietf.org/blog/ietf126-recap/>
- KubeCon EU 2027 is in Barcelona, Mar 15-18. <https://contribute.cncf.io/events/cfp/>
  - The main CFP closed Oct 11, 2026, and notifications go out Dec 7.
  - The co-located CFP reportedly closed Oct 18.
  - Maintainer Summit is Mar 14. Rejekts is Mar 13-14.
  - "Agentics Day: MCP + Agents Europe" is Mar 15 in Barcelona.
- AGNTCon + MCPCon NA (formerly MCP Dev Summit) is Apr 28-29, 2027 at Moscone SF. Europe is Sep 15-16, 2027 in London. <https://events.linuxfoundation.org/agntcon-mcpcon-north-america-2027/>
- Suggested sequence:
  1. Txn-Token/AIMS interop at the IETF 128 hackathon (results slide plus WG list post)
  2. Show HN on a Tue-Wed morning US time, about a week later and away from conference noise (inference)
  3. Booth or lightning demos at Rejekts/Agentics Day
  4. Submit to the AGNTCon CFP (check its deadline)

### CNCF sandbox day-1 hygiene (CLOMonitor checks)

- An `ADOPTERS*` file
- DCO: enable the DCO app on all repos
- OpenSSF Best Practices badge in README
- Scorecard badge in README (`api.scorecard.dev` URL)
- Scorecard-derived checks: binary artifacts, code review, dangerous workflow, dependency update tool, maintained, signed releases, token permissions
- A recent release
- An approved license (Apache-2.0 is OK) and license scanning
- A CNCF Slack reference in README
- An OpenSSF Security Insights manifest
- SECURITY.md, CODE_OF_CONDUCT, GOVERNANCE, MAINTAINERS, CONTRIBUTING
- Sources: <https://clomonitor.io/docs/topics/checks/> , <https://github.com/cncf/clomonitor/blob/main/docs/checks.md>
- Note: the sandbox onboarding asks for the Best Practices badge, while the security guidelines push Scorecard, so do both.
- For a Rust project, also: `cargo-deny`/`cargo-audit` in CI, signed releases (cosign/sigstore), SLSA provenance, and pinned action SHAs (helps the Scorecard token-permissions and pinned-deps checks).

## Gaps / confidence

- The 889 pts figure for workers-oauth-provider is not verified.
- Hubble UI's graph library is unknown.
- The IETF 128 hackathon exact days are inferred.
- AGNTCon NA CFP deadline was not checked.
- The otel-rust 0.33.1 stability claim needs a check against the release notes.
- Everything in the GenAI/MCP semconv is Development and still churning.
