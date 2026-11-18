# Market, foundations and acquisitions (as of 2026-11-18)

Why an agent delegation-chain gateway, why now, and where it could live. Star counts are from the GitHub API on 2026-11-18 unless marked otherwise.

## Bottom line

- The spec side of agent identity moved fast in 2026 (WIMSE AIMS adopted, Transaction Tokens near publication, ID-JAG stable in the MCP Enterprise-Managed Authorization extension), but the open-source **relying side** is thin: almost everything ships issuance or a vendor gateway, not neutral verification of the whole call chain.
- CNCF has no project dedicated to agent or workload identity beyond SPIFFE/SPIRE, while its own AI TCG and TOC initiatives say interoperable agent identity is "currently lacking".
- Identity and agent-security acquisitions in 2026 shifted toward agent/NHI identity and MCP gateways. OSS-led targets sold cheaply relative to closed NHI vendors; stars bought the acquisition, not the multiple.

## Open-source gaps

| Area | State | Gap |
| --- | --- | --- |
| WIMSE issuance | SPIRE v1.16.0 (2026-11-05) issues WIT-SVIDs (experimental); go-spiffe has `exp/svid/witsvid` | None on issuance |
| WIMSE verification (WPT, HTTP-sig, mTLS) | `wimsey` (Rust, Apache-2.0) and one stalled PoC; go-spiffe WPT PR #415 still a draft | Nothing deployable at an enforcement point |
| Transaction Tokens | tokenetes (CNCF Sandbox, 66 stars, maintenance mode, K8s and SPIFFE only), aramase/kontxt (26 stars, single maintainer) | No neutral, actively maintained Txn-Token Service plus verifier |
| ID-JAG issuance | Dex (merged 2026-11-11, unreleased), Casdoor v4.27.1+, commercial IdPs | Receiving side and the agent hop after it |
| AIMS reference implementation | None; the draft has no Implementation Status section | Entire composition |
| Delegation-chain verification | Per-draft author libraries (attenu-guard, Tenuo, mission-core) | Format-neutral verifier wired to Txn-Tokens and a PDP |

Already well covered and not worth competing on: SD-JWT VC and status lists, DPoP, CIMD, AuthZEN PDPs, MCP auth proxies.

## CNCF and other foundations

- Identity and security projects accepted 2024-2026: Kuadrant (2024-07), Tratteria/Tokenetes (2025-01), kagent (2025-05), Cedar (2025-10), OAuth2-Proxy (2025-10), OpenShell and Agent Substrate (2026-10). OpenFGA moved to Incubating (2025-11); cert-manager (2024-11) and Kyverno (2026-03) graduated.
- agentgateway went to the Linux Foundation (2025-08) and then the Agentic AI Foundation (AAIF). OpenBao moved to OpenSSF (2025-06).
- Sandbox process: issue form, TOC review roughly every two months, 66% gitvote. Requirements include Apache-2.0 and a MAINTAINERS file with an organization column. Median time to approval since 2025 is about 73 days. Common rejections: insufficient momentum ("grow the community for 6-12 months"), missing files, single-vendor runtime lock-in, overlap with existing projects.
- Stated demand: the CNCF AI TCG "Cloud native agentic standards" (2026-03) asks for a unique workload identity per agent instance, short-lived credentials and re-verification per operation; TOC initiatives on MCP server authN/authZ (toc#1890) and agentic foundations (toc#1746) are open. AAIF leadership named identity, attestation and audit as open problems at AGNTCon 2026.
- Best fit: CNCF Sandbox next to SPIFFE/SPIRE and Tokenetes, with specification work in IETF WIMSE / OAuth and the OpenID Foundation.

## Acquisitions, 2024-2026 (selected)

| Acquirer and target | Date | Price | Notable OSS |
| --- | --- | --- | --- |
| Palo Alto Networks and CyberArk | closed 2026-02 | about $25B | none |
| CrowdStrike and SGNL (Transaction Tokens authors) | announced 2026-01 | about $740M | tokenetes lineage |
| ServiceNow and Veza | closed 2026-03 | about $1.2B | none |
| Cisco and Astrix | announced 2026-05 | reported $250-400M | none of note |
| Snowflake and Natoma (MCP gateway) | announced 2026-05 | reported $110-128M | none |
| Palo Alto Networks and Portkey | closed 2026-05 | $117M | Portkey gateway, about 12k stars at the deal (secondary source) |
| Vercel and Better Auth | 2026-07 | undisclosed | better-auth, 28k+ stars |
| Okta and Permiso | closed 2026-08 | reported under $200M | none |
| Cyera and Oasis (NHI) | closed 2026-09 | about $1B | none |
| Snyk and Invariant Labs | 2025-06 | undisclosed | mcp-scan (now snyk/agent-scan) |
| OpenAI and Promptfoo | announced 2026-03 | undisclosed | promptfoo |

Pattern:

- Most targets in this space were closed-source NHI, PAM or ITDR vendors bought for revenue.
- OSS-led targets were a dominant developer library, a developer-loved gateway or CLI on AI traffic, or a research team whose scanner backed its disclosures.
- Price tracked revenue, not stars.

## What spread in 2025-2026

- Better Auth was the only auth library to reach very large scale (30.8k stars), by filling a developer-experience gap as Auth.js stalled.
- MCP security tools spread through security research (Invariant's tool-poisoning disclosures behind mcp-scan; Koi's postmark-mcp report) rather than launches.
- Foundation-backed gateways (agentgateway, IBM ContextForge) grew through vendor endorsement with almost no Hacker News traction.
- Stand-alone MCP auth helper libraries stayed small because the official SDKs absorbed them. New work in this space should be a gateway or broker, not a library.

## Sources

- [cncf/sandbox](https://github.com/cncf/sandbox) and its issues #80, #115, #360, #371, #397, #455, #477, #479, #486, #522, #523
- [cncf/toc](https://github.com/cncf/toc) issues #1746, #1890, #1942, #1949, #2097
- [CNCF: Cloud native agentic standards](https://www.cncf.io/blog/2026/03/23/cloud-native-agentic-standards/)
- [CNCF IAM whitepaper](https://www.cncf.io/blog/2026/06/04/identity-and-access-management-whitepaper/)
- [agentgateway joins the Linux Foundation](https://agentgateway.dev/blog/2025-08-25-solo-contributes-agentgateway-to-lf/)
- [InfoQ: AGNTCon 2026](https://www.infoq.com/news/2026/10/agntcon-mcpcon-2026/)
- [SPIRE releases](https://github.com/spiffe/spire/releases)
- [draft-ietf-wimse-aims](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/)
- [Palo Alto Networks completes CyberArk](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-cyberark-to-secure-the-ai-era)
- [CNBC: CrowdStrike and SGNL](https://www.cnbc.com/2026/01/08/crowdstrike-ai-cybersecurity-sgnl-acquisition.html)
- [Dark Reading: ServiceNow and Veza](https://www.darkreading.com/cyber-risk/servicenow-acquire-nhi-provider-veza-strengthen-governance-portfolio)
- [SecurityWeek: Cisco and Astrix](https://www.securityweek.com/cisco-moves-to-acquire-astrix-security-to-tackle-non-human-identity-risks/)
- [The Register: Snowflake and Natoma](https://www.theregister.com/ai-and-ml/2026/05/28/snowflake-buys-natoma-to-help-freeze-out-rogue-agents/5248062)
- [GovConWire: Palo Alto Networks and Portkey](https://www.govconwire.com/articles/palo-alto-networks-portkey-acquisition-prisma-airs)
- [Better Auth joins Vercel](https://better-auth.com/blog/better-auth-joins-vercel)
- [TechCrunch: Okta and Permiso](https://techcrunch.com/2026/07/30/okta-buys-ai-security-startup-permiso-source-says-for-about-200m/)
- [Calcalist: Cyera and Oasis](https://www.calcalistech.com/ctechnews/article/8115vtsb5)
- [Tech.eu: Snyk and Invariant Labs](https://tech.eu/2025/06/24/snyk-acquires-ai-security-pioneer-invariant-labs-for-a-new-era-in-ai-safeguards/)
- [SecurityWeek: OpenAI and Promptfoo](https://www.securityweek.com/openai-to-acquire-ai-security-startup-promptfoo/)
