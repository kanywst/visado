# Delegation-chain formats for visado (research, 2026-11-18)

## Bottom line

- The WG-adopted work does not cover offline attenuation. WIMSE AIMS (draft-ietf-wimse-aims-01, WG doc) and OAuth Transaction Tokens, identity chaining (RFC-to-be 10092) and the actor profile carry "who acted". The 19 Nov joint WIMSE+OAuth session has "Transaction Tokens for Agents" and "OAuth Actor Profile for Delegation". Under RFC 8693 those carry inner actors as audit history, not as limits on authority.
- The offline-attenuated family (`par_hash` chains: niyikiza AAT-02 in OAuth, asor-03 in WIMSE) has the implementer momentum: vectors, independent verifiers, a 16 Nov side meeting, and an 18 Nov convergence report. It has no WG adoption.
- Recommendation: build the core around the `par_hash` JWS chain family. Use **AAT-02 first as the conformance target**, because it has 229 mutation-checked vectors, 2 independent full passes, and per-hop signing by the parent's `cnf` key. Add **asor-03 as a second profile on the same decoder**: 36 vectors, and an independent asor verifier written during an earlier hands-on lab matched all of them, so it can serve as an oracle. Next, add an **RFC 8693 `act` adapter at "declared" assurance**, because Txn-Token minting needs it anyway. Delegate SD-JWT comes later (WG doc, but -00 and no vectors).
- Confidence: medium. I read only the Nov 5-18 pages of the mail archive (no October pages). The IETF 127 WIMSE/OAuth sessions are 18-20 Nov, so there are no minutes yet.

## Comparison

| Draft (rev, date) | Token format | Attenuation | Chain verification | Trust anchor | PoP | Maturity | Impls / vectors |
|---|---|---|---|---|---|---|---|
| asor-wimse-agent-delegation-chain-03 (2026-10-27) | RFC 9068 JWT, JCS-canonical, Ed25519 required; one RAR `agent_delegation` detail; `sub`=principal (invariant), `client_id`=actor, `del_depth`/`del_max_depth`, `par_hash`=SHA-256(parent JWS Signing Input) | Scopes (literal / segment wildcard / opaque) + 8 constraint types (max, min, max_lifetime, max_subtree, one_of, not_one_of, prefix, rank); child = meet(parent, request); unknown types fail closed | 8 ordered steps, deny on first failure, named outcomes (Table 2); steps 1-5 run offline without a request | Root key only; DT_i (i>0) signer unspecified (single-signer model); provenance listed as an open issue (S6.4) | `cnf` + DPoP only (mTLS dropped in -03) | Individual draft. Hub in WIMSE: hulea, sweeney and nandakumar build on it | attenu-guard (Py 0.22.0), attenu-guard-ts 0.16.0 (no step 6/7); Cred native verifier 36/36; 36 -03 + 20 -01 JSON vectors (HS256 test signer) |
| nandakumar-wimse-delegator-bound-chains-00 (2026-11-16) | Extends asor DTs: `del_bind=delegator`, `sub_kind=pseudonym`, `ctx` (dialog/txn) | Adds `aud` subset per hop | Child signed by the key in the parent's `cnf`; `iss`=parent `client_id`; repeated `client_id` rejected (cycle check); `par_hash` | Root issuer; HMAC pseudonym key | Inherits asor | -00, 2 days old; Marc Miro wants this as a flag in asor | None |
| niyikiza-oauth-attenuating-agent-tokens-02 (2026-10-26) | JWS JWT `typ=aat+jwt`, Ed25519; RAR `attenuating_agent_token` with `tools` -> argument constraints; same `par_hash`/`del_*` names | Full per-type subsumption table (S4.5), invariants I1-I6; holder derives children offline | S8 algorithm; child `iss` = JWK thumbprint URI of the parent `cnf.jwk`, signed by that key | Root issuer (token endpoint, `req_cnf`) | Leaf `aat-pop+jwt` binds the tool call and its arguments (an MBA profile uses DPoP/`cnf.jkt`) | Individual; side meeting at IETF 127; asor deferred claim registration to it | 229 JSON vectors (tenuo `tests/vectors/aat-jws-vectors.json`); full passes: mission-core (TS) 229/229, azat `aat` (TS) 229/229 same step; Tenuo (Rust, CBOR, JWS in progress), Warden (Go, -01), ARCP (Go) |
| sweeney-wimse-credential-delegation-02 (2026-10-30) | DPoP-bound JWTs minted by a Delegation Server; RAR `cred_delegation`; `act.sub`, `prf` -> DS-signed receipt | Same 8 constraint types; DS checks containment | Online: the DS re-verifies the whole chain at every hop; S5.5 verifies asor tokens offline | DS (central; risk noted in S10.9); did:key agents | DPoP | Individual | Cred SDK (TS) |
| hulea-wimse-agent-mandate-01 (2026-11-01) | `mandate+jwt` + `authority+jwt`/`authority+sd-jwt` (evidence that the delegator may delegate) | Per-permission narrowing; `sum_max`, `window`, `cosign_above` (no asor equivalent) | Deterministic, collects all errors; valid / invalid / indeterminate; child signed by the parent `cnf.jkt` | Role-scoped Trust Anchor Set + trust frameworks | HTTP Message Signatures with the WIT key at token exchange | Individual; plans to carry the chain in asor format next rev | 49 prose conformance cases; some signed vectors external |
| sato-soos-mjwt-06 (2026-09-07) | EdDSA JWT; many SOOS claims; `delegation_chain` array | 8-dimension Narrowing Property, Cedar actions | 13 steps; live re-check of the parent signature/status | Deferred to WIMSE | `cnf` (presentation undefined) | Individual, domain-specific; presented at IETF 126 | None found |
| ietf-oauth-delegate-sd-jwt-00 (2026-10-26) | SD-JWT whose KB-JWT is itself a KB-SD-JWT carrying a `delegate_payload`, nested | Holder withholds disclosures (selective disclosure, not a constraint algebra) | Each component verified with the previous component's `cnf`; `sd_hash`/`issuer_jwt_hash` links | Issuer key | KB-JWT chain | **OAuth WG document**; on the IETF 127 OAuth agenda | No vectors or impls; editorial bugs (typ mismatch S5.1.4 vs S6) |
| RFC 8693 `act` + mcguinness-oauth-actor-profile-01 (2026-10-09), mw-oauth-actor-chain-03 (2026-11-01) | Nested `act` in the AS-issued token; actor-chain adds `actp/acti/actc` + JWS step proofs | None. Inner actors are informational only (RFC 8693 S4.1, actor-profile) | Trust the issuing AS; actor-chain "Verified" adds a per-step proof + AS acceptance | AS | Top-level `cnf` = outermost actor (DPoP/mTLS) | Actor profile on the 19 Nov joint session agenda | Actor-chain has ES256 vectors |
| oauth-ai-agents-on-behalf-of-user-02 | `requested_actor`/`actor_token` | n/a | n/a | AS | n/a | **Expired** (2025-08-25) | none |

Short notes:

- jackson-wimse-evaluation-05 (2026-10-28): verifier-evaluation rules (inputs, staleness, fail-closed), so that two verifiers reach the same decision. It is complementary to the format drafts. Its fail-closed rules are worth reusing for a status-fetch policy.
- thaha-wimse-agent-evidence-binding-03 (Nov 2026): `aee_evidence` claim (evidence service, policy digest, did:web logical id). It says the `act` chain is "attribution, not authority". Not a chain format.
- lee-wimse-local-tool-call-proof-01 (2026-10-12): an external Call Authority issues a single-use proof over the tool name and argument digest for local (stdio MCP) calls. No chain.
- ni-wimse-ai-agent-identity-04 (2026-10-27): agent identity bootstrapping and a dual (agent+owner) credential. No chain, no token format.
- reddy-wimse-oauth-dialog-binding-00 (2026-10-30): `tctx.dlg` in Txn-Tokens + a WPT `dth` claim over a Dialog-Context header. **Relevant to minting**: a Txn-Token can carry the dialog id, and nandakumar `ctx` type `dialog` targets the same binding.
- durga-wimse-ctx-isolation-00 (2026-10-29; -01 announced 11-17): per-call signed taint attestation, self-asserted by the runtime. Orthogonal to chains; at most an optional "context evidence" attachment.

## Momentum (Oct-Nov 2026)

- WG side. AIMS is a WIMSE WG doc and points to identity chaining, Txn-Tokens and RFC 8693, but defines no multi-hop attenuation. The 19 Nov joint WIMSE/OAuth session covers Identity Chaining (RFC-to-be 10092), Txn Tokens for Agents and the OAuth Actor Profile. Delegate SD-JWT is an OAuth WG doc on the 18 Nov agenda. At IETF 126, AIMS adoption was requested and the chair said a call would follow. PEDIGREE and SOOS MJWT were presented without recorded outcomes.
- Implementer side. 18 Nov "Implementation report: convergence across the offline-attenuated agent-token drafts": niyikiza and asor are "nearly wire-identical" on `par_hash`/`del_depth`. The open points are the meet algorithm and whether signature octets are hashed (asor-03 says Signing Input). The report proposes shared chain-linkage vectors. Also: the AAT side meeting on 16 Nov; the AAT -02 thread, where `del_max_depth` semantics remain the main disagreement (AAT allows leaf == max and keeps the holder cap); the hackathon thread on agent call-chain scenarios (revocation after delegation, widening, cumulative limits); and the PACE / Actor-Bound Tokens / delegator-bound drafts from Nandakumar and Jennings (Cisco) on 16 Nov.
- Inference: the likely end state is `act`/Txn-Token for attribution inside a domain, plus an offline `par_hash` chain for bounded authority, possibly converging on a single AAT/asor claim set. Nothing is decided.

## Recommendation: pluggable chain verifier

Split into three layers:

1. `ChainDecoder` (format-specific): parse, canonicalization rules, signature verification, link verification (`par_hash` / `sd_hash` / receipt / none), producing a `NormalizedChain` plus `assurance` per hop.
2. Format-neutral invariant engine: principal invariance, monotone `exp`, depth (with a `DepthSemantics` enum: `AsorStrict` = leaf < root max; `AatHolderCap` = leaf <= the nearest cap), audience subset, cycle detection on `ActorId`, status, PoP and the action check.
3. `AuthorityAlgebra` per RAR detail type (`agent_delegation`, `attenuating_agent_token`, ...): `subsumes(parent, child)` and `permits(leaf, action, totals)`. Unknown type -> deny.

Normalized model (Rust sketch):

```rust
struct NormalizedChain {
    profile: Profile,                 // AatJws02 | AsorDt03 | DelegateSdJwt00 | Act8693 ...
    principal: Principal,             // { iss, id, kind: Subject|Pseudonym }
    root: TrustRef,                   // anchor id + key thumbprint used (for audit)
    hops: Vec<Hop>,                   // index 0 = root
    raw: Vec<Bytes>,                  // exact signing inputs, for receipts
}
struct Hop {
    depth: u32, max_depth: Option<u32>,
    actor: ActorId,                   // { iss, sub/client_id }
    delegator: Option<ActorId>,
    signer: KeyThumbprint,
    signer_binding: SignerBinding,    // RootAnchor | ParentCnf | AuthServer | Unverified
    link: Link,                       // ParHash([u8;32]) | SdHash | Receipt | NestedOnly
    authority: Authority,             // { detail_type, scopes, constraints, audiences }
    validity: Validity,               // iat, nbf, exp
    cnf: Option<Cnf>, status: Option<StatusRef>, ctx: Option<ContextRef>,
    assurance: Assurance,             // Verified (crypto-attenuated) | Declared (act-only)
}
struct Constraint { key: String, op: Op, value: Value, measure: PerAction|Cumulative|Subtree }
```

Rules: authorize only on hops with `assurance=Verified`. `Declared` hops (RFC 8693 inner `act`) go to audit or Txn-Token context, never to subsumption. Report `steps_performed/steps_skipped` (asor S6.1). Output Txn-Token: `sub`=principal, `act`=leaf actor (outermost), `tctx`=chain digest + `dlg` if present.

Test vectors:

- AAT-02: 229 JSON, tenuo-ai/tenuo `tests/vectors/aat-jws-vectors.json`, `compare_results.py`, INTEROP table.
- asor-03: 36 JSON (`src/attenu_guard/vectors/draft02`, tag v0.22.0) + 20 -01. HS256 test signer. An independent verifier from an earlier hands-on lab matched 36/36 (and 52/52 including the -01 set).
- hulea-01: 49 prose cases (not machine-readable).
- mw-actor-chain-03: ES256 vectors (S30, not read).
- RFC 8037 Ed25519 / RFC 9449 DPoP examples for primitives.
- Delegate SD-JWT, nandakumar, MJWT, sweeney: none in-draft (Cred SDK reruns asor vectors).
- Hackathon scenario files (Ben Le) were promised but not seen.

## Sources

- <https://datatracker.ietf.org/doc/draft-asor-wimse-agent-delegation-chain/03/>
- <https://datatracker.ietf.org/doc/draft-nandakumar-wimse-delegator-bound-chains/00/>
- <https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/>
- <https://datatracker.ietf.org/doc/draft-sweeney-wimse-credential-delegation/02/>
- <https://datatracker.ietf.org/doc/draft-hulea-wimse-agent-mandate/01/>
- <https://datatracker.ietf.org/doc/draft-sato-soos-mjwt/06/>
- <https://datatracker.ietf.org/doc/draft-ietf-oauth-delegate-sd-jwt/00/>
- <https://datatracker.ietf.org/doc/draft-mcguinness-oauth-actor-profile/01/>
- <https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/03/>
- <https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/02/>
- <https://www.rfc-editor.org/rfc/rfc8693#section-4.1>
- <https://datatracker.ietf.org/doc/draft-jackson-wimse-evaluation/05/>
- <https://datatracker.ietf.org/doc/draft-thaha-wimse-agent-evidence-binding/03/>
- <https://datatracker.ietf.org/doc/draft-lee-wimse-local-tool-call-proof/01/>
- <https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/04/>
- <https://datatracker.ietf.org/doc/draft-reddy-wimse-oauth-dialog-binding/00/>
- <https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/01/>
- <https://mailarchive.ietf.org/arch/msg/wimse/cassf4o4SK4TEW2KH1g22P-vVEM/> (convergence report, 11-18)
- <https://mailarchive.ietf.org/arch/msg/wimse/fMPFKSpMHoji68UYn5W3bcNh_NE/> (delegator-bound reply, 11-16)
- <https://mailarchive.ietf.org/arch/msg/wimse/a1elD5SHAy4Yhdf4GkQ4zkrIa78/> (AAT -02 thread, 11-09)
- <https://mailarchive.ietf.org/arch/msg/wimse/KhTvcCX802aq2nWC2d1fB7kU4Mg/> (AAT side meeting)
- <https://mailarchive.ietf.org/arch/msg/wimse/ZixXiR4EY4j_6MbCONxf7N53qzI/> (hackathon scenarios)
- <https://mailarchive.ietf.org/arch/msg/wimse/SHso1Zyz_O4N_fiIhRoh_i8IgZA/> (AIMS-00 multi-hop)
- <https://datatracker.ietf.org/meeting/125/session/wimse>
- <https://datatracker.ietf.org/doc/minutes-126-wimse-202607201200/>
- <https://datatracker.ietf.org/meeting/127/session/wimse>
- <https://datatracker.ietf.org/meeting/127/session/oauth>
- <https://github.com/tenuo-ai/tenuo/tree/main/ietf/vectors> (README.md, INTEROP.md)
- <https://github.com/attenu-io/attenu-guard> (src/attenu_guard/vectors/draft02, 36 files)
- Local: tracks/ietf-wimse/deep-dives/draft-asor-wimse-agent-delegation-chain/{README,spec-notes,context,interop-checklist,hands-on-log}.md; draft-durga-wimse-ctx-isolation/{README,context}.md
