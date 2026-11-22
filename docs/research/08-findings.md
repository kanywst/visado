# Findings from building visado (2026-11-22)

What implementing the drafts and running them against other implementations showed. The interop runs and their evidence are in [docs/interop.md](../interop.md); visado's choices where a draft is silent are in [SPEC-MAP.md](../../SPEC-MAP.md). Section numbers are the revisions visado pins.

## Interop results

- AAT -02: tenuo's 229 vectors agree 229/229 in visado, every denial at the expected step; 9 visado-minted chains agree 9/9 in tenuo's Section 8 verifier.
- asor -03: 9/9 each way with attenu-guard 0.22.0, same Table 2 outcome on every rejection, apart from attenu-guard's `EdDSA` label, which the draft already records.
- Transaction Tokens -11: authgent and kontxt tokens verify in visado (6/6, 4/4); visado tokens verify in atlas-go except where atlas-go departs from §9.2 (14/17), and in kontxt once visado signs RS256.
- WIMSE: the token and signature formats interoperate with wit-wpt-go, go-spiffe, the WG example generator and yaronf/httpsign. Most disagreements come from implementations that target s2s-protocol-07 or older.
- Three changes to visado came out of the runs: `RS256` verification, `RS256` minting with an RSA signing key, and `aud` arrays.

## 1. One key type, two names

The most common cause of failure across all four specs was the name of the Ed25519 algorithm. RFC 9864 deprecates the polymorphic `EdDSA` for the fully-specified `Ed25519`, and the drafts split:

- asor-03 §3 requires `Ed25519`; its reference implementation writes `EdDSA` (asor-1).
- AAT -02 requires `Ed25519` support and allows other algorithms (§9.11); visado accepts `Ed25519` and `ES256` and rejects the `EdDSA` label.
- atlas-go verifies Transaction Tokens signed `EdDSA` but not `Ed25519` (txn-2).
- creds-03's example WIT names its key `Ed25519` and wpt-02's names the same key `EdDSA`, so the two drafts' examples do not verify together (wimse-9).
- go-spiffe's WIT-SVID support refuses Ed25519 under either name (wimse-5).

A deployment that mixes these needs per-peer configuration of the algorithm label. The drafts would interoperate better if each said which label a verifier MUST accept during the transition.

## 2. Transaction Tokens

- No mandatory-to-implement algorithm (§9.1). The only example is RS256; kontxt signs and verifies only RS256, visado only Ed25519 and ES256. Two implementations of the same draft shared no algorithm until visado added RS256 (txn-1).
- `scope` is REQUIRED (§9.2) but not required to be non-empty. authgent issues `" "` and atlas-go accepts it; visado rejects it (txn-5).
- `aud` is "the trust domain" (§9.2) with no word on the array form RFC 7519 allows (txn-6). `typ` MUST be `txntoken+jwt` (§9.1), but RFC 7515 makes `application/txntoken+jwt` equivalent; implementations disagree (txn-7).
- Scope comparison is undefined (§13.6), the method for preserving a call chain across replacement is out of scope (§13.15), and `req_wl` with several workloads is ambiguous (§9.2). visado's answers are in SPEC-MAP.md.
- There is no subject token type URN for a WIT, so a TTS that exchanges a workload credential has to invent one.

## 3. Delegation chains

- Neither AAT -02 nor asor-03 defines an HTTP binding (AAT §1; asor has none). visado chose `AAT-Chain` and `AAT-PoP`, and `Agent-Delegation-Chain` with `DPoP` (`docs/bindings.md`). Two enforcement points that choose differently will not interoperate on the wire even with identical verifiers.
- AAT's audience claims are optional (§9.5). Without them a chain and its PoP can be replayed at another enforcement point; visado requires both by default.
- asor leaves the signer of every token after the root unspecified (§6.4, an open issue). visado binds every hop to the root's anchor, which matches attenu-guard's single-signer model.
- asor does not say what a per-action constraint means when the action has no matching parameter. visado denies; attenu-guard leaves it unbounded. No vector covers it.
- RFC 8693 §4.1 says prior actors are not used for access control but does not say how a resource server identifies the current actor. visado binds it to the authenticated caller.

## 4. WIMSE credentials

- wpt-02 §2 and http-signature-08 §3 cite workload-creds "Section 5.1.4", which does not exist in creds-03 (wimse-10). http-signature-09 fixes its own reference.
- wpt-02 §2 says a WPT whose `exp` is "unreasonably far in the future" SHOULD be rejected without a bound. visado's 60 s default rejects the draft's own Figure 5 WPT until shortly before it expires (wimse-8).
- Implementations written against s2s-protocol-07 and earlier (wit-wpt-go, the Cofide PoC) use the old WPT `typ`, `@request-target`, and no `wimse-aud`. Interop reports against the split documents need to state the revision.

## 5. AuthZEN

- AuthZEN 1.0 has no model for an agent acting for a user. visado sends the agent as `subject` and the user as `context.principal`.
- Of the PDPs tried, Cerbos does not pass `context` to the policy and Topaz evaluates only subject, relation and object, so a policy cannot see the user. visado added `[pdp] context_in_subject`, which copies the context into `subject.properties`. A PDP that follows the spec's `context` member is not enough by itself for agent traffic.

## Open

- No result yet from IETF 128 hackathon interop, and none of the drafts' Implementation Status sections lists visado.
- AAT verifiers other than tenuo's (azatdavliatshin/aat, mission-bound-authorization) and more Transaction Token Services (pytrat, Keycloak TTS, Janssen) have not been run.
