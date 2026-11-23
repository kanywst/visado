# Interop results

Runs of visado against implementations written by other people, run on 2026-11-22. The harnesses, pins and raw results are in [interop/](../interop/); each directory's `run.sh` reproduces its rows. "Agree" counts cases where both sides give the verdict the pinned draft requires, except where noted.

## Matrix

| Spec | Implementation | Version | Direction | Cases | Result |
| --- | --- | --- | --- | --- | --- |
| AAT -02 | [tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo) vector suite | `f1a6c22b`, suite SHA-256 `b7a42e9d…` | tenuo -> visado | 229 | 229/229 agree, 175/175 denials at the expected step (tenuo's `compare_results.py`) |
| AAT -02 | tenuo `gen_vectors.verify_chain` | `f1a6c22b` | visado -> tenuo | 9 | 9/9 agree, same step on all 7 denials |
| asor -03 | [attenu-io/attenu-guard](https://github.com/attenu-io/attenu-guard) | 0.22.0 | attenu-guard -> visado | 9 | 8/9; A.9 is attenu-guard's `EdDSA` label (asor-1) |
| asor -03 | attenu-guard | 0.22.0 | visado -> attenu-guard | 9 | 9/9, same Table 2 outcome on every rejection |
| Txn-Tokens -11 | [authgent/authgent](https://github.com/authgent/authgent) TTS | `8341cf93` (authgent-server 0.3.4) | authgent -> visado | 6 | 6/6 |
| Txn-Tokens -11 | [aramase/kontxt](https://github.com/aramase/kontxt) TTS | `d23ebb50` | kontxt -> visado | 4 | 4/4 after the RS256 fix (0/4 valid before: txn-1) |
| Txn-Tokens -11 | [Atlas-Authorization/atlas-go](https://github.com/Atlas-Authorization/atlas-go) verifier | v0.27.0 (`794a21e5`) | visado -> atlas-go | 17 | 14/17 (txn-2, txn-3, txn-4) |
| Txn-Tokens -11 | kontxt verifier | `d23ebb50` | visado -> kontxt | 17 | 13/17: all RS256 cases pass after the RS256 minting fix; the ES256 and Ed25519 valid cases are rejected at `alg` (txn-1) |
| WIMSE WIT + WPT | [strideynet/wit-wpt-go](https://github.com/strideynet/wit-wpt-go) | `e8fa3451` | wit-wpt-go -> visado | 7 | 6/7 (wimse-2) |
| WIMSE WIT | wit-wpt-go `MintWIT` | `5cf9b7de` | wit-wpt-go -> visado | 6 | 6/6 |
| WIMSE WIT + WPT | wit-wpt-go `ValidateWPT` | `5cf9b7de` | visado -> wit-wpt-go | 27 | 21/27 as is; 13/18 with WPTs re-signed in its format (wimse-2 to wimse-4) |
| WIMSE WIT | [spiffe/go-spiffe](https://github.com/spiffe/go-spiffe) `witsvid` | `b6b0441b` | visado -> go-spiffe | 27 | 14/27; ES256 8/9 (wimse-5, wimse-6) |
| WIMSE HTTP signature | [cofide/wimse-s2s-httpsig-poc](https://github.com/cofide/wimse-s2s-httpsig-poc) | `7984a601` | Cofide -> visado | 8 | 8/8 against -08 (none of its requests is valid under -08: wimse-7) |
| WIMSE HTTP signature | Cofide PoC server; yaronf/httpsign | `7984a601`; v0.3.1 | visado -> Cofide | 8; 24 | 7/8 (wimse-7); RFC 9421 and RFC 9530 checks 24/24 |
| WIMSE WIT + WPT | WG example generator, draft examples | s2s-protocol `ae2acf10`; creds-03, wpt-02 | drafts -> visado | 7 | 6/7 (wimse-8) |
| WIT-SVID | SPIRE | v1.16.0 | SPIRE -> visado | lab | `deploy/lab`: SPIRE-issued ES256 WIT-SVIDs with WPTs and HTTP signatures |
| AuthZEN 1.0 | OPA with [opa-authzen-plugin](https://github.com/kanywst/opa-authzen-plugin), Cerbos | 0.12.1, 0.57.0 | visado -> PDP | lab | `deploy/lab`, both PDPs in CI. The OPA plugin has the same author as visado; Cerbos is independent |

visado changes from these runs: three, all in Transaction Tokens (txn-1: RS256 verification and RS256 minting with an RSA `[signing_key]`; txn-6: `aud` arrays). No AAT, asor or WIMSE bug was found in visado or wimsey.

## Divergences

Section numbers are the pinned revision. File and line references are in the other project at the pinned commit. "Other side" means the other implementation departs from the draft; "spec" means the draft leaves it open or is inconsistent. Nothing here has been reported upstream yet.

### Transaction Tokens (draft-ietf-oauth-transaction-tokens-11)

| # | Finding | Evidence | Class |
| --- | --- | --- | --- |
| txn-1 | No mandatory-to-implement algorithm. kontxt signs and verifies RS256 only; visado signed and verified only Ed25519, EdDSA and ES256. visado now verifies and mints RS256 (RSA keys of at least 2048 bits), so the two interoperate when visado is given an RSA `[signing_key]` | §9.1 (the only `alg` is RS256 in the example); kontxt `pkg/token/token.go:45`, `sdk/verify/verifier.go:77`, `:140` | spec; visado fixed |
| txn-2 | atlas-go accepts `EdDSA` but not the fully-specified `Ed25519` (RFC 9864), which visado writes for Ed25519 keys | atlas-go `verify.go:574`, `txn_token.go:85` | other side |
| txn-3 | atlas-go requires `iss` and rejects a token without it | §9.2 (`iss` OPTIONAL); atlas-go `txn_token.go:69-70`, `:121` | other side |
| txn-4 | atlas-go accepts until `exp` + 5 s; visado rejects at `exp` with no default leeway | RFC 7519 §4.1.4 allows leeway; atlas-go `txn_token.go:132`, `verify.go:35` | both conform |
| txn-5 | Empty or blank `scope`: atlas-go checks presence only; authgent issues `"scope": " "`; visado rejects both | §9.2 (`scope` REQUIRED, non-empty not stated); atlas-go `txn_token.go:138-141`; authgent `server/authgent_server/services/token_service.py:722-723`, `:749` | spec |
| txn-6 | `aud` as an array: visado rejected it; atlas-go accepts any array that contains the trust domain, including one that also names other audiences. visado now accepts only a one-element array holding the trust domain, since a Txn-Token is scoped to one trust domain; a longer array is `txn.invalid_claim` | RFC 7519 §4.1.3; §9.2 (`aud` is the trust domain) silent on arrays; atlas-go `txn_token.go:160-172` | visado changed; spec |
| txn-7 | `typ` `application/txntoken+jwt`: visado accepts it (RFC 7515 §4.1.9), atlas-go and kontxt reject it | §9.1 ("MUST be `txntoken+jwt`"); atlas-go `txn_token.go:85`; kontxt `sdk/verify/verifier.go:57` | spec |
| txn-8 | Future `iat`: visado rejects, atlas-go does not check | §12.2 lists signature, `aud` and expiry only | policy |
| txn-9 | kontxt's verifier does not check the §9.2 required claims (code reading; not reachable in the run) | kontxt `sdk/verify/verifier.go:161-186` | other side |

### asor (draft-asor-wimse-agent-delegation-chain-03)

| # | Finding | Evidence | Class |
| --- | --- | --- | --- |
| asor-1 | attenu-guard signs and verifies Ed25519 as `"alg": "EdDSA"`; visado rejects it as `signature_invalid` | §3 and step 1 of §6 (fully-specified algorithm, RFC 9864); attenu-guard `wire.py` `Ed25519Signer.alg`. The draft's §11 already says so | other side, known |

The rows of SPEC-MAP.md "asor: known divergences and choices" where visado and attenu-guard differ on inputs no vector covers still stand; none came up in these runs.

### WIMSE (workload-creds-03, wpt-02, http-signature-08)

| # | Finding | Evidence | Class |
| --- | --- | --- | --- |
| wimse-1 | wit-wpt-go `MintWPT` fails for every WIT `MintWIT` makes (P-256 WIT key, `EdDSA` WPT signer) | wit-wpt-go `wit.go:63`, `wpt.go:86-91` | other side |
| wimse-2 | wit-wpt-go's WPT has `typ` `wimse-proof+jwt` and `exp` as a JSON time string | wpt-02 §2, RFC 7519 §4.1.4; wit-wpt-go `wpt.go:13`, `:19` | other side (s2s-protocol-06 or earlier) |
| wimse-3 | `ValidateWPT` takes only ES256 WITs and `EdDSA` WPTs | creds-03 §5.1; wit-wpt-go `wpt.go:131`, `:147-150` | other side |
| wimse-4 | `ValidateWPT` checks neither WIT `exp`, WPT `exp` nor `aud` | wpt-02 §2; wit-wpt-go `wpt.go:120-122`, `:136` | other side |
| wimse-5 | go-spiffe `witsvid` refuses Ed25519 issuer and proof keys, including the shape of creds-03 Figure 4 | creds-03 §5.1; go-spiffe `exp/svid/witsvid/svid.go:21-31`, `:208-210` | other side (local policy) |
| wimse-6 | go-spiffe `witsvid` requires `kid`; visado accepts a WIT without one when the trust domain has one key | creds-03 §3; go-spiffe `svid.go:115` | other side (stricter) |
| wimse-7 | The Cofide PoC signs with the `alg` parameter, `expires` at the WIT `exp`, `@request-target` and no `wimse-aud`, and its server requires `@request-target` | http-signature-08 §3; Cofide `wimse/shared/httpsig.go:25`, `:34-45`, `wimse/server/server.go:94` | other side (targets s2s-protocol-07) |
| wimse-8 | visado caps a WPT's remaining lifetime at 60 s by default, so the wpt-02 Figure 5 WPT is refused until 60 s before its `exp` | wpt-02 §2 ("unreasonably far in the future SHOULD be rejected") | visado choice |
| wimse-9 | creds-03 Figure 2 has `cnf.jwk.alg` `Ed25519`, wpt-02 Figure 5 has `EdDSA` for the same key, so the two drafts' examples do not combine | creds-03 Figure 4; wpt-02 Figures 3 and 5 | spec (editorial) |
| wimse-10 | wpt-02 §2 and http-signature-08 §3 point to workload-creds "Section 5.1.4", which does not exist in creds-03 (§5.1.3) | wpt-02 §2; http-signature-08 §3, §3.6 | spec; http-signature-09 fixes its own reference |

The full WIMSE list, with wimse-11 and wimse-12 (Cofide server checks, wit-wpt-go `oth`), is in [interop/wimse/README.md](../interop/wimse/README.md).

## http-signature -09

visado pins draft-ietf-wimse-http-signature-08. The -09 (20 November 2026) changes, per its Appendix B.1: a request may carry a server-generated nonce from `Accept-Signature` that meets the uniqueness and entropy rules (#369); CONNECT `@authority` follows RFC 9421 default-port omission (#419); editorial changes to the introduction and example nonces; and corrected cross-references to workload-creds (#422), which fixes this document's side of wimse-10. visado sends no `Accept-Signature` and does not handle CONNECT, so none of these changes its behaviour; the pin can move to -09 with a SPEC-MAP update.

## Not yet run

- AAT: [azatdavliatshin/aat](https://github.com/azatdavliatshin/aat) and [mcguinness/mission-bound-authorization](https://github.com/mcguinness/mission-bound-authorization) pass tenuo's suite and could verify visado-minted chains.
- Transaction Tokens: roshanlam/pytrat, ianlintner/rust-oauth2-server, CarrettiPro/keycloak-tts, the Janssen server.
- AuthZEN: OpenFGA, Topaz and Permguard were tried for the lab and set aside: Topaz ignores `context`, OpenFGA rejects SPIFFE-shaped subject and URL-shaped object identifiers in tuples, Permguard needs non-standard request fields.
