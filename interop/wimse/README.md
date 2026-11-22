# WIMSE credential interop

visado's caller authentication (`visado-credentials`, through wimsey 0.10.1)
for a WIT with a WPT and a WIT with an HTTP message signature, against
independent implementations. visado pins draft-ietf-wimse-workload-creds-03,
draft-ietf-wimse-wpt-02 and draft-ietf-wimse-http-signature-08 (-09 has since
been published). Section numbers below are those revisions unless stated.

## Implementations

| Implementation | Language, license | Pin | Targets | Role here |
| --- | --- | --- | --- | --- |
| [strideynet/wit-wpt-go](https://github.com/strideynet/wit-wpt-go) | Go, Apache-2.0 | `5cf9b7de` (HEAD) | s2s-protocol, unversioned: WIT `typ` of -07, WPT `typ` of -06 and earlier | WIT minter (`MintWIT`), verifier (`ValidateWPT`) |
| same | | `e8fa3451` | same | WIT and WPT minter (`MintWPT` still works there) |
| [spiffe/go-spiffe](https://github.com/spiffe/go-spiffe) `exp/svid/witsvid` | Go, Apache-2.0 | `b6b0441b` (v2.9.1-0.20261121152617) | WIT-SVID | WIT verifier (`ParseAndValidate`); no public minter |
| [cofide/wimse-s2s-httpsig-poc](https://github.com/cofide/wimse-s2s-httpsig-poc) | Go, Apache-2.0 | `7984a601`, with yaronf/httpsign v0.3.1 | s2s-protocol-07 | HTTP signature signer (`shared.GetWITHTTPSigner`) and the server's check |
| [ietf-wg-wimse/draft-ietf-wimse-s2s-protocol](https://github.com/ietf-wg-wimse/draft-ietf-wimse-s2s-protocol) `examples/main.go` | Go | `ae2acf10` | editors' copy | WIT and WPT example generator |
| Draft examples | text | creds-03 Figures 2 and 4 to 6, wpt-02 Figures 2 and 5 | | fixed vectors, `vectors/draft-examples.json` |

Existing result, not rebuilt here: `deploy/lab` runs SPIRE v1.16.0, which issues
ES256 WIT-SVIDs that visado verifies with WPTs and HTTP signatures signed with
the SPIRE-generated key (`deploy/lab/README.md`, "SPIRE" and "Scenarios").

## Directions and cases

`wimse mint` (`../harness/src/bin/wimse.rs`) makes the visado side: WITs by
`wimsey-wit` in the testkit's claim shape, WPTs by `testkit::wpt_at`, HTTP
signatures by `testkit::http_signature`, in three suites: `ed25519` (testkit
issuer and proof key), `es256`, and `es256-eddsa` (ES256 issuer, Ed25519 proof
key named `EdDSA`, as in the wpt-02 examples). Each suite has nine WPT cases
(`valid`, `expired_wit`, `untrusted_issuer` (same `kid`, other key),
`wit_signature_tampered`, `wth_mismatch`, `other_audience`,
`wpt_signature_tampered`, `expired_wpt`, `wit_no_kid`) and eight signed-request
cases (`valid`, `expired_wit`, `untrusted_issuer`, `other_audience`,
`signature_tampered`, `body_changed`, `covered_header_changed`,
`query_changed`). `expect` is the verdict per the pinned drafts; `wit_expect`
and `sig_expect` are the verdicts on the WIT alone and on the RFC 9421
signature plus body digest alone.

1. visado -> visado: fixed `now` 1800000000. Recorded with the inputs in
   `results/visado-mint.json`.
2. Draft examples and the WG generator -> visado, at a `now` inside the
   examples' validity.
3. wit-wpt-go `5cf9b7de` -> visado: `MintWIT` WITs; `MintWPT` fails there, so
   the WPT is signed by visado-testkit with the WIT's key. `e8fa3451` -> visado:
   `MintWIT` and `MintWPT` both.
4. visado -> wit-wpt-go `ValidateWPT`: `as_is` (visado's WPT) and, for the
   Ed25519 proof keys, `own_format_wpt` (the same claims re-signed in
   wit-wpt-go's format: `typ` `wimse-proof+jwt`, `exp` as a JSON time), which
   leaves only the WIT and the claim checks under test.
5. visado -> go-spiffe: the WPT cases' WITs, against `wit_expect`.
6. visado -> Cofide: the PoC server's check (`poc_server`, es256 only, against
   `expect`) and yaronf/httpsign with the draft-08 components plus the RFC 9530
   digest check (`httpsign_draft08`, against `sig_expect`).
7. Cofide -> visado: POSTs signed by the PoC's signer with the PoC client's
   components (`poc`) and with the draft-08 components (`draft-08`). visado also
   reports `rfc9421_only`: the signature alone, checked by wimsey-httpsig with
   no WIMSE profile.

wit-wpt-go, go-spiffe and the PoC read the wall clock, so directions 3 to 7
use the current time (`wimse mint --now $(date +%s)`).

## Run

```sh
interop/wimse/run.sh
```

Needs cargo, go, git, jq and network access to github.com and
proxy.golang.org. The Go drivers in `go/` pin the implementations in their
`go.mod`; `run.sh` checks the pins and fetches the WG repository at its
commit. Files:

- `../harness/src/bin/wimse.rs`: `wimse mint [--now N]`, `wimse verify`.
  Verify input: `{now, issuers: [{trust_domain, iss?, jwks}], cases: [{id,
  expect?, now?, wit, wpt? | pop_private_jwk (+ wpt_aud?, wpt_wit?), method,
  uri, headers?, body?}]}`.
- `go/witwpt`, `go/witwpt-e8fa345`, `go/gospiffe`, `go/cofide`: drivers.
- `vectors/draft-examples.json`: the draft examples as verify input.
- `results/*.json`: recorded verdicts, `agrees` per case.

## Results

| Implementation | Pin | Direction | Checker | Agree | Differs |
| --- | --- | --- | --- | --- | --- |
| visado | 0.3.0 | visado -> visado | visado | 51/51 | |
| Draft examples | creds-03, wpt-02 | draft -> visado | visado | 4/5 | `wpt-02/figure-5/early` (D10) |
| WG generator | `ae2acf10` | WG -> visado | visado | 2/2 | |
| wit-wpt-go | `5cf9b7de` | wit-wpt-go WIT, visado WPT -> visado | visado | 6/6 | `MintWPT` fails (D1); D5 worked around |
| wit-wpt-go | `e8fa3451` | wit-wpt-go -> visado | visado | 6/7 | `valid` (D2); the rejected cases all fail at `typ` first |
| wit-wpt-go | `5cf9b7de` | visado -> wit-wpt-go | `ValidateWPT`, as is | 21/27 | all 27 rejected (D2, D3) |
| wit-wpt-go | `5cf9b7de` | visado WIT, own-format WPT -> wit-wpt-go | `ValidateWPT` | 13/18 | ed25519: `valid`, `wit_no_kid` (D3); es256-eddsa: `expired_wit`, `other_audience`, `expired_wpt` accepted (D4) |
| go-spiffe | `b6b0441b` | visado -> go-spiffe | `witsvid.ParseAndValidate` | 14/27 | es256 8/9 (`wit_no_kid`, D7); ed25519 and es256-eddsa every accept case (D6) |
| Cofide PoC | `7984a601` | visado -> PoC | server check | 7/8 | `valid` (D8); the rejected cases all fail at coverage first |
| yaronf/httpsign | v0.3.1 | visado -> httpsign | RFC 9421 + RFC 9530 | 24/24 | |
| Cofide PoC | `7984a601` | PoC -> visado | visado | 8/8 | none is valid under -08 (D8); `rfc9421_only` accepts the untampered signatures of both component sets |

The WIT, WPT and signature formats themselves interoperate: visado accepts
wit-wpt-go's and the WG generator's WITs and WPTs, wit-wpt-go accepts
visado's ES256-signed WITs, go-spiffe accepts visado's ES256 WITs, and
httpsign and wimsey-httpsig verify each other's signature bases.

## Divergences

Line numbers are at the pinned commits. "Other side" means the other
implementation departs from the pinned draft, usually because it targets an
older revision.

| # | Finding | Evidence | Class |
| --- | --- | --- | --- |
| D1 | `MintWPT` fails for every WIT `MintWIT` makes: the WIT key became P-256, the WPT signer stayed `EdDSA` | wit-wpt-go `wit.go:63`, `wpt.go:86-91`; its own `TestMintWPT` fails | other side |
| D2 | WPT `typ` `wimse-proof+jwt` and `exp` a JSON time string; visado requires `wpt+jwt` and a NumericDate, and `ValidateWPT` cannot read a numeric `exp` | wpt-02 §2 (`typ`, `exp`), RFC 7519 §4.1.4; wit-wpt-go `wpt.go:13`, `wpt.go:19` | other side (s2s-protocol-06 or earlier) |
| D3 | `ValidateWPT` takes only ES256 WITs and only `EdDSA` WPTs | creds-03 §5.1 allows any asymmetric `alg`; wit-wpt-go `wpt.go:131`, `wpt.go:147-150` | other side |
| D4 | `ValidateWPT` checks neither WIT `exp`, WPT `exp` nor `aud` (`aud` only in the gRPC transport) | wpt-02 §2 validation list; wit-wpt-go `wpt.go:120-122`, `wpt.go:136`, `transport/grpc/grpc.go:242-247` | other side |
| D5 | `MintWIT` writes a random `kid` per token, not one naming the issuer key, so a verifier selecting by `kid` finds no key; the driver lists the issuer key under each minted `kid` | creds-03 §3; wit-wpt-go `wit.go:89-93` | other side |
| D6 | witsvid accepts RS, ES and PS algorithms only, for the WIT and for `cnf.jwk.alg`; Ed25519 issuers and proof keys are refused, including the shape of creds-03's own Figure 4 | creds-03 §5.1 (ES256 MUST, others allowed); go-spiffe `exp/svid/witsvid/svid.go:21-31`, `svid.go:208-210` | other side (local policy the draft permits) |
| D7 | witsvid requires `kid`; visado accepts a WIT without `kid` when the trust domain has one key | creds-03 §3 ("If kid is absent, deployment policy would need to provide unambiguous key selection"); go-spiffe `svid.go:115` | other side (stricter) |
| D8 | The PoC signs with the `alg` parameter (httpsign's default), `expires` equal to the WIT `exp`, `@request-target` and no `wimse-aud`; its server requires `@request-target` | http-signature-08 §3 (`@path`, `@query`, `wimse-aud`, no `alg`, short `expires`); s2s-protocol-07 §3.3 already forbade `alg` and long `expires`; Cofide `wimse/shared/httpsig.go:25`, `:34-45`, `wimse/client/client.go:109`, `wimse/server/server.go:94`; httpsign `config.go:25` | other side (-07, plus `alg` and `expires` against -07 too) |
| D9 | The PoC server reads the WIT without verifying it and does not check `Content-Digest` against the body; not reachable in this run because coverage fails first | http-signature-08 §3; Cofide `wimse/server/server.go:72-101` | other side (code reading only) |
| D10 | visado caps a WPT's remaining lifetime at 60 s by default, so the wpt-02 Figure 5 WPT is refused 1016 s before its `exp` and accepted 36 s before | wpt-02 §2 ("unreasonably far in the future SHOULD be rejected"); `Authenticator::with_replay_limits`, SPEC-MAP "WPT replay" | visado choice |
| D11 | creds-03's example WIT (Figure 2) has `cnf.jwk.alg` `Ed25519`, wpt-02's (Figure 5) has `EdDSA` for the same key, and wpt-02's WPT uses `EdDSA`, so the two drafts' examples do not combine (visado rejects that pair at `alg`) | creds-03 Figure 4, wpt-02 Figures 3 and 5 | spec (editorial) |
| D12 | wpt-02 §2 and http-signature-08 §3 point to "Section 5.1.4" of workload-creds for WIT validation; in creds-03 it is §5.1.3 and there is no §5.1.4 | wpt-02 §2, http-signature-08 §3 and §3.6, creds-03 §5.1.3 | spec (dangling reference) |
| D13 | wit-wpt-go's `oth` is one string; wpt-02 makes it a JSON object keyed by header name. Not exercised | wpt-02 §2; wit-wpt-go `wpt.go:23` | other side |

No visado or wimsey bug was found. Every case visado got "wrong" against
`expect` is D10.
