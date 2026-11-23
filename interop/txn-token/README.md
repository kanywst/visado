# Transaction Token interop

visado's `visado-txn-token` (draft-ietf-oauth-transaction-tokens-11) against
three independent implementations. Section numbers are draft -11.

## Implementations

| Implementation | Language, license | Pin | Targets | Role here |
| --- | --- | --- | --- | --- |
| [authgent/authgent](https://github.com/authgent/authgent) | Python, Apache-2.0 | `8341cf93`, authgent-server 0.3.4 | -09 (docs) | TTS, ES256 |
| [Atlas-Authorization/atlas-go](https://github.com/Atlas-Authorization/atlas-go) | Go, MIT | v0.27.0 = `794a21e5` | unversioned | verifier (`VerifyTransactionToken`) |
| [aramase/kontxt](https://github.com/aramase/kontxt) | Go, Apache-2.0 | `d23ebb50` | -08 | TTS (`pkg/token.New`, RS256) and verifier (`sdk/verify`) |

## Directions

1. visado -> atlas-go: `txn mint` (fixed `now` 1800000000), verified by
   `atlas-verify` with the same `now`.
2. visado -> kontxt: `txn mint --now <wall clock>`, verified by
   `sdk/verify.Verifier`. It has no clock option, so this pair uses the wall
   clock.
3. authgent -> visado: the real FastAPI app in-process (in-memory SQLite, as
   its tests do), tokens from RFC 8693 exchange at `POST /token`, keys from
   `GET /.well-known/jwks.json`. atlas-go runs the same cases as a control.
   Each case's `now` is derived from the token's `iat`/`exp`.
4. kontxt -> visado: tokens from `pkg/token.New`, keys from
   `pkg/keys.Manager.JWKSHandler`. kontxt's verifier and atlas-go are controls.

## Run

```sh
interop/txn-token/run.sh
```

Needs git, python3 (3.11+), go, cargo, and network access to github.com,
pypi.org and proxy.golang.org. authgent's dependencies are pinned by
`authgent-constraints.txt`, the Go modules by their `go.mod`/`go.sum`.

Files:

- `../harness/src/bin/txn.rs`: `txn mint [--now N]`, `txn verify`.
  Input format: `{trust_domain, issuer, now, keys: [JWK], cases: [{id, token,
  now?, trust_domain?}]}`.
- `atlas-verify/`, `kontxt-driver/`: Go drivers, same input format.
- `authgent_mint.py`: mints with authgent, prints the input format.
- `summarize.py`: joins cases and verdicts into `results/*-to-*.json`.
- `results/visado-minted.json`: visado's tokens and JWKs, reproducible.

## Results

`expect` comes from the draft; `unspecified` marks cases the draft does not
decide. Counts exclude `unspecified` cases.

| Direction | Verifier | As expected | Differs |
| --- | --- | --- | --- |
| visado -> atlas-go | visado | 17/17 | |
| visado -> atlas-go | atlas-go | 14/17 | `ed25519-valid`, `es256-no-iss`, `es256-exp-equals-now` |
| visado -> kontxt | kontxt | 13/17 | the non-RSA valid cases (`es256-valid`, `ed25519-valid`, `eddsa-valid`, `es256-no-iss`), rejected at `alg`; the RS256 cases all pass |
| authgent -> visado | visado | 6/6 | |
| authgent -> visado | atlas-go (control) | 5/6 | `authgent-exp-equals-now` |
| kontxt -> visado | visado | 4/4 | |
| kontxt -> visado | kontxt (control) | 4/4 | |
| kontxt -> visado | atlas-go (control) | 4/4 | |

`tctx` and `rctx` came through unchanged on every accepted token (authgent,
kontxt and visado tokens, all verifiers).

Unspecified cases:

| Case | visado | atlas-go | kontxt |
| --- | --- | --- | --- |
| `es256-empty-scope` (`"scope": ""`) | reject `txn.invalid_claim` | accept | (alg) |
| `authgent-blank-scope` (`"scope": " "`) | reject `txn.invalid_claim` | accept | |
| `es256-aud-array` (`["trust-domain.example"]`) | accept | accept | (alg) |
| `es256-iat-future` | reject `txn.issued_in_future` | accept | (alg) |
| `es256-typ-media-type` (`application/txntoken+jwt`) | accept | reject | (alg) |

Missing required claims: authgent always emits every §9.2 claim, and
kontxt's `token.New` refuses empty `iss`, `sub`, `scope` and `req_wl`
(`pkg/token/token.go:53-69`), so only visado's own hand-signed tokens test
this. visado and atlas-go reject missing `scope`, `req_wl`, `txn` and `iat`.

## Divergences

Paths are in the other project at the pinned commit.

1. kontxt signs RS256 only (`pkg/token/token.go:45`) and its verifier takes
   RSA keys only (`sdk/verify/verifier.go:77`, JWKS filter at `:140`). visado
   first minted and verified Ed25519/EdDSA/ES256 only, so neither side
   accepted the other's tokens. Fixed in visado: `visado-txn-token` verifies
   and mints RS256 with RSA keys of at least 2048 bits. kontxt -> visado is
   4/4, and kontxt accepts visado's `rs256-valid` and rejects
   `rs256-expired` and `rs256-tampered`. Spec gap: draft -11 names no
   mandatory-to-implement algorithm; the only `alg` in the text is RS256 in
   the §9.1 example.
2. `Ed25519` (RFC 9864) not accepted by atlas-go. `SigningAlgs` lists `EdDSA`
   but not `Ed25519` (`verify.go:574`), checked at `txn_token.go:85`. visado
   tokens signed with the `EdDSA` label verify. Same spec gap as 1; visado
   picks `Ed25519` by default for Ed25519 keys, so a deployment that talks to
   atlas-go has to configure `EdDSA`.
3. atlas-go requires `iss`. `VerifyTransactionToken` refuses to run without
   an issuer (`txn_token.go:69-70`) and rejects a token whose `iss` differs or
   is absent (`txn_token.go:121`). §9.2 makes `iss` OPTIONAL. atlas-go side.
   kontxt's `token.New` also refuses an empty `iss` (`pkg/token/token.go:54`),
   which only constrains its own TTS.
4. `exp` boundary. atlas-go accepts until `exp + 5` s
   (`txn_token.go:132`, `ClockSkewSeconds` at `verify.go:35`); visado rejects
   at `now >= exp` with zero default leeway. RFC 7519 §4.1.4 allows a small
   leeway, so both conform.
5. Empty or blank `scope`. atlas-go checks presence only (`raw[c] == nil`,
   `txn_token.go:138-141`) and accepts `""` and `" "`. authgent issues
   `"scope": " "` when the request carries `scope=" "`: the subset check skips
   an empty split (`server/authgent_server/services/token_service.py:722-723`)
   and the raw string is copied (`:749`). visado rejects both. Spec gap: §9.2
   says `scope` is REQUIRED but not that it is non-empty.
6. `aud` as an array. visado modeled `aud` as a string and rejected an array
   as malformed; atlas-go accepts an array containing the trust domain
   (`txn_token.go:160-172`). RFC 7519 §4.1.3 allows either; §9.2 does not say.
   Changed in visado: a one-element array holding the trust domain is
   accepted; a longer array is rejected even if it names the trust domain,
   because a Txn-Token is scoped to one trust domain. atlas-go accepts such
   longer arrays, which lets one token pass in several trust domains.
7. `typ` spelling. visado accepts `application/txntoken+jwt` (RFC 7515
   §4.1.9 equivalence, `crates/txn-token/src/token.rs:136`); atlas-go
   (`txn_token.go:85`) and kontxt (`sdk/verify/verifier.go:57`, exact and
   case-sensitive) accept only `txntoken+jwt`. §9.1 says the value MUST be
   `txntoken+jwt`. Spec gap.
8. Future `iat`. visado rejects `iat > now`; atlas-go has no `iat` check.
   §12.2 asks only for signature, `aud` and expiry. Policy difference.
9. kontxt's verifier does not check §9.2 required claims
   (`sdk/verify/verifier.go:161-186` copies whatever is present). Read from
   the code; not exercised, since no token it accepts can come from visado.

Items 1 and 6 were fixed in visado after the first run; the results above
are from the run after the fixes.
