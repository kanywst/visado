# asor interop

visado's `visado-chain-asor` (draft-asor-wimse-agent-delegation-chain-03) against [attenu-io/attenu-guard](https://github.com/attenu-io/attenu-guard) 0.22.0 from PyPI (wheel SHA-256 `12f9edf6…`, Apache-2.0), the reference implementation named in the draft's Section 11. attenu-guard implements the -03 claims as its opt-in `"02"` profile; it checks neither DPoP (step 6) nor status lists (step 7).

## Directions

1. attenu-guard -> visado: nine chains minted with `Guard.issue`, `Guard.delegate` and `wire.serialize_chain` (Ed25519, `cnf.jkt` per holder), verified by `visado-interop asor-verify`. Three carry a request with an RFC 9449 DPoP proof by the leaf holder, so visado runs `verify` (steps 1 to 8); the rest run `check`. attenu-guard's verdict is `wire.load` plus `VerifiedChain.permits`.
2. visado -> attenu-guard: nine chains minted by `visado-testkit` (`visado-interop asor-mint`), verified by attenu-guard's `wire.load` with the `"02"` profile.

attenu-guard's built-in Ed25519 signer writes `"alg": "EdDSA"`. The chains in direction 1 are signed through a wrapper that writes `"Ed25519"` with the same key, except case A.9, which keeps the built-in signer.

## Run

```sh
interop/asor/run.sh
```

Needs python3, cargo and network access to pypi.org.

## Results

| Direction | Verifier | Agree | Differs |
| --- | --- | --- | --- |
| attenu-guard -> visado | visado | 8/9 | A.9 |
| visado -> attenu-guard | attenu-guard | 9/9 | |

Every rejection agrees on the Table 2 outcome name too (`not_narrower`, `principal_altered`, `par_hash_mismatch`, `depth_invalid`, `signature_invalid`, `expired`, `audience_mismatch`, `ceiling_exceeded`, `scope_not_granted`).

A.9: attenu-guard signs and verifies Ed25519 as `"alg": "EdDSA"` (`wire.py`, `Ed25519Signer.alg`); visado rejects it as `signature_invalid` because Section 3 requires a fully-specified algorithm (RFC 9864). The draft's Section 11 already records this, so it is not reported again.
