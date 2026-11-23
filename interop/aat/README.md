# AAT interop

visado's `visado-chain-aat` (draft-niyikiza-oauth-attenuating-agent-tokens-02) against [tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo) at commit `f1a6c22b3ef6de3d442eee4cbc1a9231fd65e7d4` (Apache-2.0).

## Directions

1. tenuo -> visado: the published suite `tests/vectors/aat-jws-vectors.json` (SHA-256 `b7a42e9d…`, 229 vectors), verified by `visado-interop aat-suite`, scored by tenuo's own `ietf/vectors/compare_results.py`, as its `ietf/vectors/INTEROP.md` describes.
2. visado -> tenuo: nine chains minted by `visado-testkit` (`visado-interop aat-mint`), verified by `verify_chain` in tenuo's `ietf/vectors/gen_vectors.py`, the Section 8 verifier that generates and self-checks the suite. Two permit; seven deny for an argument outside `one_of`, a tool the leaf lacks, a child that adds a tool, a PoP by another key, a spliced `par_hash`, a chain past `del_max_depth`, and a PoP `hta` that differs from the call.

## Run

```sh
interop/aat/run.sh
```

Needs git, python3, cargo and network access to github.com and pypi.org.

## Results

| Direction | Verifier | Agree | Same step |
| --- | --- | --- | --- |
| tenuo suite -> visado | visado, scored by `compare_results.py` | 229/229 | 175/175 denials |
| visado -> tenuo | `gen_vectors.verify_chain` | 9/9 | 7/7 denials |

Files: `results/visado-on-tenuo-suite.json` (verdicts in the `INTEROP.md` format), `results/visado-on-tenuo-suite.compare.txt`, `results/visado-minted.json`, `results/tenuo-on-visado-minted.json`.

No divergence. tenuo's runtime library uses CBOR warrants, not the JWS AAT format, so its only JWS implementation is the vector generator's verifier.
