# AAT vectors

`aat-jws-vectors.json` is the published JWS test vector suite for [draft-niyikiza-oauth-attenuating-agent-tokens-02](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/), copied unchanged.

| | |
| --- | --- |
| Source | [`tests/vectors/aat-jws-vectors.json`](https://github.com/tenuo-ai/tenuo/blob/63ed003934f1d452601164965e6ab3b6ca23fc43/tests/vectors/aat-jws-vectors.json) in [tenuo-ai/tenuo](https://github.com/tenuo-ai/tenuo) |
| Commit | `63ed003934f1d452601164965e6ab3b6ca23fc43` |
| SHA-256 | `b7a42e9dfdce7fbc1f623670bf060f90e6d6b25f64384cbab1bd79363e82209b` |
| Vectors | 229 (54 permit, 175 deny) |
| License | Apache-2.0, Copyright 2025-2026 Tenuo Contributors. See [NOTICE](../../NOTICE). |

Each vector gives a chain, a PoP JWT, a tool invocation, the verifier settings, and the expected verdict. For a denial, `expected.step` is the first failing §8 step. The suite's [INTEROP.md](https://github.com/tenuo-ai/tenuo/blob/63ed003934f1d452601164965e6ab3b6ca23fc43/ietf/vectors/INTEROP.md) describes how to run it.

`crates/chain-aat/tests/vectors.rs` runs every vector and checks both the verdict and the step. Result: 229/229, every denial at the expected step.

To update, fetch the file at a new commit, update the commit and SHA-256 above, and run `cargo test -p visado-chain-aat`.
