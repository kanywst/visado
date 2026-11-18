# visado-chain-aat

Verify Attenuating Agent Token chains ([draft-niyikiza-oauth-attenuating-agent-tokens-02](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/02/)).

```rust
use visado_chain_aat::{Invocation, Presentation, TrustAnchor, Verifier};

let verifier = Verifier::new(vec![TrustAnchor::new("https://auth.example.com", key)], vec![audience]);
let authorized = verifier.verify(
    &Presentation { chain: &chain, pop: &pop },
    &Invocation { tool: "read_file", args_json: r#"{"path":"/data/q3-report.pdf"}"# },
    now,
    None,
)?;
```

- Runs the §8 algorithm in order. An error reports the §8 step (`4p4`, `7g`, ...) and a stable code (`aat.not_attenuated`, ...).
- Passes all 229 published JWS vectors; see [conformance/aat](https://github.com/kanywst/visado/tree/main/conformance/aat).
- Signatures: `Ed25519` and `ES256`, through [`wimsey-jose`](https://crates.io/crates/wimsey-jose). `EdDSA` is rejected.
- Numbers in claims and arguments are read as written, so admissibility (§3.4) is exact.
- Pass a `ReplayCache` for tools whose PoP `jti` values must be tracked (§7.3).
- The `ChainDecoder` implementation runs steps 1 to 5 only and returns a `NormalizedChain` from [`visado-chain`](https://github.com/kanywst/visado/tree/main/crates/chain).

Pre-alpha. Licensed under Apache-2.0.
