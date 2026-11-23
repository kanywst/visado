# visado-txn-token

Mint, verify and replace OAuth Transaction Tokens ([draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/)).

```rust
use visado_txn_token::{mint, verify, KeySet, Validation};

let token = mint(&claims, Some("k1"), &signing_key)?;
let keys = KeySet::new().with_key("k1", signing_key.verifying_key());
let verified = verify(&token, &keys, &Validation::new("trust-domain.example", now))?;
```

- Signatures: `Ed25519`, `EdDSA`, `ES256`, through [`wimsey-jose`](https://crates.io/crates/wimsey-jose). `RS256` with RSA keys of at least 2048 bits and the exponent 65537: `TxnSigningKey::from_rsa_jwk` and `mint_with` to mint, `KeySet::with_rsa_key` to verify.
- Errors carry stable codes (`txn.expired`, `txn.scope_escalation`, ...) shared with the [conformance vectors](https://github.com/kanywst/visado/tree/main/conformance).
- Where the draft leaves a choice open, see [SPEC-MAP.md](https://github.com/kanywst/visado/blob/main/SPEC-MAP.md).

Pre-alpha. Licensed under Apache-2.0.
